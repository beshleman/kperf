/*
 * accept() -> sockfd
 * getsockname, ifindex, etc...
 * n_conns, num_queues
 * sched_
 *
 *
 *
 *
 * assumptions:
 *	each server has only one device
 *	devmem_setup is called before spawn_conn()
 *	devmem_setup knows the device (ifindex, ifname, etc...)
 *
 *
 *	may have multiple instances of ./server colocated, what is the best way to to cut up the CPU range per instance.
 *
 * Idea:
 *	hardcode detection of numa cpu list for device and slicing into pre-compiled X ranges
 *	configure rss_equal(based on range)
 *
 * flow:
 * spawn_conn() -> server_session_spawn_conn(), reply with src and dst INCOMING_CPU
 * pin_worker() -> server_session_msg_pin_worker()
 *
 *
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <sched.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#define SERVER_CPUS_FPATH "/tmp/server.cpus"
#define MAX_CPUS 1024

int get_numa_node(const char *interface)
{
	char path[256];
	FILE *file;
	int numa_node;

	snprintf(path, sizeof(path), "/sys/class/net/%s/device/numa_node",
		 interface);

	file = fopen(path, "r");
	if (!file) {
		perror("fopen");
		return -1;
	}

	if (fscanf(file, "%d", &numa_node) != 1) {
		perror("fscanf");
		fclose(file);
		return -1;
	}

	fclose(file);

	return numa_node;
}

int affinity_db_init(const char *filename)
{
	unsigned char buf[MAX_CPUS] = {0};
	FILE *file;

	file = fopen(filename, "r");
	if (!file) {
		file = fopen(filename, "w");
		if (!file) {
			perror("fopen");
			return EXIT_FAILURE;
		}

		fwrite(&buf, sizeof(buf), 1, file);
	}

	fclose(file);
	return 0;
}

/* Return true if we acquire the cpu. Otherwise, return false */
bool affinity_db_get_cpu(const char *filename, int cpu)
{
	unsigned char value;
	bool ret = false;
	int fd;

	fd = open(filename, O_RDWR);
	if (fd == -1) {
		perror("open");
		return false;
	}

	if (flock(fd, LOCK_EX) == -1) {
		perror("flock");
		close(fd);
		return false;
	}

	if (lseek(fd, sizeof(value) * cpu, SEEK_SET) == -1) {
		perror("lseek");
		flock(fd, LOCK_UN);
		close(fd);
		return false;
	}

	if (read(fd, &value, sizeof(value)) != sizeof(value)) {
		perror("read");
		flock(fd, LOCK_UN);
		close(fd);
		return false;
	}

	/* the cpu is free, lets claim it while we have the flock */
	if (value == 0) {
		value = ~0;

		if (lseek(fd, sizeof(value) * cpu, SEEK_SET) == -1) {
			perror("lseek");
			flock(fd, LOCK_UN);
			close(fd);
			return false;
		}

		if (write(fd, &value, sizeof(value)) != sizeof(value)) {
			perror("write");
			flock(fd, LOCK_UN);
			close(fd);
			return false;
		}

		ret = true;
	}

	if (flock(fd, LOCK_UN) == -1) {
		perror("flock");
		close(fd);
		return false;
	}

	close(fd);
	return ret;
}

bool affinity_db_free_cpu(const char *filename, int cpu)
{
	unsigned char value;
	bool ret = false;
	int fd;

	fd = open(filename, O_RDWR);
	if (fd == -1) {
		perror("open");
		return false;
	}

	if (flock(fd, LOCK_EX) == -1) {
		perror("flock");
		close(fd);
		return false;
	}

	if (lseek(fd, sizeof(value) * cpu, SEEK_SET) == -1) {
		perror("lseek");
		flock(fd, LOCK_UN);
		close(fd);
		return false;
	}

	value = 0;

	if (write(fd, &value, sizeof(value)) != sizeof(value)) {
		perror("write");
		flock(fd, LOCK_UN);
		close(fd);
		return false;
	}

	ret = true;

	if (flock(fd, LOCK_UN) == -1) {
		perror("flock");
		close(fd);
		return false;
	}

	close(fd);
	return ret;
}

/* IDEA:
 *	hardcode detection of numa cpu list for device and slicing into pre-compiled X ranges
 *	configure rss_equal(based on range)
 *
 * Pass an ifname, return a start,end range CPUs (numa local).
 */

// 00000000,000000ff,ffffffff,ffff0000,00000000,00ffffff,ffffffff

#define MAX_CPUS 1024  // Adjust this value as needed

#define DEVICES_PER_NODE 4

int count(const char *str, char c)
{
	int cnt = 0;
	size_t i, n;

	n = strlen(str);
	for (i = 0; i < n; i++) {
		if (str[i] == c)
			cnt++;
	}

	return cnt;
}

int parse_cpu_mask(const char *cpu_mask_str, cpu_set_t *cpu_set)
{
	unsigned long mask;
	int cpu_index = 0;
	char *mask_str;
	char *token;
	int words;
	int ret;

	CPU_ZERO(cpu_set);

	mask_str = strdup(cpu_mask_str);
	if (!mask_str) {
		perror("strdup");
		return -1;
	}

	words = count(mask_str, ',');
	if (words != 0)
		words++;

	token = strtok(mask_str, ",");
	cpu_index = 0;

	ret = 0;
	while (token && cpu_index < MAX_CPUS) {
		if (words < 0) {
			fprintf(stderr, "words left %d\n", words);
			ret = -1;
			goto out;
		}

		mask = strtoul(token, NULL, 16);

		for (int bit = 0; bit < 32 && cpu_index < MAX_CPUS; ++bit, ++cpu_index) {
			if (mask & (1UL << bit))
				CPU_SET(bit + ((words - 1) * 32), cpu_set);
		}

		token = strtok(NULL, ",");
		words--;
	}

out:
	free(mask_str);
	return ret;
}

int affinity_next_cpu(const char *ifname)
{
	char path[PATH_MAX];
	char buf[128];
	cpu_set_t set;
	int numa;
	int cpu;
	int fd;
	int i;

	snprintf(path, sizeof(path), "/sys/class/net/%s/device/local_cpus", ifname);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -ENOENT;

	memset(buf, '\0', sizeof(buf));

	if (read(fd, buf, sizeof(buf)) < 0) {
		perror("failed to read local cpu");
		close(fd);
		return -1;
	}

	close(fd);

	if (parse_cpu_mask(buf, &set) < 0)
		return -1;

	numa = get_numa_node(ifname);
	if (numa < 0) {
		fprintf(stderr, "failed to get numa node");
		return -1;
	}

	affinity_db_init(SERVER_CPUS_FPATH);

	/* return the nth CPU from the set */
	cpu = -1;
	for (i = 0; i < MAX_CPUS; i++) {
		if (!CPU_ISSET(i, &set))
			continue;

		if (affinity_db_get_cpu(SERVER_CPUS_FPATH, i)) {
			cpu = i;
			break;
		}
	}

	return cpu;
}

void affinity_free_cpu(const char *filename, int cpu)
{
	if (!affinity_db_free_cpu(SERVER_CPUS_FPATH, cpu))
		fprintf(stderr, "failed to free cpu %d\n", cpu);
}

#if 0
void test_parse_cpu_mask(void)
{
	const char *cpu_mask_str = "00000000,000000ff,ffffffff,ffff0000,00000000,00ffffff,ffffffff";
	cpu_set_t cpu_set;

	parse_cpu_mask(cpu_mask_str, &cpu_set);

	printf("CPUs in set: ");
	for (int i = 0; i < MAX_CPUS; ++i) {
		if (CPU_ISSET(i, &cpu_set)) {
			printf("%d ", i);
		}
	}
	printf("\n");
}
#endif

#ifdef KPERF_UNITS
int main(int argc, char **argv)
{
	bool cpus[MAX_CPUS] = {false};
	int expected;
	int next;
	int i;

	printf("Acquire all CPUs local to %s\n", argv[1]);
	next = 0;
	while ((next = affinity_next_cpu(argv[1])) >= 0) {
		printf("%d,", next);
		cpus[next] = 1;
	}
	printf("\n");

	printf("Release all previously acquired CPUs (%s)\n", argv[1]);
	for (i = 0; i < MAX_CPUS; i++) {
		if (!cpus[i])
			continue;
		affinity_free_cpu(argv[1], i);
	}

	printf("Acquire first cpu, free, then acquire again\n");
	next = affinity_next_cpu(argv[1]);
	printf("\tacquired cpu %d, freeing it immediately\n", next);
	expected = next;
	affinity_free_cpu(argv[1], next);

	next = affinity_next_cpu(argv[1]);
	if (next != expected)
		fprintf(stderr, "failed: the next cpu %d was not the expected %d\n", next, expected);
	else
		printf("OK: next cpu was as expected\n");
	affinity_free_cpu(argv[1], next);


	return 0;
}
#endif
