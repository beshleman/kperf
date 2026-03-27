// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/daemonize/daemonize.h>
#include <ccan/minmax/minmax.h>
#include <ccan/net/net.h>
#include <ccan/opt/opt.h>

#include "bipartite_match.h"
#include "proto.h"
#include "proto_dbg.h"

int verbose = 3;

static struct {
	bool msg_trunc;
	bool devmem_rx;
	enum memory_provider_type devmem_rx_memory;
	enum memory_provider_type devmem_tx_memory;
	struct pci_dev devmem_dst_dev;
	struct pci_dev devmem_src_dev;
	bool devmem_tx;
	bool msg_zerocopy;
	bool tls;
	bool tls_rx;
	bool tls_tx;
	bool tls_nopad;
	bool output_csv;
	bool output_hdr;
	bool xpin;
	unsigned int tls_ver;
	char *src;
	char *dst;
	char *src_svc;
	char *dst_svc;
	unsigned int time_stats;
	unsigned int req_size;
	unsigned int resp_size;
	unsigned int read_size;
	unsigned int write_size;
	unsigned int pin_off;
	unsigned int time;
	unsigned int cpu_min;
	unsigned int cpu_max;
	int cpu_src_wrk;
	int cpu_dst_wrk;
	unsigned int mss;
	unsigned int n_conns;
	unsigned long max_pace;
	char *tcp_cong_ctrl;
	unsigned int dmabuf_rx_size_mb;
	unsigned int dmabuf_tx_size_mb;
	unsigned int num_rx_queues;
	bool validate;
	bool iou_src;
	bool iou_dst;
	bool zerocopy_rx;
	unsigned int iou_rx_size_mb;
	unsigned int xps_src_irq_start;
	unsigned int xps_dst_irq_start;
	bool bidirectional;
	unsigned int src_queue_start;
	unsigned int dst_queue_start;
	unsigned int src_ack_queue_start;
	unsigned int dst_ack_queue_start;
	unsigned int src_local_port_start;
	unsigned int dst_local_port_start;
	unsigned int src_listen_port;
	unsigned int dst_listen_port;
	char *src_ifname;
	char *dst_ifname;
	unsigned int src_cpu_start;
	unsigned int dst_cpu_start;
	bool bidi_spread;
} opt = {
	.tls_ver = TLS_1_3_VERSION,
	.src = "localhost",
	.dst = "localhost",
	.src_svc = "18323",
	.dst_svc = "18323",
	.req_size = ~0U,
	.read_size = KPM_DFL_OP_CHUNK,
	.write_size = KPM_DFL_OP_CHUNK,
	.time = 5,
	.cpu_min = 0,
	.cpu_max = 255,
	.cpu_src_wrk = -1,
	.cpu_dst_wrk = -1,
	.n_conns = 1,
	/* 128M is enough to drive one queue at 200G */
	.dmabuf_rx_size_mb = 128,
	.dmabuf_tx_size_mb = 128,
	.num_rx_queues = 1,
	.devmem_rx_memory = MEMORY_PROVIDER_HOST,
	.devmem_dst_dev = {
		.domain = DEVICE_DOMAIN_ANY,
		.bus = DEVICE_BUS_ANY,
		.device = DEVICE_DEVICE_ANY
	},
	.devmem_tx_memory = MEMORY_PROVIDER_HOST,
	.devmem_src_dev = {
		.domain = DEVICE_DOMAIN_ANY,
		.bus = DEVICE_BUS_ANY,
		.device = DEVICE_DEVICE_ANY
	},
	.iou_src = false,
	.iou_dst = false,
	.zerocopy_rx = false,
	.iou_rx_size_mb = 64,
};

#define dbg(fmt...) while (0) { warnx(fmt); }

static void opt_show_uinthex(char buf[OPT_SHOW_LEN], const unsigned int *ui)
{
	sprintf(buf, "0x%x", *ui);
}

static char *arg_bad(const char *fmt, const char *arg)
{
	char *str;

	str = malloc(strlen(fmt) + strlen(arg));
	if (!str)
		return strerror(errno);

	sprintf(str, fmt, arg);

	return str;
}

static char *
opt_set_memory_provider(const char *arg, enum memory_provider_type *provider)
{
	char *ret;

	/* Client accepts cuda provider unconditionally; actual CUDA
	 * work is done by the server which must be built with CUDA.
	 */

	ret = NULL;
	if (!strcmp(arg, "host")) {
		*provider = MEMORY_PROVIDER_HOST;
	} else if (!strcmp(arg, "cuda")) {
		*provider = MEMORY_PROVIDER_CUDA;
	} else {
		ret = arg_bad("'%s' is not a valid memory provider", arg);
	}

	return ret;

}

static char *
opt_set_dev(const char *arg, struct pci_dev *dev)
{
	if (!strcmp(arg, "any")) {
		dev->domain = DEVICE_DOMAIN_ANY;
		dev->bus = DEVICE_BUS_ANY;
		dev->device = DEVICE_DEVICE_ANY;
		return NULL;
	}

	if (sscanf(arg, "%hx:%hhx:%hhx", &dev->domain, &dev->bus, &dev->device) == 3)
		return NULL;

	return arg_bad("'%s' invalid PCI ID format. Expected format: domain:bus:device\n", arg);
}

static void
opt_show_memory_provider(char buf[OPT_SHOW_LEN], const enum memory_provider_type *p)
{
	switch (*p) {
	case MEMORY_PROVIDER_HOST:
		strncpy(buf, "host", OPT_SHOW_LEN);
		break;
	case MEMORY_PROVIDER_CUDA:
		strncpy(buf, "cuda", OPT_SHOW_LEN);
		break;
	default:
		/* inval */
		strncpy(buf, "invalid", OPT_SHOW_LEN);
		break;
	}
}

static void
opt_show_dev(char buf[OPT_SHOW_LEN], const struct pci_dev *dev)
{
	if (dev->domain == DEVICE_DOMAIN_ANY &&
	    dev->bus == DEVICE_BUS_ANY &&
	    dev->device == DEVICE_DEVICE_ANY)
		strncpy(buf, "any", OPT_SHOW_LEN);
	else
		snprintf(buf, OPT_SHOW_LEN, "%hx:%hhx:%hhx",
			 dev->domain, dev->bus, dev->device);
}

static const struct opt_table opts[] = {
	OPT_WITH_ARG("--src <arg>", opt_set_charp, opt_show_charp,
		     &opt.src, "Source server"),
	OPT_WITH_ARG("--dst <arg>", opt_set_charp, opt_show_charp,
		     &opt.dst, "Destination server"),
	OPT_WITH_ARG("--src-svc <arg>", opt_set_charp, opt_show_charp,
		     &opt.src_svc, "Source server"),
	OPT_WITH_ARG("--dst-svc <arg>", opt_set_charp, opt_show_charp,
		     &opt.dst_svc, "Destination server"),
	OPT_WITH_ARG("--req-size|-s <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.req_size, "Request size"),
	OPT_WITH_ARG("--resp-size <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.resp_size, "Request size"),
	OPT_WITH_ARG("--read-size <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.read_size, "Buffer size for write/send syscall"),
	OPT_WITH_ARG("--write-size <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.write_size, "Buffer size for read/recv syscall"),
	OPT_WITH_ARG("--pin-off <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.pin_off, "CPU pin offset"),
	OPT_WITH_ARG("--cpu-min <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.cpu_min, "min CPU number for connection"),
	OPT_WITH_ARG("--cpu-max <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.cpu_max, "max CPU number for connection"),
	OPT_WITH_ARG("--cpu-src-wrk <arg>", opt_set_intval, opt_show_intval,
		     &opt.cpu_src_wrk, "max CPU number for connection"),
	OPT_WITH_ARG("--cpu-dst-wrk <arg>", opt_set_intval, opt_show_intval,
		     &opt.cpu_dst_wrk, "max CPU number for connection"),
	OPT_WITHOUT_ARG("--cross-pin", opt_set_bool, &opt.xpin, "Cross-pin"),
	OPT_WITH_ARG("--time|-t <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.time, "Test length"),
	OPT_WITH_ARG("--time-stats|-T <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.time_stats,
		     "Time stats - (0) none, (1) hist, (2) hist+pstats"),
	OPT_WITH_ARG("--mss|-M <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.mss, "MSS for TCP"),
	OPT_WITH_ARG("--max-pace <arg>", opt_set_ulongval, opt_show_ulongval,
		     &opt.max_pace, "Max sending/pacing rate"),
	OPT_WITHOUT_ARG("--tls", opt_set_bool, &opt.tls,
			"Enable TLS in both directions"),
	OPT_WITH_ARG("--tls-ver <arg>", opt_set_uintval, opt_show_uinthex,
		     &opt.tls_ver, "Version of TLS as per kernel defines"),
	OPT_WITHOUT_ARG("--tls-rx", opt_set_bool, &opt.tls_rx,
			"Enable TLS for Rx"),
	OPT_WITHOUT_ARG("--tls-tx", opt_set_bool, &opt.tls_tx,
			"Enable TLS for Tx"),
	OPT_WITHOUT_ARG("--tls-nopad", opt_set_bool, &opt.tls_nopad,
			"Enable TLS no padding optimization for Rx"),
	OPT_WITH_ARG("--num-connections|-n <arg>",
		     opt_set_uintval, opt_show_uintval,
		     &opt.n_conns, "Number of connections"),
	OPT_WITH_ARG("--tcp-cc <arg>", opt_set_charp, opt_show_charp,
		     &opt.tcp_cong_ctrl, "Set TCP congestion control"),
	OPT_WITHOUT_ARG("--out-csv", opt_set_bool, &opt.output_csv,
			"Print output in terse CSV format"),
	OPT_WITHOUT_ARG("--out-hdr", opt_set_bool, &opt.output_hdr,
			"Include column name header in the CSV output"),
	OPT_WITHOUT_ARG("--verbose|-v", opt_inc_intval, &verbose,
			"Verbose mode (can be specified more than once)"),
	OPT_WITHOUT_ARG("--quiet|-q", opt_dec_intval, &verbose,
			"Quiet mode (can be specified more than once)"),
	OPT_WITHOUT_ARG("--usage|--help|-h", opt_usage_and_exit,
			"kpeft client",	"Show this help message"),
	OPT_WITHOUT_ARG("--msg-trunc", opt_set_bool, &opt.msg_trunc, "Use MSG_TRUNC on receive"),
	OPT_WITHOUT_ARG("--msg-zerocopy", opt_set_bool, &opt.msg_zerocopy, "Use MSG_ZEROCOPY on transmit"),
	OPT_EARLY_WITHOUT_ARG("--devmem-rx", opt_set_bool, &opt.devmem_rx, "Use TCP Devmem on receive"),
	OPT_WITH_ARG("--devmem-rx-memory {cuda,host}", opt_set_memory_provider,
		     opt_show_memory_provider, &opt.devmem_rx_memory,
		     "Select the memory provider for TCP Devmem RX"),
	OPT_WITH_ARG("--dmabuf-rx-size-mb <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.dmabuf_rx_size_mb, "Size of RX dmabuf for TCP Devmem mode"),
	OPT_WITH_ARG("--dmabuf-tx-size-mb <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.dmabuf_tx_size_mb, "Size of TX dmabuf for TCP Devmem mode"),
	OPT_WITHOUT_ARG("--devmem-tx", opt_set_bool, &opt.devmem_tx, "Use TCP Devmem on transmit"),
	OPT_WITH_ARG("--devmem-tx-memory {cuda,host}", opt_set_memory_provider,
		     opt_show_memory_provider, &opt.devmem_tx_memory,
		     "Select the memory provider for TCP Devmem TX"),
	OPT_WITH_ARG("--num-rx-queues <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.num_rx_queues, "Number of RX queues for TCP Devmem mode"),
	OPT_WITH_ARG("--validate <yes|no>", opt_set_bool_arg, NULL, &opt.validate,
		     "Validate payload. Default is no when using --devmem-rx; otherwise, default is yes"),
	OPT_WITH_ARG("--devmem-dst-dev <arg>", opt_set_dev, opt_show_dev,
		     &opt.devmem_dst_dev, "Select the destination device for the TCP Devmem memory provider"),
	OPT_WITH_ARG("--devmem-src-dev <arg>", opt_set_dev, opt_show_dev,
		     &opt.devmem_src_dev, "Select the source device for the TCP Devmem memory provider"),
	OPT_WITHOUT_ARG("--iou-src", opt_set_bool, &opt.iou_src,
			"Use io_uring on source server"),
	OPT_WITHOUT_ARG("--iou-dst", opt_set_bool, &opt.iou_dst,
			"Use io_uring on destination server"),
	OPT_EARLY_WITHOUT_ARG("--zerocopy-rx", opt_set_bool, &opt.zerocopy_rx,
			      "Use zero copy on receive"),
	OPT_WITH_ARG("--iou-rx-size-mb <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.iou_rx_size_mb, "Size of RX memory reserved by io_uring"),
	OPT_WITH_ARG("--xps-src-irq-start <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.xps_src_irq_start, "Source IRQ CPU start for XPS pairing"),
	OPT_WITH_ARG("--xps-dst-irq-start <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.xps_dst_irq_start, "Destination IRQ CPU start for XPS pairing"),
	OPT_WITHOUT_ARG("--bidirectional", opt_set_bool, &opt.bidirectional,
			"Enable bidirectional mode"),
	OPT_WITH_ARG("--src-queue-start <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.src_queue_start, "Source RX data queue start"),
	OPT_WITH_ARG("--dst-queue-start <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.dst_queue_start, "Destination RX data queue start"),
	OPT_WITH_ARG("--src-ack-queue-start <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.src_ack_queue_start, "Source TX ACK queue start"),
	OPT_WITH_ARG("--dst-ack-queue-start <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.dst_ack_queue_start, "Destination TX ACK queue start"),
	OPT_WITH_ARG("--src-local-port-start <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.src_local_port_start, "Source local port start for TX bind"),
	OPT_WITH_ARG("--dst-local-port-start <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.dst_local_port_start, "Destination local port start for TX bind"),
	OPT_WITH_ARG("--src-listen-port <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.src_listen_port, "Source listen port for acceptor"),
	OPT_WITH_ARG("--dst-listen-port <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.dst_listen_port, "Destination listen port for acceptor"),
	OPT_WITH_ARG("--src-ifname <arg>", opt_set_charp, opt_show_charp,
		     &opt.src_ifname, "Source interface name for steering/affinity"),
	OPT_WITH_ARG("--dst-ifname <arg>", opt_set_charp, opt_show_charp,
		     &opt.dst_ifname, "Destination interface name for steering/affinity"),
	OPT_WITH_ARG("--src-cpu-start <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.src_cpu_start, "Source CPU start for SMP affinity"),
	OPT_WITH_ARG("--dst-cpu-start <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.dst_cpu_start, "Destination CPU start for SMP affinity"),
	OPT_WITHOUT_ARG("--bidi-spread", opt_set_bool, &opt.bidi_spread,
			"Spread bidi CPU pinning (no TX net / RX app overlap)"),
	OPT_ENDTABLE
};

static struct kpm_connect_reply *
spawn_conn(int src, int dst, struct sockaddr_in6 *addr, socklen_t len)
{
	struct kpm_connect_reply **replies;
	struct kpm_connect_reply *conns;
	struct kpm_connect_reply *id;
	struct bim_state *bim;
	struct bim_edge m;
	unsigned int i;
	int *seq;

	if (!opt.n_conns)
		return NULL;
	conns = calloc(opt.n_conns, sizeof(*conns));
	if (!conns)
		return NULL;
	replies = calloc(opt.n_conns, sizeof(*replies));
	if (!replies)
		goto err_free_conns;
	seq = calloc(opt.n_conns, sizeof(int));
	if (!seq)
		goto err_free_replies;
	bim = bim_init();
	if (!bim)
		goto err_free_seq;

again:
	for (i = 0; i < opt.n_conns; i++) {
		seq[i] = kpm_send_connect(src, addr, len, opt.mss);
		if (seq[i] < 0)
			err(7, "Failed to connect");
	}
	for (i = 0; i < opt.n_conns; i++) {
		id = kpm_receive(src);
		if (!id)
			errx(7, "No connection ID");

		if (!kpm_good_reply(id, KPM_MSG_TYPE_CONNECT, seq[i]))
			errx(7, "Invalid connection ID %d %d",
			     id->hdr.type, id->hdr.len);

		replies[i] = id;
	}

	for (i = 0; i < opt.n_conns; i++) {
		bool good, bim_unique;

		id = replies[i];

		good = clamp(id->local.cpu, opt.cpu_min, opt.cpu_max) ==
			id->local.cpu &&
		       clamp(id->remote.cpu, opt.cpu_min, opt.cpu_max) ==
			id->remote.cpu;
		bim_unique = good &&
			bim_add_edge(bim, id->local.cpu, id->remote.cpu, id);

		kpm_dbg("Connection established %d:cpu %d | %d:cpu %d - %s",
			id->local.id, id->local.cpu,
			id->remote.id, id->remote.cpu,
			good && bim_unique ? "good" :
			(good ? "duplicate" : "out of range"));

		if (!bim_unique) {
			bool fail = kpm_req_disconnect(src, id->local.id) < 0 ||
				    kpm_req_disconnect(dst, id->remote.id) < 0;
			free(id);
			if (fail) {
				warnx("Disconnect failed");
				i = opt.n_conns - i - 1;
				goto err_drain;
			}
		}
	}

	if (bim_match_size(bim) < opt.n_conns)
		goto again;

	i = 0;
	bim_for_each_edge(bim, &m) {
		id = m.cookie;

		if (m.is_match && i < opt.n_conns) {
			kpm_info("Connected %d:cpu %d | %d:cpu %d",
				 id->local.id, id->local.cpu,
				 id->remote.id, id->remote.cpu);
			memcpy(&conns[i], id, sizeof(*id));
			i++;
		} else {
			kpm_req_disconnect(src, id->local.id);
			kpm_req_disconnect(dst, id->remote.id);
		}
		free(id);
	}

	for (i = 0; i < opt.n_conns; i++) {
		if (opt.max_pace) {
			if (kpm_req_pacing(src, conns[i].local.id, opt.max_pace) ||
			    kpm_req_pacing(dst, conns[i].remote.id, opt.max_pace))
				err(8, "Failed to set pacing rate");
		}

		if (opt.tcp_cong_ctrl) {
			if (kpm_req_tcp_cc(src, conns[i].local.id, opt.tcp_cong_ctrl) ||
			    kpm_req_tcp_cc(dst, conns[i].remote.id, opt.tcp_cong_ctrl))
				err(8, "Failed to set TCP cong control");
		}
	}

	free(seq);
	free(replies);
	return conns;

err_drain:
	bim_for_each_edge(bim, &m) {
		id = m.cookie;
		kpm_req_disconnect(src, id->local.id);
		kpm_req_disconnect(dst, id->remote.id);
		free(id);
	}
	bim_destroy(bim);
err_free_seq:
	free(seq);
err_free_replies:
	free(replies);
err_free_conns:
	free(conns);
	return NULL;
}

static int spawn_worker(int fd, int cpu, __u32 *wid)
{
	struct __kpm_generic_u32 *id;
	struct kpm_empty *ack;
	int seq;

	seq = kpm_send_empty(fd, KPM_MSG_TYPE_SPAWN_PWORKER);
	if (seq < 0) {
		warn("Failed to spawn");
		return 1;
	}

	id = kpm_receive(fd);
	if (!id) {
		warnx("No ack for spawn");
		return 1;
	}

	if (!kpm_good_reply(id, KPM_MSG_TYPE_SPAWN_PWORKER, seq)) {
		warnx("Invalid spawn ack %d %d", id->hdr.type, id->hdr.len);
		free(id);
		return 1;
	}

	*wid = id->val;
	free(id);

	seq = kpm_send_pin_worker(fd, *wid, cpu);
	if (seq < 0) {
		warn("Failed to pin");
		return 1;
	}

	ack = kpm_receive(fd);
	if (!ack) {
		warnx("No ack for pin");
		return 1;
	}

	if (!kpm_good_reply(ack, KPM_MSG_TYPE_PIN_WORKER, seq)) {
		warnx("Invalid ack for pin %d %d", ack->hdr.type, ack->hdr.len);
		free(ack);
		return 1;
	}
	free(ack);

	return 0;
}

static void
show_cpu_stat(const char *pfx, struct kpm_test_results *result, unsigned int id)
{
	struct kpm_cpu_load *cpu = &result->cpu_load[id];

	if (cpu->id != id) {
		warnx("Sparse CPU IDs %d != %d!", cpu->id, id);
		return;
	}

	warnx("  %sCPU%3d: usr:%5.2f%% sys:%5.2f%% idle:%5.2f%% iow:%5.2f%% irq:%5.2f%% sirq:%5.2f%%",
	      pfx, id, cpu->user / 100.0, cpu->system / 100.0,
	      cpu->idle / 100.0, cpu->iowait / 100.0, cpu->irq / 100.0,
	      cpu->sirq / 100.0);
}

static void
dump_result(struct kpm_test_results *result, const char *dir,
	    struct kpm_connect_reply *conns, bool local,
	    const __u32 *net_cpus)
{
	unsigned int end = 0, i, r;
	int start = -1;

	warnx("== %s", dir);
	for (r = 0; r < opt.n_conns; r++)
		warnx("  Tx %7.3lf Gbps (%llu bytes in %u usec)",
		      (double)result->res[r].tx_bytes * 8 /
		      result->time_usec /
		      1000,
		      result->res[r].tx_bytes,
		      result->time_usec);
	for (r = 0; r < opt.n_conns; r++)
		warnx("  Rx %7.3lf Gbps (%llu bytes in %u usec)",
		      (double)result->res[r].rx_bytes * 8 /
		      result->time_usec /
		      1000,
		      result->res[r].rx_bytes,
		      result->time_usec);
	warnx("  TCP retrans reord rtt rttvar d_ce snd_wnd cwnd");
	for (r = 0; r < opt.n_conns; r++)
		warnx("      %7u %5u %3u %6u %4u %7u %4u",
		      result->res[r].retrans, result->res[r].reord_seen,
		      result->res[r].rtt,
		      result->res[r].rttvar, result->res[r].delivered_ce,
		      result->res[r].snd_wnd, result->res[r].snd_cwnd);

	for (r = 0; r < opt.n_conns; r++) {
		int flow_cpu;

		if (net_cpus)
			flow_cpu = net_cpus[r];
		else
			flow_cpu = local ? conns[r].local.cpu : conns[r].remote.cpu;
		show_cpu_stat(opt.pin_off ? "net " : "", result, flow_cpu);
		if (opt.pin_off)
			show_cpu_stat("app ", result, flow_cpu + opt.pin_off);
	}

	/* The rest is RR-only */
	if (opt.req_size == ~0U)
		return;

	for (r = 0; r < opt.n_conns; r++)
		warnx("%.1lf RPS",
		      (double)result->res[r].reqs /
		      result->time_usec * 1000000);

	if (opt.time_stats < 1)
		return;

	for (r = 0; r < opt.n_conns; r++) {
		for (i = 0; i < ARRAY_SIZE(result->res[r].lat_hist); i++) {
			if (!result->res[r].lat_hist[i])
				continue;
			if (start < 0)
				start = i;
			end = i + 1;
		}
		for (i = start; i < end; i++) {
			unsigned int val;
			const char *unit;

			if (i < 3) {
				val = 128 << i;
				unit = "ns";
			} else if (i < 13) {
				val = (1ULL << (i + 7)) / 1000;
				unit = "us";
			} else {
				val = (1ULL << (i + 7)) / (1000 * 1000);
				unit = "ms";
			}
			warnx("  [%3d%s] %d",
			      val, unit, result->res[r].lat_hist[i]);
		}
	}

	if (opt.time_stats < 2)
		return;

	for (r = 0; r < opt.n_conns; r++)
		warnx("p25:%uus p50:%uus p90:%uus p99:%uus p999:%uus p9999:%uus",
		      result->res[r].p25 * 128 / 1000,
		      result->res[r].p50 * 128 / 1000,
		      result->res[r].p90 * 128 / 1000,
		      result->res[r].p99 * 128 / 1000,
		      result->res[r].p999 * 128 / 1000,
		      result->res[r].p9999 * 128 / 1000);
}

static void
dump_result_machine(struct kpm_test_results *result, const char *dir,
		    struct kpm_connect_reply *conns, bool local)
{
	struct kpm_test_result res = {};
	struct kpm_cpu_load *cpu;
	unsigned int r;
	int flow_cpu;
	__u64 bytes;
	int i;

	for (r = 0; r < opt.n_conns; r++) {
#define S(f) res.f += result->res[r].f;
		S(rx_bytes);
		S(tx_bytes);
		S(reqs);
		S(retrans);
		S(reord_seen);
		S(rtt);
		S(rttvar);
		S(delivered_ce);
		S(snd_wnd);
		S(snd_cwnd);

		if (opt.time_stats < 2)
			continue;
		S(p25);
		S(p50);
		S(p90);
		S(p99);
		S(p999);
		S(p9999);
#undef S
	}
	res.rtt /= opt.n_conns;
	res.rttvar /= opt.n_conns;
	res.snd_wnd /= opt.n_conns;
	res.snd_cwnd /= opt.n_conns;
	res.p25 /= opt.n_conns;
	res.p50 /= opt.n_conns;
	res.p90 /= opt.n_conns;
	res.p99 /= opt.n_conns;
	res.p999 /= opt.n_conns;
	res.p9999 /= opt.n_conns;
	r = 0;

	/* Headers once on the first line */
	if (local && opt.output_hdr) {
		for (i = 0; i < 2; i++) {
			printf("tcp,,,,,,,");
			if (opt.time_stats >= 2)
				printf("latency,(us),,,,,");
			if (opt.n_conns < 2) {
				printf("net,,,,");
				if (opt.pin_off)
					printf("app,,,,");
			}
			printf("data%c", i ? '\n' : ',');
		}
		for (i = 0; i < 2; i++) {
			printf("retrans,reord,ce,rtt,rttvar,swnd,cwnd,");
			if (opt.time_stats >= 2)
				printf("p25,p50,p90,p99,p999,p9999,");
			if (opt.n_conns < 2) {
				printf("usr,sys,idle,sirq,");
				if (opt.pin_off)
					printf("usr,sys,idle,sirq,");
			}
			printf(i ? "rx\n" : "tx,");
		}
	}

	printf("%u,%u,%u,%u,%u,%u,%u,",
	       res.retrans, res.reord_seen, res.delivered_ce,
	       res.rtt, res.rttvar, res.snd_wnd, res.snd_cwnd);

	if (opt.time_stats >= 2)
		printf("%u,%u,%u,%u,%u,%u,",
		       res.p25 * 128 / 1000, res.p50 * 128 / 1000,
		       res.p90 * 128 / 1000, res.p99 * 128 / 1000,
		       res.p999 * 128 / 1000, res.p9999 * 128 / 1000);

	/* Dunno how to report CPU use, yet */
	if (opt.n_conns < 2) {
		flow_cpu = local ? conns[r].local.cpu : conns[r].remote.cpu;
		cpu = &result->cpu_load[flow_cpu];
		printf("%.4f,%.4f,%.4f,%.4f,",
		       cpu->user / 10000.0, cpu->system / 10000.0,
		       cpu->idle / 10000.0, cpu->sirq / 10000.0);

		if (opt.pin_off) {
			cpu = &result->cpu_load[flow_cpu + opt.pin_off];
			printf("%.4f,%.4f,%.4f,%.4f,",
			       cpu->user / 10000.0, cpu->system / 10000.0,
			       cpu->idle / 10000.0, cpu->sirq / 10000.0);
		}
	}

	bytes = local ? res.tx_bytes : res.rx_bytes;
	printf("%.3lf", (double)bytes * 8 / result->time_usec / 1000);
	printf(local ? "," : "\n");
}

/* copied from devmem.c */
static void inet_to_inet6(struct sockaddr *addr, struct sockaddr_in6 *out)
{
	out->sin6_addr.s6_addr32[3] = ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr32[0];
	out->sin6_addr.s6_addr32[0] = 0;
	out->sin6_addr.s6_addr32[1] = 0;
	out->sin6_addr.s6_addr16[4] = 0;
	out->sin6_addr.s6_addr16[5] = 0xffff;
	out->sin6_family = AF_INET6;
}

int inet_sockaddr(const char *str, struct sockaddr_in6 *out)
{
	struct sockaddr_in *sa4;
	struct sockaddr_in6 tmp;

	out->sin6_family = AF_INET6;
	if (inet_pton(AF_INET6, str, &(out->sin6_addr)) == 1) {
		out->sin6_family = AF_INET6;
		return 0;
	}

	sa4 = (struct sockaddr_in *)&tmp;
	if (inet_pton(AF_INET, str, &(sa4->sin_addr)) == 1) {
		sa4->sin_family = AF_INET;
		inet_to_inet6((void *)sa4, out);
		return 0;
	}

	return -1;
}

static int install_steering_rule(int server_fd, const char *ifname,
				 struct sockaddr_in6 *addr, __u16 port,
				 int queue_id, bool match_is_dst,
				 __s32 *out_rule_loc)
{
	struct kpm_steering_rule rule = {};

	memcpy(&rule.addr, addr, sizeof(rule.addr));
	rule.port = port;
	rule.match_is_dst = match_is_dst ? 1 : 0;
	rule.action = 0; /* add */
	rule.queue_id = queue_id;
	strncpy(rule.ifname, ifname, sizeof(rule.ifname) - 1);

	return kpm_req_steering_rule(server_fd, &rule, out_rule_loc);
}

static int remove_steering_rule(int server_fd, const char *ifname,
				__s32 rule_loc)
{
	struct kpm_steering_rule rule = {};

	rule.action = 1; /* delete */
	rule.rule_loc = rule_loc;
	strncpy(rule.ifname, ifname, sizeof(rule.ifname) - 1);

	return kpm_req_steering_rule(server_fd, &rule, NULL);
}

/*
 * Bidirectional mode: single client orchestrates flows in both directions.
 *
 * Forward direction: src -> dst (src sends, dst receives)
 * Reverse direction: dst -> src (dst sends, src receives)
 *
 * On each host we set up:
 *   - RX data queues for incoming data
 *   - ACK queues for ACKs of outgoing data
 *   - Workers pinned at SO_INCOMING_CPU + pin_off
 */
static int run_bidirectional(int src, int dst,
			     unsigned int src_ncpus, unsigned int dst_ncpus)
{
	struct kpm_connect_reply *fwd_conns = NULL, *rev_conns = NULL;
	__u32 *fwd_src_wrk_id, *fwd_dst_wrk_id;
	__u32 *rev_src_wrk_id, *rev_dst_wrk_id;
	struct sockaddr_in6 fwd_conn_addr, rev_conn_addr;
	struct kpm_test_results *result;
	struct kpm_test *test;
	__u32 fwd_src_tst_id, fwd_dst_tst_id;
	__u32 rev_src_tst_id, rev_dst_tst_id;
	socklen_t len;
	unsigned int i;
	size_t sz;
	int seq;
	struct sockaddr_in6 src_addr = {}, dst_addr = {};
	__s32 *steering_rule_locs = NULL;
	unsigned int n_steering_rules = 0;
	int ret = -1;

	if (inet_sockaddr(opt.src, &src_addr) < 0) {
		warnx("failed to get sockaddr from %s", opt.src);
		return -1;
	}
	if (inet_sockaddr(opt.dst, &dst_addr) < 0) {
		warnx("failed to get sockaddr from %s", opt.dst);
		return -1;
	}

	/* Max 4 rules per flow: fwd data, rev data, fwd ACK, rev ACK */
	steering_rule_locs = calloc(opt.n_conns * 4, sizeof(__s32));

	/* Net CPU arrays for correct CPU stat reporting */
	__u32 *fwd_src_net_cpu = calloc(opt.n_conns, sizeof(__u32));
	__u32 *fwd_dst_net_cpu = calloc(opt.n_conns, sizeof(__u32));
	__u32 *rev_src_net_cpu = calloc(opt.n_conns, sizeof(__u32));
	__u32 *rev_dst_net_cpu = calloc(opt.n_conns, sizeof(__u32));

	fwd_src_wrk_id = calloc(opt.n_conns, sizeof(__u32));
	fwd_dst_wrk_id = calloc(opt.n_conns, sizeof(__u32));
	rev_src_wrk_id = calloc(opt.n_conns, sizeof(__u32));
	rev_dst_wrk_id = calloc(opt.n_conns, sizeof(__u32));

	/* Phase 1: NIC Setup - configure modes on both hosts
	 *
	 * In spread mode, TX app CPUs are at net_cpu + n_conns, so
	 * xps_pin_off = n_conns to pair XPS correctly.
	 */
	__u32 bidi_xps_pin_off = opt.bidi_spread ? opt.n_conns : opt.pin_off;

	struct kpm_mode dst_mode = {
		.rx_mode = opt.devmem_rx ? KPM_RX_MODE_DEVMEM : KPM_RX_MODE_SOCKET,
		.tx_mode = opt.devmem_tx ? KPM_TX_MODE_DEVMEM : KPM_TX_MODE_SOCKET,
		.rx_provider = opt.devmem_rx_memory,
		.tx_provider = opt.devmem_tx_memory,
		.dev = opt.devmem_dst_dev,
		.dmabuf_rx_size_mb = opt.dmabuf_rx_size_mb,
		.dmabuf_tx_size_mb = opt.dmabuf_tx_size_mb,
		.num_rx_queues = opt.num_rx_queues,
		.addr = dst_addr,
		.validate = opt.validate,
		.iou = opt.iou_dst,
		.iou_rx_size_mb = opt.iou_rx_size_mb,
		.xps_pin_off = bidi_xps_pin_off,
		.xps_irq_start = opt.xps_dst_irq_start,
	};

	struct kpm_mode src_mode = {
		.rx_mode = opt.devmem_rx ? KPM_RX_MODE_DEVMEM : KPM_RX_MODE_SOCKET,
		.tx_mode = opt.devmem_tx ? KPM_TX_MODE_DEVMEM : KPM_TX_MODE_SOCKET,
		.rx_provider = opt.devmem_rx_memory,
		.tx_provider = opt.devmem_tx_memory,
		.dev = opt.devmem_src_dev,
		.dmabuf_rx_size_mb = opt.dmabuf_rx_size_mb,
		.dmabuf_tx_size_mb = opt.dmabuf_tx_size_mb,
		.num_rx_queues = opt.num_rx_queues,
		.addr = src_addr,
		.validate = opt.validate,
		.iou = opt.iou_src,
		.iou_rx_size_mb = opt.iou_rx_size_mb,
		.xps_pin_off = bidi_xps_pin_off,
		.xps_irq_start = opt.xps_src_irq_start,
	};

	/* Phase 2: Open acceptors on both hosts */
	/* Forward: dst accepts connections from src */
	if (opt.dst_listen_port) {
		len = sizeof(fwd_conn_addr);
		if (kpm_req_tcp_sock_ex(dst, opt.dst_listen_port,
					&fwd_conn_addr, &len) < 0) {
			warnx("Failed to create forward TCP acceptor");
			goto out;
		}
	} else {
		len = sizeof(fwd_conn_addr);
		if (kpm_req_tcp_sock(dst, &fwd_conn_addr, &len) < 0) {
			warnx("Failed to create forward TCP acceptor");
			goto out;
		}
	}

	/* Reverse: src accepts connections from dst */
	if (opt.src_listen_port) {
		len = sizeof(rev_conn_addr);
		if (kpm_req_tcp_sock_ex(src, opt.src_listen_port,
					&rev_conn_addr, &len) < 0) {
			warnx("Failed to create reverse TCP acceptor");
			goto out;
		}
	} else {
		len = sizeof(rev_conn_addr);
		if (kpm_req_tcp_sock(src, &rev_conn_addr, &len) < 0) {
			warnx("Failed to create reverse TCP acceptor");
			goto out;
		}
	}

	/* Set up modes after acceptors so devmem can bind to the tcp_sock */
	if (kpm_req_mode(dst, &dst_mode) < 0) {
		warnx("Failed to setup dst mode");
		goto out;
	}
	if (kpm_req_mode(src, &src_mode) < 0) {
		warnx("Failed to setup src mode");
		goto out;
	}

	/* Phase 2b: SMP affinity - pin queue IRQs to NUMA-local CPUs */
	if (opt.dst_ifname) {
		struct kpm_smp_affinity aff = {};

		strncpy(aff.ifname, opt.dst_ifname, sizeof(aff.ifname) - 1);

		/* dst data queues: receive forward traffic */
		aff.queue_start = opt.dst_queue_start;
		aff.queue_count = opt.n_conns;
		aff.cpu_start = opt.dst_cpu_start;
		if (kpm_req_smp_affinity(dst, &aff) < 0)
			warnx("Failed to set dst data queue affinity");

		/* dst ACK queues: receive ACKs for reverse TX
		 * Spread: ACK IRQs at cpu_start + 2*N (zone 3)
		 * Default: ACK IRQs at cpu_start + N (zone 2, overlaps RX app)
		 */
		if (opt.dst_ack_queue_start) {
			aff.queue_start = opt.dst_ack_queue_start;
			aff.cpu_start = opt.dst_cpu_start +
				(opt.bidi_spread ? 2 * opt.n_conns : opt.n_conns);
			if (kpm_req_smp_affinity(dst, &aff) < 0)
				warnx("Failed to set dst ACK queue affinity");
		}
	}
	if (opt.src_ifname) {
		struct kpm_smp_affinity aff = {};

		strncpy(aff.ifname, opt.src_ifname, sizeof(aff.ifname) - 1);

		/* src data queues: receive reverse traffic */
		aff.queue_start = opt.src_queue_start;
		aff.queue_count = opt.n_conns;
		aff.cpu_start = opt.src_cpu_start;
		if (kpm_req_smp_affinity(src, &aff) < 0)
			warnx("Failed to set src data queue affinity");

		/* src ACK queues: receive ACKs for forward TX */
		if (opt.src_ack_queue_start) {
			aff.queue_start = opt.src_ack_queue_start;
			aff.cpu_start = opt.src_cpu_start +
				(opt.bidi_spread ? 2 * opt.n_conns : opt.n_conns);
			if (kpm_req_smp_affinity(src, &aff) < 0)
				warnx("Failed to set src ACK queue affinity");
		}
	}

	/* Phase 3: Establish connections in both directions */
	warnx("Establishing forward connections (src -> dst)...");
	fwd_conns = spawn_conn(src, dst, &fwd_conn_addr, len);
	if (!fwd_conns) {
		warnx("Failed to establish forward connections");
		goto out;
	}

	warnx("Establishing reverse connections (dst -> src)...");
	rev_conns = spawn_conn(dst, src, &rev_conn_addr, len);
	if (!rev_conns) {
		warnx("Failed to establish reverse connections");
		goto out;
	}

	/* Phase 3b: Install steering rules to pin flows to queues */
	if (opt.dst_ifname) {
		for (i = 0; i < opt.n_conns; i++) {
			/* Steer forward RX data to dst data queue[i] */
			if (install_steering_rule(dst, opt.dst_ifname,
						  &src_addr,
						  fwd_conns[i].local.port,
						  opt.dst_queue_start + i,
						  false,
						  &steering_rule_locs[n_steering_rules]) < 0)
				warnx("Failed to install fwd data steering rule %u", i);
			else
				n_steering_rules++;
		}
	}
	if (opt.src_ifname) {
		for (i = 0; i < opt.n_conns; i++) {
			/* Steer reverse RX data to src data queue[i] */
			if (install_steering_rule(src, opt.src_ifname,
						  &dst_addr,
						  rev_conns[i].local.port,
						  opt.src_queue_start + i,
						  false,
						  &steering_rule_locs[n_steering_rules]) < 0)
				warnx("Failed to install rev data steering rule %u", i);
			else
				n_steering_rules++;
		}
	}
	if (opt.src_ifname && opt.src_ack_queue_start) {
		for (i = 0; i < opt.n_conns; i++) {
			/* Steer forward TX ACKs to src ACK queue[i] */
			if (install_steering_rule(src, opt.src_ifname,
						  &dst_addr,
						  fwd_conns[i].remote.port,
						  opt.src_ack_queue_start + i,
						  false,
						  &steering_rule_locs[n_steering_rules]) < 0)
				warnx("Failed to install fwd ACK steering rule %u", i);
			else
				n_steering_rules++;
		}
	}
	if (opt.dst_ifname && opt.dst_ack_queue_start) {
		for (i = 0; i < opt.n_conns; i++) {
			/* Steer reverse TX ACKs to dst ACK queue[i] */
			if (install_steering_rule(dst, opt.dst_ifname,
						  &src_addr,
						  rev_conns[i].remote.port,
						  opt.dst_ack_queue_start + i,
						  false,
						  &steering_rule_locs[n_steering_rules]) < 0)
				warnx("Failed to install rev ACK steering rule %u", i);
			else
				n_steering_rules++;
		}
	}

	/* Phase 4: Spawn and pin workers for both directions
	 *
	 * Default layout (pin_off=N, overlapping):
	 *   Per-NUMA: [RX data net: N] [TX ack net + RX app: N] [TX app: N]
	 *   Total: 3*N CPUs per NUMA node
	 *   Example (N=4, NUMA 0 at CPU 0):
	 *     CPUs 0-3: RX net (data queues)
	 *     CPUs 4-7: TX net (ack queues) AND RX app (overlap!)
	 *     CPUs 8-11: TX app
	 *
	 * Spread layout (--bidi-spread, no overlap):
	 *   Per-NUMA: [RX data net: N] [RX app: N] [TX ack net: N] [TX app: N]
	 *   Total: 4*N CPUs per NUMA node
	 *   Example (N=4, NUMA 0 at CPU 0):
	 *     CPUs 0-3: RX net (data queues)
	 *     CPUs 4-7: RX app
	 *     CPUs 8-11: TX net (ack queues)
	 *     CPUs 12-15: TX app
	 */
	for (i = 0; i < opt.n_conns; i++) {
		__u32 fwd_src_cpu, fwd_dst_cpu, rev_src_cpu, rev_dst_cpu;

		if (opt.src_ifname) {
			if (opt.bidi_spread) {
				/* Spread: TX net at cpu_start + 2*N */
				fwd_src_net_cpu[i] = opt.src_cpu_start + 2 * opt.n_conns + i;
				fwd_src_cpu = opt.src_cpu_start + 3 * opt.n_conns + i;
			} else {
				/* Default: TX net at cpu_start + N, app at + pin_off */
				fwd_src_net_cpu[i] = opt.src_cpu_start + opt.n_conns + i;
				fwd_src_cpu = opt.src_cpu_start + opt.n_conns + i + opt.pin_off;
			}
		} else {
			fwd_src_cpu = fwd_conns[i].local.cpu + opt.pin_off;
			fwd_src_net_cpu[i] = fwd_conns[i].local.cpu;
		}

		if (opt.dst_ifname) {
			if (opt.bidi_spread) {
				/* Spread: RX net at cpu_start, app at cpu_start + N */
				fwd_dst_net_cpu[i] = opt.dst_cpu_start + i;
				fwd_dst_cpu = opt.dst_cpu_start + opt.n_conns + i;
			} else {
				fwd_dst_net_cpu[i] = opt.dst_cpu_start + i;
				fwd_dst_cpu = opt.dst_cpu_start + i + opt.pin_off;
			}
		} else {
			fwd_dst_cpu = fwd_conns[i].remote.cpu + opt.pin_off;
			fwd_dst_net_cpu[i] = fwd_conns[i].remote.cpu;
		}

		if (opt.dst_ifname) {
			if (opt.bidi_spread) {
				/* Spread: TX net at cpu_start + 2*N */
				rev_src_net_cpu[i] = opt.dst_cpu_start + 2 * opt.n_conns + i;
				rev_src_cpu = opt.dst_cpu_start + 3 * opt.n_conns + i;
			} else {
				rev_src_net_cpu[i] = opt.dst_cpu_start + opt.n_conns + i;
				rev_src_cpu = opt.dst_cpu_start + opt.n_conns + i + opt.pin_off;
			}
		} else {
			rev_src_cpu = rev_conns[i].local.cpu + opt.pin_off;
			rev_src_net_cpu[i] = rev_conns[i].local.cpu;
		}

		if (opt.src_ifname) {
			if (opt.bidi_spread) {
				/* Spread: RX net at cpu_start, app at cpu_start + N */
				rev_dst_net_cpu[i] = opt.src_cpu_start + i;
				rev_dst_cpu = opt.src_cpu_start + opt.n_conns + i;
			} else {
				rev_dst_net_cpu[i] = opt.src_cpu_start + i;
				rev_dst_cpu = opt.src_cpu_start + i + opt.pin_off;
			}
		} else {
			rev_dst_cpu = rev_conns[i].remote.cpu + opt.pin_off;
			rev_dst_net_cpu[i] = rev_conns[i].remote.cpu;
		}

		if (spawn_worker(src, fwd_src_cpu, &fwd_src_wrk_id[i]) ||
		    spawn_worker(dst, fwd_dst_cpu, &fwd_dst_wrk_id[i]) ||
		    spawn_worker(dst, rev_src_cpu, &rev_src_wrk_id[i]) ||
		    spawn_worker(src, rev_dst_cpu, &rev_dst_wrk_id[i]))
			goto out_conns;
	}

	/* Phase 5: Start tests in both directions simultaneously */
	sz = sizeof(*test) + opt.n_conns * sizeof(test->specs[0]);
	test = calloc(1, sz);
	test->n_conns = opt.n_conns;
	test->time_sec = opt.time;

	/* Forward direction: dst passive test (receives) */
	for (i = 0; i < opt.n_conns; i++) {
		test->specs[i].connection_id = fwd_conns[i].remote.id;
		test->specs[i].worker_id = fwd_dst_wrk_id[i];
		test->specs[i].type = KPM_TEST_TYPE_STREAM;
		test->specs[i].read_size = opt.read_size;
		test->specs[i].write_size = opt.write_size;
	}
	test->active = 0;
	seq = kpm_send(dst, &test->hdr, sz, KPM_MSG_TYPE_TEST);
	{
		struct __kpm_generic_u32 *ack = kpm_receive(dst);
		if (!kpm_good_reply(ack, KPM_MSG_TYPE_TEST, seq)) {
			warnx("Bad ack for fwd dst test");
			free(ack);
			free(test);
			goto out_conns;
		}
		fwd_dst_tst_id = ack->val;
		free(ack);
	}

	/* Reverse direction: src passive test (receives) */
	for (i = 0; i < opt.n_conns; i++) {
		test->specs[i].connection_id = rev_conns[i].remote.id;
		test->specs[i].worker_id = rev_dst_wrk_id[i];
	}
	test->active = 0;
	seq = kpm_send(src, &test->hdr, sz, KPM_MSG_TYPE_TEST);
	{
		struct __kpm_generic_u32 *ack = kpm_receive(src);
		if (!kpm_good_reply(ack, KPM_MSG_TYPE_TEST, seq)) {
			warnx("Bad ack for rev src test");
			free(ack);
			free(test);
			goto out_conns;
		}
		rev_dst_tst_id = ack->val;
		free(ack);
	}

	/* Forward direction: src active test (sends) */
	for (i = 0; i < opt.n_conns; i++) {
		test->specs[i].connection_id = fwd_conns[i].local.id;
		test->specs[i].worker_id = fwd_src_wrk_id[i];
	}
	test->active = 1;
	seq = kpm_send(src, &test->hdr, sz, KPM_MSG_TYPE_TEST);
	{
		struct __kpm_generic_u32 *ack = kpm_receive(src);
		if (!kpm_good_reply(ack, KPM_MSG_TYPE_TEST, seq)) {
			warnx("Bad ack for fwd src test");
			free(ack);
			free(test);
			goto out_conns;
		}
		fwd_src_tst_id = ack->val;
		free(ack);
	}

	/* Reverse direction: dst active test (sends) */
	for (i = 0; i < opt.n_conns; i++) {
		test->specs[i].connection_id = rev_conns[i].local.id;
		test->specs[i].worker_id = rev_src_wrk_id[i];
	}
	test->active = 1;
	seq = kpm_send(dst, &test->hdr, sz, KPM_MSG_TYPE_TEST);
	{
		struct __kpm_generic_u32 *ack = kpm_receive(dst);
		if (!kpm_good_reply(ack, KPM_MSG_TYPE_TEST, seq)) {
			warnx("Bad ack for rev dst test");
			free(ack);
			free(test);
			goto out_conns;
		}
		rev_src_tst_id = ack->val;
		free(ack);
	}
	free(test);

	/*
	 * Collect results from both sockets. Each socket carries results
	 * for two tests (active + passive), so we need to dispatch by
	 * test_id rather than assuming ordering.
	 *
	 * src socket: fwd_src (active, sends) + rev_dst (passive, receives)
	 * dst socket: rev_src (active, sends) + fwd_dst (passive, receives)
	 *
	 * Active tests finish first (they drive the timer), then we
	 * end_test the passive side and collect those results.
	 */
	{
		int results_collected = 0;

		/* Collect 2 active results (one from each socket) */
		warnx("Waiting for results...");
		while (results_collected < 2) {
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(src, &fds);
			FD_SET(dst, &fds);
			int maxfd = src > dst ? src : dst;

			if (select(maxfd + 1, &fds, NULL, NULL, NULL) < 0) {
				warn("select");
				break;
			}

			if (FD_ISSET(src, &fds)) {
				result = kpm_receive(src);
				if (result && result->hdr.type == KPM_MSG_TYPE_TEST_RESULT) {
					if (result->test_id == fwd_src_tst_id) {
						dump_result(result, "Forward Source (TX)",
							    fwd_conns, true,
							    fwd_src_net_cpu);
					} else {
						dump_result(result, "Reverse Target (RX)",
							    rev_conns, false,
							    rev_dst_net_cpu);
					}
					results_collected++;
					free(result);
				}
			}
			if (FD_ISSET(dst, &fds)) {
				result = kpm_receive(dst);
				if (result && result->hdr.type == KPM_MSG_TYPE_TEST_RESULT) {
					if (result->test_id == rev_src_tst_id) {
						dump_result(result, "Reverse Source (TX)",
							    rev_conns, true,
							    rev_src_net_cpu);
					} else {
						dump_result(result, "Forward Target (RX)",
							    fwd_conns, false,
							    fwd_dst_net_cpu);
					}
					results_collected++;
					free(result);
				}
			}
		}

		/* Stop all tests */
		kpm_req_end_test(src, fwd_src_tst_id);
		kpm_req_end_test(dst, fwd_dst_tst_id);
		kpm_req_end_test(dst, rev_src_tst_id);
		kpm_req_end_test(src, rev_dst_tst_id);

		/* Collect 2 passive results */
		while (results_collected < 4) {
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(src, &fds);
			FD_SET(dst, &fds);
			int maxfd = src > dst ? src : dst;

			if (select(maxfd + 1, &fds, NULL, NULL, NULL) < 0) {
				warn("select");
				break;
			}

			if (FD_ISSET(src, &fds)) {
				result = kpm_receive(src);
				if (result && result->hdr.type == KPM_MSG_TYPE_TEST_RESULT) {
					if (result->test_id == fwd_src_tst_id) {
						dump_result(result, "Forward Source (TX)",
							    fwd_conns, true,
							    fwd_src_net_cpu);
					} else {
						dump_result(result, "Reverse Target (RX)",
							    rev_conns, false,
							    rev_dst_net_cpu);
					}
					results_collected++;
					free(result);
				}
			}
			if (FD_ISSET(dst, &fds)) {
				result = kpm_receive(dst);
				if (result && result->hdr.type == KPM_MSG_TYPE_TEST_RESULT) {
					if (result->test_id == rev_src_tst_id) {
						dump_result(result, "Reverse Source (TX)",
							    rev_conns, true,
							    rev_src_net_cpu);
					} else {
						dump_result(result, "Forward Target (RX)",
							    fwd_conns, false,
							    fwd_dst_net_cpu);
					}
					results_collected++;
					free(result);
				}
			}
		}
	}

	ret = 0;

out_conns:
	free(fwd_conns);
	free(rev_conns);
out:
	free(fwd_src_wrk_id);
	free(fwd_dst_wrk_id);
	free(rev_src_wrk_id);
	free(rev_dst_wrk_id);
	free(steering_rule_locs);
	free(fwd_src_net_cpu);
	free(fwd_dst_net_cpu);
	free(rev_src_net_cpu);
	free(rev_dst_net_cpu);
	return ret;
}

int main(int argc, char *argv[])
{
	enum kpm_rx_mode rx_mode = KPM_RX_MODE_SOCKET;
	enum kpm_tx_mode tx_mode = KPM_TX_MODE_SOCKET;
	unsigned int src_ncpus, dst_ncpus;
	struct __kpm_generic_u32 *ack_id;
	__u32 *src_wrk_cpu, *dst_wrk_cpu;
	struct kpm_connect_reply *conns;
	struct kpm_test_results *result;
	__u32 *src_wrk_id, *dst_wrk_id;
	struct sockaddr_in6 conn_addr;
	__u32 src_tst_id, dst_tst_id;
	struct sockaddr_in6 src_addr;
	struct addrinfo *addr;
	struct kpm_test *test;
	unsigned int i;
	socklen_t len;
	int src, dst;
	size_t sz;
	int seq, ret;

	opt_register_table(opts, NULL);

	/* Use early parse to set default for --validate based on --devmem-rx */
	if (!opt_early_parse(argc, argv, opt_log_stderr))
		exit(1);
	opt.validate = !opt.devmem_rx;

	if (!opt_parse(&argc, argv, opt_log_stderr))
		exit(1);

	err_set_progname(argv[0]);

	if (opt.read_size > KPM_MAX_OP_CHUNK ||
	    opt.write_size > KPM_MAX_OP_CHUNK)
		errx(1, "Max read/write size is %d", KPM_MAX_OP_CHUNK);
	if (opt.tcp_cong_ctrl &&
	    strnlen(opt.tcp_cong_ctrl, KPM_CC_NAME_LEN) == KPM_CC_NAME_LEN)
		errx(1, "TCP CC name is too long");
	if (opt.xpin) {
		if (opt.cpu_src_wrk != -1 || opt.cpu_dst_wrk != -1)
			errx(1, "Cross-pin can't use explicit pin");
		if (opt.pin_off)
			errx(1, "Cross-pin can't use pin off");
		if (opt.n_conns != 2)
			errx(1, "Cross-pin only works with 2 connections");
	}

	if (inet_sockaddr(opt.src, &src_addr) < 0)
		errx(1, "failed to get sockaddr from %s\n", opt.src);

	/* io_uring doesn't support devmem yet */
	if (opt.devmem_rx && opt.iou_dst)
		errx(1, "io_uring does not support --devmem-rx yet");
	if (opt.devmem_tx && opt.iou_src)
		errx(1, "io_uring does not support --devmem-tx yet");

	if (opt.msg_trunc && opt.validate)
		errx(1, "--msg-trunc and --validate yes are mutually exclusive");

	if (opt.msg_trunc && (opt.devmem_rx || opt.zerocopy_rx))
		errx(1, "--msg-trunc and (--devmem-rx or --zerocopy-rx) are mutually exclusive");

	if (opt.msg_trunc)
		rx_mode = KPM_RX_MODE_SOCKET_TRUNC;
	else if (opt.zerocopy_rx)
		rx_mode = KPM_RX_MODE_SOCKET_ZEROCOPY;
	else if (opt.devmem_rx)
		rx_mode = KPM_RX_MODE_DEVMEM;

	/* TODO: support --validate yes for cuda rx */
	if (opt.validate && opt.devmem_rx_memory == MEMORY_PROVIDER_CUDA)
		errx(1, "--devmem-rx-memory cuda does not support --validate yes");

	if (opt.msg_zerocopy && opt.devmem_tx)
		errx(1, "--msg-zerocopy and --devmem-tx are mutually exclusive");

	if (opt.msg_zerocopy)
		tx_mode = KPM_TX_MODE_SOCKET_ZEROCOPY;
	else if (opt.devmem_tx)
		tx_mode = KPM_TX_MODE_DEVMEM;

	src_wrk_id = calloc(opt.n_conns, sizeof(*src_wrk_id));
	dst_wrk_id = calloc(opt.n_conns, sizeof(*dst_wrk_id));
	src_wrk_cpu = calloc(opt.n_conns, sizeof(*src_wrk_cpu));
	dst_wrk_cpu = calloc(opt.n_conns, sizeof(*dst_wrk_cpu));

	addr = net_client_lookup(opt.src, opt.src_svc, AF_UNSPEC, SOCK_STREAM);
	if (!addr)
		errx(1, "Failed to look up service to connect to");

	/* Src */
	src = net_connect(addr);
	freeaddrinfo(addr);
	if (src < 1)
		err(1, "Failed to connect");

	addr = net_client_lookup(opt.dst, opt.dst_svc, AF_UNSPEC, SOCK_STREAM);
	if (!addr)
		errx(1, "Failed to look up service to connect to");

	if (kpm_xchg_hello(src, &src_ncpus))
		errx(2, "Bad hello");

	/* Dst */
	dst = net_connect(addr);
	freeaddrinfo(addr);
	if (dst < 1)
		err(1, "Failed to connect");

	if (kpm_xchg_hello(dst, &dst_ncpus))
		errx(2, "Bad hello");

	if (opt.bidirectional) {
		ret = run_bidirectional(src, dst, src_ncpus, dst_ncpus);
		close(src);
		close(dst);
		return ret;
	}

	/* Main */
	len = sizeof(conn_addr);
	if (kpm_req_tcp_sock(dst, &conn_addr, &len) < 0) {
		warnx("Failed create TCP acceptor");
		goto out;
	}

	struct kpm_mode dst_mode = {
		.rx_mode = rx_mode,
		.tx_mode = tx_mode,
		.rx_provider = opt.devmem_rx_memory,
		.tx_provider = opt.devmem_tx_memory,
		.dev = opt.devmem_dst_dev,
		.dmabuf_rx_size_mb = opt.dmabuf_rx_size_mb,
		.dmabuf_tx_size_mb = opt.dmabuf_tx_size_mb,
		.num_rx_queues = opt.num_rx_queues,
		.validate = opt.validate,
		.iou = opt.iou_dst,
		.iou_rx_size_mb = opt.iou_rx_size_mb,
		.xps_pin_off = opt.pin_off,
		.xps_irq_start = opt.xps_dst_irq_start,
	};
	if (kpm_req_mode(dst, &dst_mode) < 0) {
		warnx("Failed setup destination mode");
		goto out;
	}

	struct kpm_mode src_mode = {
		.rx_mode = rx_mode,
		.tx_mode = tx_mode,
		.rx_provider = opt.devmem_rx_memory,
		.tx_provider = opt.devmem_tx_memory,
		.dev = opt.devmem_src_dev,
		.dmabuf_rx_size_mb = opt.dmabuf_rx_size_mb,
		.dmabuf_tx_size_mb = opt.dmabuf_tx_size_mb,
		.num_rx_queues = opt.num_rx_queues,
		.addr = src_addr,
		.validate = opt.validate,
		.iou = opt.iou_src,
		.iou_rx_size_mb = opt.iou_rx_size_mb,
		.xps_pin_off = opt.pin_off,
		.xps_irq_start = opt.xps_src_irq_start,
	};
	if (kpm_req_mode(src, &src_mode) < 0) {
		warnx("Failed setup source mode");
		goto out;
	}

	conns = spawn_conn(src, dst, &conn_addr, len);
	if (!conns)
		goto out;

	if (opt.tls || opt.tls_rx || opt.tls_tx) {
		struct tls12_crypto_info_aes_gcm_128 aes128 = {};
		unsigned int rx, src_mask, dst_mask;

		aes128.info.version = opt.tls_ver;
		aes128.info.cipher_type = TLS_CIPHER_AES_GCM_128;

		rx = KPM_TLS_RX;
		if (opt.tls_nopad)
			rx |= KPM_TLS_NOPAD;
		if (opt.tls) {
			src_mask = dst_mask = KPM_TLS_TX | rx;
		} else if (opt.tls_rx) {
			src_mask = rx;
			dst_mask = KPM_TLS_TX;
		} else {
			src_mask = KPM_TLS_TX;
			dst_mask = rx;
		}

		for (i = 0; i < opt.n_conns; i++) {
			if (kpm_req_tls(src, conns[i].local.id,
					KPM_TLS_ULP | src_mask,
					&aes128, sizeof(aes128)) ||
			    kpm_req_tls(dst, conns[i].remote.id,
					KPM_TLS_ULP | dst_mask,
					&aes128, sizeof(aes128))) {
				warnx("TLS setup failed");
				goto out_id;
			}
		}
	}

	for (i = 0; i < opt.n_conns; i++) {
		struct kpm_connect_reply *id = &conns[i];

		if (opt.xpin)
			src_wrk_cpu[i] = conns[!i].local.cpu;
		else if (opt.cpu_src_wrk != -1)
			src_wrk_cpu[i] = opt.cpu_src_wrk;
		else
			src_wrk_cpu[i] = id->local.cpu + opt.pin_off;

		if (opt.xpin)
			dst_wrk_cpu[i] = conns[!i].remote.cpu;
		if (opt.cpu_dst_wrk != -1)
			dst_wrk_cpu[i] = opt.cpu_dst_wrk;
		else
			dst_wrk_cpu[i] = id->remote.cpu + opt.pin_off;

		if (spawn_worker(src, src_wrk_cpu[i], &src_wrk_id[i]) ||
		    spawn_worker(dst, dst_wrk_cpu[i], &dst_wrk_id[i]))
			goto out_id;
	}

	sz = sizeof(*test) + opt.n_conns * sizeof(test->specs[0]);
	test = malloc(sz);
	memset(test, 0, sz);

	test->n_conns = opt.n_conns;
	test->time_sec = opt.time;
	for (i = 0; i < opt.n_conns; i++) {
		test->specs[i].connection_id = conns[i].remote.id;
		test->specs[i].worker_id = dst_wrk_id[i];
		test->specs[i].read_size = opt.read_size;
		test->specs[i].write_size = opt.write_size;
		if (opt.req_size == ~0U) {
			test->specs[i].type = KPM_TEST_TYPE_STREAM;
		} else {
			test->specs[i].type = KPM_TEST_TYPE_RR;
			test->specs[i].arg.rr.req_size = opt.req_size;
			test->specs[i].arg.rr.resp_size = opt.resp_size ?: opt.req_size;
			test->specs[i].arg.rr.timings = opt.time_stats;
		}
	}

	seq = kpm_send(dst, &test->hdr, sz, KPM_MSG_TYPE_TEST);

	ack_id = kpm_receive(dst);
	if (!kpm_good_reply(ack_id, KPM_MSG_TYPE_TEST, seq)) {
		warnx("Invalid ack for test %d %d",
		      ack_id->hdr.type, ack_id->hdr.len);
		goto out_id;
	}
	dst_tst_id = ack_id->val;
	dbg("Test id dst %d", dst_tst_id);
	free(ack_id);

	test->active = 1;
	for (i = 0; i < opt.n_conns; i++) {
		test->specs[i].connection_id = conns[i].local.id;
		test->specs[i].worker_id = src_wrk_id[i];
	}

	seq = kpm_send(src, &test->hdr, sz, KPM_MSG_TYPE_TEST);
	free(test);

	ack_id = kpm_receive(src);
	if (!kpm_good_reply(ack_id, KPM_MSG_TYPE_TEST, seq)) {
		warnx("Invalid ack for test %d %d",
		      ack_id->hdr.type, ack_id->hdr.len);
		goto out_id;
	}
	src_tst_id = ack_id->val;
	dbg("Test id src %d", src_tst_id);
	free(ack_id);

	/* Source worker is done */
	result = kpm_receive(src);
	if (!result) {
		warnx("No result");
		goto out_id;
	}
	sz = sizeof(*result) + opt.n_conns * sizeof(result->res[0]);
	if (result->hdr.type != KPM_MSG_TYPE_TEST_RESULT ||
	    result->hdr.len < sz)
		warnx("Invalid result %d %d",
		      result->hdr.type, result->hdr.len);
	else if (opt.output_csv)
		dump_result_machine(result, "Source", conns, true);
	else
		dump_result(result, "Source", conns, true, NULL);
	free(result);

	/* Stop the test on both ends */
	if (kpm_req_end_test(src, src_tst_id) ||
	    kpm_req_end_test(dst, dst_tst_id))
		warnx("Failed to stop test");

	/* Destination worker is done */
	result = kpm_receive(dst);
	if (!result) {
		warnx("No result");
		goto out_id;
	}
	if (result->hdr.type != KPM_MSG_TYPE_TEST_RESULT ||
	    result->hdr.len < sizeof(*result) + sizeof(result->res[0]))
		warnx("Invalid result %d %d",
		      result->hdr.type, result->hdr.len);
	else if (opt.output_csv)
		dump_result_machine(result, "Source", conns, false);
	else
		dump_result(result, "Target", conns, false, NULL);
	free(result);

out_id:
	free(conns);
out:
	close(src);
	close(dst);

	return 0;
}
