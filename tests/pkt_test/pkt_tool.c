// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define MAGIC "PKTTEST1"
#define MAGIC_LEN 8
#define DEFAULT_ETHERTYPE 0x88B5
#define MAX_PAYLOAD 512

enum mode_type {
	MODE_NONE = 0,
	MODE_SEND,
	MODE_RECV,
};

enum traffic_type {
	TRAFFIC_ANY = -1,
	TRAFFIC_NORMAL = 0,
	TRAFFIC_MULTICAST = 1,
	TRAFFIC_ALLMULTI = 2,
	TRAFFIC_BROADCAST = 3,
};

#pragma pack(push, 1)
struct pkt_header {
	char magic[MAGIC_LEN];
	uint8_t traffic;
	uint32_t seq;
	char user[MAX_PAYLOAD - MAGIC_LEN - 1 - sizeof(uint32_t)];
};
#pragma pack(pop)

struct opts {
	enum mode_type mode;
	enum traffic_type traffic;
	char iface[IFNAMSIZ];
	char dst_mac[18];
	char src_mac[18];
	char expect_src[18];
	char expect_dst[18];
	char expect_user[sizeof(((struct pkt_header *)0)->user)];
	char payload[sizeof(((struct pkt_header *)0)->user)];
	int timeout_ms;
	int timeout_set;
	int count;
	int interval_ms;
	int rx_allmulti;
	uint16_t ethertype;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s --mode send --iface IFACE --dst-mac MAC [options]\n"
		"  %s --mode recv --iface IFACE [options]\n\n"
		"Required:\n"
		"  --mode send|recv\n"
		"  --iface IFACE\n\n"
		"Send options:\n"
		"  --dst-mac MAC             Destination MAC\n"
		"  --src-mac MAC             Override source MAC (default: iface MAC)\n"
		"  --count N                 Number of packets (default: 1)\n"
		"  --interval-ms N           Gap between packets (default: 100)\n\n"
		"Receive options:\n"
		"  --expect-src MAC          Match source MAC\n"
		"  --expect-dst MAC          Match destination MAC\n"
		"  --expect-payload TEXT     Match payload text\n"
		"  --expect-user TEXT        Alias of --expect-payload (deprecated)\n"
		"  --timeout-ms N            Receive timeout in ms (default: no timeout)\n"
		"  --rx-allmulti             Enable socket all-multicast membership\n\n"
		"Common options:\n"
		"  --traffic normal|multicast|allmulti|broadcast\n"
		"  --payload TEXT            Payload text\n"
		"  --ethertype HEX           Ethernet type (default: 0x88B5)\n",
		prog, prog);
}

static int parse_mac(const char *str, uint8_t mac[6])
{
	unsigned int b[6];

	if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
		    &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
		return -1;
	}
	for (int i = 0; i < 6; i++) {
		if (b[i] > 0xff)
			return -1;
		mac[i] = (uint8_t)b[i];
	}
	return 0;
}

static int parse_traffic(const char *value, enum traffic_type *traffic)
{
	if (!strcmp(value, "normal"))
		*traffic = TRAFFIC_NORMAL;
	else if (!strcmp(value, "multicast"))
		*traffic = TRAFFIC_MULTICAST;
	else if (!strcmp(value, "allmulti"))
		*traffic = TRAFFIC_ALLMULTI;
	else if (!strcmp(value, "broadcast"))
		*traffic = TRAFFIC_BROADCAST;
	else
		return -1;
	return 0;
}

static int get_iface_mac(const char *iface, uint8_t mac[6])
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;

	if (fd < 0) {
		perror("socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		close(fd);
		return -1;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	close(fd);
	return 0;
}

static int open_packet_socket(const char *iface, uint16_t ethertype, int *ifindex)
{
	int fd;
	struct sockaddr_ll sll;

	*ifindex = if_nametoindex(iface);
	if (*ifindex == 0) {
		perror("if_nametoindex");
		return -1;
	}

	fd = socket(AF_PACKET, SOCK_RAW, htons(ethertype));
	if (fd < 0) {
		perror("socket(AF_PACKET)");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ethertype);
	sll.sll_ifindex = *ifindex;

	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		perror("bind");
		close(fd);
		return -1;
	}

	return fd;
}

static int set_rx_allmulti(int fd, int ifindex)
{
	struct packet_mreq mreq;

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_ALLMULTI;

	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		perror("setsockopt(PACKET_MR_ALLMULTI)");
		return -1;
	}

	return 0;
}

static int run_send(const struct opts *o)
{
	int ifindex;
	int fd;
	uint8_t src[6];
	uint8_t dst[6];
	uint8_t frame[ETH_FRAME_LEN];
	struct ether_header *eth = (struct ether_header *)frame;
	struct pkt_header *hdr = (struct pkt_header *)(frame + sizeof(*eth));
	size_t frame_len;

	if (o->dst_mac[0] == '\0') {
		fprintf(stderr, "--dst-mac is required in send mode\n");
		return 1;
	}

	if (parse_mac(o->dst_mac, dst) != 0) {
		fprintf(stderr, "invalid dst MAC: %s\n", o->dst_mac);
		return 1;
	}

	if (o->src_mac[0] != '\0') {
		if (parse_mac(o->src_mac, src) != 0) {
			fprintf(stderr, "invalid src MAC: %s\n", o->src_mac);
			return 1;
		}
	} else if (get_iface_mac(o->iface, src) != 0) {
		return 1;
	}

	fd = open_packet_socket(o->iface, o->ethertype, &ifindex);
	if (fd < 0)
		return 1;

	memset(frame, 0, sizeof(frame));
	memcpy(eth->ether_dhost, dst, 6);
	memcpy(eth->ether_shost, src, 6);
	eth->ether_type = htons(o->ethertype);
	memcpy(hdr->magic, MAGIC, MAGIC_LEN);
	hdr->traffic = (o->traffic == TRAFFIC_ANY) ? TRAFFIC_NORMAL : (uint8_t)o->traffic;
	snprintf(hdr->user, sizeof(hdr->user), "%s", o->payload);
	frame_len = sizeof(*eth) + sizeof(*hdr);

	for (int i = 0; i < o->count; i++) {
		hdr->seq = htonl((uint32_t)i + 1);
		if (send(fd, frame, frame_len, 0) < 0) {
			perror("send");
			close(fd);
			return 1;
		}
		if (o->interval_ms > 0 && i + 1 < o->count)
			usleep((useconds_t)o->interval_ms * 1000);
	}

	close(fd);
	return 0;
}

static int match_mac(const uint8_t mac[6], const char *expected)
{
	uint8_t exp[6];

	if (expected[0] == '\0')
		return 1;
	if (parse_mac(expected, exp) != 0)
		return 0;
	return memcmp(mac, exp, 6) == 0;
}

static int match_user(const char *actual, const char *expected)
{
	if (expected[0] == '\0')
		return 1;
	return strcmp(actual, expected) == 0;
}

static int run_recv(const struct opts *o)
{
	int ifindex;
	int fd;
	int matched = 0;
	uint8_t buf[2048];
	struct timeval start, now;
	long elapsed_ms;

	fd = open_packet_socket(o->iface, o->ethertype, &ifindex);
	if (fd < 0)
		return 1;

	if (o->rx_allmulti && set_rx_allmulti(fd, ifindex) != 0) {
		close(fd);
		return 1;
	}

	if (gettimeofday(&start, NULL) != 0) {
		perror("gettimeofday");
		close(fd);
		return 1;
	}

	while (matched < o->count) {
		struct sockaddr_ll from;
		socklen_t fromlen = sizeof(from);
		ssize_t n = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT,
				     (struct sockaddr *)&from, &fromlen);

		/* Skip our own outgoing frames so a receiver sharing an interface
		 * with a sender counts only genuinely received copies.
		 */
		if (n >= (ssize_t)(sizeof(struct ether_header) + sizeof(struct pkt_header)) &&
		    from.sll_pkttype != PACKET_OUTGOING) {
			struct ether_header *eth = (struct ether_header *)buf;
			struct pkt_header *hdr =
				(struct pkt_header *)(buf + sizeof(struct ether_header));

			if (memcmp(hdr->magic, MAGIC, MAGIC_LEN) == 0 &&
			    (o->traffic == TRAFFIC_ANY || hdr->traffic == (uint8_t)o->traffic) &&
			    match_mac(eth->ether_shost, o->expect_src) &&
			    match_mac(eth->ether_dhost, o->expect_dst) &&
			    match_user(hdr->user, o->expect_user)) {
				matched++;
			}
		} else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			perror("recv");
			close(fd);
			return 1;
		}

		if (gettimeofday(&now, NULL) != 0) {
			perror("gettimeofday");
			close(fd);
			return 1;
		}
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
			(now.tv_usec - start.tv_usec) / 1000L;
		if (o->timeout_set && elapsed_ms > o->timeout_ms)
			break;
		usleep(10 * 1000);
	}

	close(fd);
	if (matched != o->count) {
		fprintf(stderr, "matched %d packets, expected %d\n", matched, o->count);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct opts o = {
		.mode = MODE_NONE,
		.traffic = TRAFFIC_ANY,
		.timeout_ms = 0,
		.timeout_set = 0,
		.count = 1,
		.interval_ms = 100,
		.rx_allmulti = 0,
		.ethertype = DEFAULT_ETHERTYPE,
	};
	int c;
	static const struct option long_opts[] = {
		{"mode", required_argument, NULL, 'm'},
		{"iface", required_argument, NULL, 'i'},
		{"dst-mac", required_argument, NULL, 'd'},
		{"src-mac", required_argument, NULL, 's'},
		{"expect-src", required_argument, NULL, 'S'},
		{"expect-dst", required_argument, NULL, 'D'},
		{"expect-payload", required_argument, NULL, 'U'},
		{"expect-user", required_argument, NULL, 'U'},
		{"traffic", required_argument, NULL, 't'},
		{"payload", required_argument, NULL, 'p'},
		{"timeout-ms", required_argument, NULL, 'T'},
		{"count", required_argument, NULL, 'c'},
		{"interval-ms", required_argument, NULL, 'I'},
		{"rx-allmulti", no_argument, NULL, 'a'},
		{"ethertype", required_argument, NULL, 'e'},
		{NULL, 0, NULL, 0},
	};

	while ((c = getopt_long(argc, argv, "m:i:d:s:S:D:U:t:p:T:c:I:ae:",
				 long_opts, NULL)) != -1) {
		switch (c) {
		case 'm':
			if (!strcmp(optarg, "send")) {
				o.mode = MODE_SEND;
			} else if (!strcmp(optarg, "recv")) {
				o.mode = MODE_RECV;
			} else {
				fprintf(stderr, "invalid mode: %s\n", optarg);
				return 1;
			}
			break;
		case 'i':
			strncpy(o.iface, optarg, sizeof(o.iface) - 1);
			break;
		case 'd':
			strncpy(o.dst_mac, optarg, sizeof(o.dst_mac) - 1);
			break;
		case 's':
			strncpy(o.src_mac, optarg, sizeof(o.src_mac) - 1);
			break;
		case 'S':
			strncpy(o.expect_src, optarg, sizeof(o.expect_src) - 1);
			break;
		case 'D':
			strncpy(o.expect_dst, optarg, sizeof(o.expect_dst) - 1);
			break;
		case 'U':
			strncpy(o.expect_user, optarg, sizeof(o.expect_user) - 1);
			break;
		case 't':
			if (parse_traffic(optarg, &o.traffic) != 0) {
				fprintf(stderr, "invalid traffic type: %s\n", optarg);
				return 1;
			}
			break;
		case 'p':
			strncpy(o.payload, optarg, sizeof(o.payload) - 1);
			break;
		case 'T':
			o.timeout_ms = atoi(optarg);
			o.timeout_set = 1;
			break;
		case 'c':
			o.count = atoi(optarg);
			break;
		case 'I':
			o.interval_ms = atoi(optarg);
			break;
		case 'a':
			o.rx_allmulti = 1;
			break;
		case 'e': {
			unsigned long x = strtoul(optarg, NULL, 0);

			if (x > 0xffff) {
				fprintf(stderr, "invalid ethertype: %s\n", optarg);
				return 1;
			}
			o.ethertype = (uint16_t)x;
			break;
		}
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (o.mode == MODE_NONE || o.iface[0] == '\0') {
		usage(argv[0]);
		return 1;
	}
	if (o.count <= 0 || o.interval_ms < 0) {
		fprintf(stderr, "invalid numeric arguments\n");
		return 1;
	}
	if (o.timeout_set && o.timeout_ms <= 0) {
		fprintf(stderr, "invalid numeric arguments\n");
		return 1;
	}

	if (o.mode == MODE_SEND)
		return run_send(&o);
	return run_recv(&o);
}
