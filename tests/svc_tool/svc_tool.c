// SPDX-License-Identifier: GPL-2.0
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <uapi/ethernet/cxi-abi.h>

enum svc_preset {
	PRESET_ETH,
	PRESET_SRIOV,
};

static int open_cxi_device(const char *dev_name)
{
	char path[64];
	int fd;

	if (strncmp(dev_name, "/dev/", 5) == 0)
		snprintf(path, sizeof(path), "%s", dev_name);
	else
		snprintf(path, sizeof(path), "/dev/%s", dev_name);

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Error: failed to open %s: %s\n",
			path, strerror(errno));
		return -1;
	}

	return fd;
}

static int alloc_parent_svc(int fd, const struct cxi_svc_desc *desc,
			    unsigned int *svc_id_out)
{
	struct cxi_svc_alloc_resp resp = {};
	struct cxi_svc_alloc_cmd cmd = {
		.op = CXI_OP_SVC_ALLOC_PARENT,
		.resp = &resp,
		.svc_desc = *desc,
	};
	ssize_t ret;

	ret = write(fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd)) {
		fprintf(stderr, "Error: CXI_OP_SVC_ALLOC_PARENT failed: %s\n",
			strerror(errno));
		return -1;
	}

	*svc_id_out = resp.svc_id;
	return 0;
}

static int set_vni_range(int fd, unsigned int svc_id,
			 unsigned int vni_min, unsigned int vni_max)
{
	struct cxi_svc_vni_range_cmd cmd = {
		.op = CXI_OP_SVC_SET_VNI_RANGE,
		.resp = NULL,
		.svc_id = svc_id,
		.vni_min = vni_min,
		.vni_max = vni_max,
	};
	ssize_t ret;

	ret = write(fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd)) {
		fprintf(stderr, "Error: CXI_OP_SVC_SET_VNI_RANGE failed: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

static int enable_svc(int fd, unsigned int svc_id, bool enable)
{
	struct cxi_svc_enable_cmd cmd = {
		.op = CXI_OP_SVC_ENABLE,
		.resp = NULL,
		.svc_id = svc_id,
		.enable = enable,
	};
	ssize_t ret;

	ret = write(fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd)) {
		fprintf(stderr, "Error: CXI_OP_SVC_ENABLE failed: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

static int create_eth_preset(int fd, unsigned int *svc_id_out)
{
	struct cxi_svc_desc desc = {
		.resource_limits = 1,
		.restricted_members = 0,
		.restricted_vnis = 1,
		.restricted_tcs = 0,
		.enable = 1,
		.num_vld_vnis = 1,
		.vnis = { 2 },
		.limits = {
			.acs  = { .max = 8,     .res = 8 },
			.eqs  = { .max = 256,   .res = 8 },
			.ptes = { .max = 64,    .res = 32 },
			.txqs = { .max = 256,   .res = 8 },
			.tgqs = { .max = 256,   .res = 8 },
			.tles = { .max = 512,   .res = 512 },
			.les  = { .max = 16384, .res = 4096 },
			.cts  = { .max = 0,     .res = 0 },
		},
	};

	return alloc_parent_svc(fd, &desc, svc_id_out);
}

static int create_sriov_preset(int fd, unsigned int *svc_id_out)
{
	struct cxi_svc_desc desc = {
		.resource_limits = 1,
		.restricted_members = 0,
		.restricted_vnis = 0,
		.restricted_tcs = 0,
		.enable = 0,
		.limits = {
			.acs  = { .max = 1022,  .res = 1022 },
			.eqs  = { .max = 2047,  .res = 2047 },
			.cts  = { .max = 2047,  .res = 2047 },
			.ptes = { .max = 2047,  .res = 2047 },
			.txqs = { .max = 1022,  .res = 1022 },
			.tgqs = { .max = 511,   .res = 511 },
			.tles = { .max = 1536,  .res = 1536 },
			.les  = { .max = 16383, .res = 16383 },
		},
	};
	unsigned int svc_id;
	int ret;

	ret = alloc_parent_svc(fd, &desc, &svc_id);
	if (ret < 0)
		return ret;

	ret = set_vni_range(fd, svc_id, 32, 63);
	if (ret < 0)
		return ret;

	ret = enable_svc(fd, svc_id, true);
	if (ret < 0)
		return ret;

	*svc_id_out = svc_id;
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <eth|sriov> [device]\n"
		"\n"
		"Creates a CXI parent service using a preset descriptor and prints the svc_id.\n"
		"\n"
		"Presets:\n"
		"  eth    Parent service for Ethernet VF tests (VNI 2)\n"
		"  sriov  Parent service for SR-IOV tests (VNIs 32-63)\n"
		"\n"
		"Arguments:\n"
		"  device CXI device name (default: cxi0)\n",
		prog);
}

int main(int argc, char *argv[])
{
	const char *preset_name;
	const char *dev_name = "cxi0";
	enum svc_preset preset;
	unsigned int svc_id = 0;
	int fd;
	int ret;

	if (argc < 2 || strcmp(argv[1], "-h") == 0 ||
	    strcmp(argv[1], "--help") == 0) {
		usage(argv[0]);
		return 1;
	}

	preset_name = argv[1];
	if (strcmp(preset_name, "eth") == 0) {
		preset = PRESET_ETH;
	} else if (strcmp(preset_name, "sriov") == 0) {
		preset = PRESET_SRIOV;
	} else {
		fprintf(stderr, "Error: unknown preset '%s'\n", preset_name);
		usage(argv[0]);
		return 1;
	}

	if (argc >= 3)
		dev_name = argv[2];

	fd = open_cxi_device(dev_name);
	if (fd < 0)
		return 1;

	if (preset == PRESET_ETH)
		ret = create_eth_preset(fd, &svc_id);
	else
		ret = create_sriov_preset(fd, &svc_id);

	close(fd);

	if (ret < 0)
		return 1;

	printf("%u\n", svc_id);
	return 0;
}
