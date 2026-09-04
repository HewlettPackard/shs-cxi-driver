# SPDX-License-Identifier: GPL-2.0
# Copyright 2026 Hewlett Packard Enterprise Development LP

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror \
	-I../../include \
	-I../../../cassini-headers/install/include \
	-I../../../cassini-headers/include

all: svc_tool

svc_tool: svc_tool.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f svc_tool

.PHONY: all clean
