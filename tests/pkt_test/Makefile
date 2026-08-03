# SPDX-License-Identifier: GPL-2.0
# Copyright 2026 Hewlett Packard Enterprise Development LP

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror

all: pkt_tool

pkt_tool: pkt_tool.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f pkt_tool

.PHONY: all clean
