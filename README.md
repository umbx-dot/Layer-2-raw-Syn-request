# raw_l2_syn

## Overview

`raw_l2_syn` is a minimal C program that constructs and sends a handcrafted Ethernet frame containing an IPv4 TCP SYN packet over a raw Layer 2 socket.

## Requirements

- Linux with raw socket support
- Root privileges to create and send raw packets
- GCC or compatible C compiler

## Build

`gcc -o raw_l2_syn raw_l2_syn.c`

## Notes

- Update NIC in line 48 to your Interface
- Update Source MAC and IP at line 68 and 92
- Update Destination MAC and IP at line 63 and 93
