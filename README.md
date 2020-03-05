# simple_sniffer
Very simple raw network sniffer that outputs a PCAP file

This small C program can be compiled and run on most linux-based embedded 
systems to enable very simplistic network traffic capture.

Usage:

`./simple_sniffer file.pcap [ifname]`

The interface name (`ifname`) is optional. If specified, only capture packets 
on that interface. If not specified, packets from all interfaces will be captured.
This has interesting results if the system has non-ethernet interfaces since the PCAP is 
written to assume ethernet.

**Installation**

Compile with an appropriate compiler for your platform. There are no external dependencies
or libraries. For example, to compile for an ARMHF target:

`arm-none-linux-gnueabihf-gcc simple_sniffer.c -o simple_sniffer`

will create the appropriate binary you can then copy onto your target system

**Issues:**

For reasons unkown, if you specify an interface name, it looks like in some cases 
the first handful of packets you receive may come from another interface. So if you
get some weird results initially, then the rest of the packets are what you expect,
it's probably a bug in this program.
