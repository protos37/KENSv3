#ifndef _COMMON_HPP_
#define _COMMON_HPP_

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define ETH_ALEN 6

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_FLAG(hdr) (hdr.fin | (hdr.syn << 1) | (hdr.rst << 2) | (hdr.psh << 3) | (hdr.ack << 4) | (hdr.urg << 5))

struct ethhdr
{
	unsigned char h_dest[ETH_ALEN];
	unsigned char h_source[ETH_ALEN];
	uint16_t h_proto;
};

struct hdr
{
	struct ethhdr eth;
	struct iphdr ip;
	struct tcphdr tcp;
} __attribute__((packed));

#endif
