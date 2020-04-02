#pragma once
#include <windows.h>

//TCP Flags
#define FIN 0x1
#define SYN 0x2
#define RST 0x4
#define PSH 0x8
#define ACK 0xf
#define URG 0x20
#define ECN 0x40
#define CWR 0x80

//Convo issue flags
#define IPv4_TTL_MANIPULATION 0x1
#define TCP_SYNRT 0x2
#define TCP_RT 0x4

//How bitmasking works: https://stackoverflow.com/questions/18591924/how-to-use-bitmask

typedef struct ethernet_header{
	BYTE dst_mac[6];
	BYTE src_mac[6];
	u_short type;
}ethernet_header;

/* IP Address */
typedef struct ip_address{
	u_char oct1;
	u_char oct2;
	u_char oct3;
	u_char oct4;
}ip_address;

/* IP Header */
typedef struct ip_header{
	u_char ver_ihl;
	u_char tos;
	u_short tlen;
	u_short identification;
	u_short flags_fo;
	u_char ttl;
	u_char proto;
	u_short crc;
	ip_address saddr;
	ip_address daddr;
	u_int op_pad;
}ip_header;

/* ICMP Header */
typedef struct icmp_header {
	BYTE type;
	BYTE code;
	u_short crc;
	u_int op_pad;
}icmp_header;

/* TCP Header */
typedef struct tcp_header {
	u_short sprt;
	u_short dprt;
	u_int seq;
	u_int ack;
	BYTE data_offset_reserved;
	BYTE flags;
	u_short window;
	u_short crc;
	u_short urg_ptr;
	u_int op_pad;
}tcp_header;

/* UDP Header */
typedef struct udp_header{
	u_short sprt;
	u_short dprt;
	u_short len;
	u_short crc;
}udp_header;

typedef struct frame{
	ip_header iphdr;
	tcp_header tcphdr;
	udp_header udphdr;
	u_short src_port;
	u_short dst_port;
	frame* prev_frame;
	BYTE issue_flags; //Defining a byte to store our issue flags
}frame;


