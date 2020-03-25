// TraceAnalyzer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <Winsock2.h>
#include "Misc.h"
#define LINE_LEN 16

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

/* TCP Header */
typedef struct tcp_header {
	u_short sprt;
	u_short dprt;
	u_int seq;
	BYTE data_offset;
	BYTE reserved;
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
	

void packet_handler(u_char*, const struct pcap_pkthdr *, const u_char*);

int main(int argc, char* argv[])
{
	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	
	if(!LoadNpDlls())
	{
		printf("Failed to load the required DLL's\n");
		exit(1);
	}
	if(argc < 2)
	{
		printf("usage: %s filename", argv[0]);
		exit(1);
	}
	
	if( pcap_createsrcstr( source,
							PCAP_SRC_FILE,
							NULL,
							NULL,
							argv[1],
							errbuf
							) != 0)
	{
			printf("Error creating source string\n");
			exit(1);
	}
	
	if(( fp = pcap_open(source, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000,	NULL, errbuf)) == NULL)
	{
		printf("Unable to open the file %s\n", source);
		exit(1);
	}
	
	pcap_loop(fp, 0, packet_handler, NULL);
	
	return 0;
}

void packet_handler(u_char* temp1, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm ltime;
	char timestr[16];
	ip_header *pIPHeader;
	udp_header *pUDPHeader;
	tcp_header *pTCPHeader;
	u_int ip_len;
	u_short sprt, dprt;
	time_t local_tv_sec;
	
	int i = 0;
	(VOID)temp1;
	
	
	/* Lets convert the stamp of the packet into something useful */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);
	
	/* Now lets work with the IP header */
	pIPHeader = (ip_header *) (pkt_data + 14);
	ip_len = (pIPHeader->ver_ihl & 0xf) * 4;
	if(pIPHeader->proto == 6)
	{
		pTCPHeader = (tcp_header *)((u_char *)pIPHeader + ip_len);
		sprt = ntohs(pTCPHeader->sprt);
		dprt = ntohs(pTCPHeader->dprt);
	}
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		pIPHeader->daddr.oct1,
		pIPHeader->saddr.oct2,
		pIPHeader->saddr.oct2,
		pIPHeader->saddr.oct3,
		sprt,
		pIPHeader->daddr.oct1,
		pIPHeader->daddr.oct2,
		pIPHeader->daddr.oct3,
		pIPHeader->daddr.oct4,
		dprt);
	printf("\n\n");
}
