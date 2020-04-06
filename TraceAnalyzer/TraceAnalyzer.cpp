// TraceAnalyzer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <winsock.h>
#include <string>
#include <Shlwapi.h>
#include "Logger.h"
#include "NetStructs.h"
#include "ConversationMgr.h"
#include "Misc.h"


#pragma warning(disable : 4996)
#define LINE_LEN 16

UINT packet_counter = 0;
UINT current_parsed = 0;
VOID packet_handler(u_char*, const struct pcap_pkthdr *, const u_char*);
BOOL ParseArgs(int argc, char* argv[]);
BOOL ParseArgs(int argc, char* argv[])
{
	// For future args implementations
	//for (int i = 0; i < argc; i++)
	//{
	//	
	//}
	return FALSE;
}
int main(int argc, char* argv[])
{
	// I need to figure out how to handle flags
	pcap_t* pFrame;
	const u_char* packet;
	struct pcap_pkthdr header;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	char Filename[MAX_PATH];
	
 	if(!LoadNpDlls())
	{
		printf("Failed to load the required DLL's\n");
		exit(1);
	}
	if(argc < 2 && !PathFileExistsA(argv[1]))
	{
		printf("\nUSAGE:\n");
		printf("\tTraceAnalyzer.exe [filename]\t\tReviews the input pcap/pcapng for any common issues.\n");
		//I should add a flag for out report location
		exit(1);
	}
	/*if (ParseArgs(argc, argv))
	{

	}*/
	printf("Starting conversion of %s\n", argv[1]);
	if (!InitLogger(argv[1]))
	{
		printf("Failed to setup analysis\n");
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
	
	if(( pFrame = pcap_open(source, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000,	NULL, errbuf)) == NULL)
	{
		printf("Unable to open the file %s\n", source);
		exit(1);
	}
	//From what I have seen this is the only way to get the number of packets...
	while (packet = pcap_next(pFrame, &header))
	{
		packet_counter++;
	}
	pcap_close(pFrame);
	if ((pFrame = pcap_open(source, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		printf("Unable to open the file %s\n", source);
		exit(1);
	}
	printf("Parsing %d packets\n", packet_counter);
	pcap_loop(pFrame, 0, packet_handler, NULL);
	printf("\n");
	fflush(stdout);
	printf("Completed conversion\n");
	return 0;
}

void packet_handler(u_char* temp1, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	/* I need to think of a way to manage the structures of conversations */
	struct tm ltime;
	char timestr[16];
	ethernet_header *pEthHeader;
	ip_header *pIPHeader;
	u_int ip_len;
	time_t local_tv_sec;
	
	int i = 0;
	//(VOID)temp1;
	
	
	/* Lets convert the stamp of the packet into something useful */	
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
	
	
	pEthHeader = (ethernet_header *)(pkt_data);
	/* Ignoring non-IPv4 for now*/
	if((int)pEthHeader->type == 0x08)
	{
		pIPHeader = (ip_header *) (pkt_data + 14);
		ip_len = (pIPHeader->ver_ihl & 0xf) * 4;
		CheckPacket(timestr, pIPHeader, ip_len);
	}
	current_parsed++;
	printf("In progress: %9.2f %%\r", (float)(((float)current_parsed / (float)packet_counter) * 100));

}


