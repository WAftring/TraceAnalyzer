// TraceAnalyzer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <winsock.h>
#include <iostream>
#include <string>
#include <Shlwapi.h>
#include "ParserFlags.h"
#include "Logger.h"
#include "NetStructs.h"
#include "ConversationMgr.h"
#include "Misc.h"

#define LINE_LEN 16
#define EDITCAP_PATH "C:\\Program Files\\WireShark\\editcap.exe"

UINT packet_counter = 0;
UINT current_parsed = 0;
VOID packet_handler(u_char*, const struct pcap_pkthdr *, const u_char*);
BOOL ConvertToPCAP(const std::string FileName, std::string &ConvertedBuff);
BOOL ParseArgs(int argc, char* argv[]);
BOOL ParseArgs(int argc, char* argv[])
{
	if (!PathFileExistsA(argv[1]))
	{
		printf("Cannot find specified file %s\n", argv[1]);
		return FALSE;
	}
	for(int i = 0; i < argc; i++)
	{
		if(i > 1)
		{
			if(strcmp(argv[i], "-t") == 0)
				g_L4Flags = PARSE_TCP;
			else if(!strcmp(argv[i], "-u") == 0)
				g_L4Flags = PARSE_UDP;
			else
				return FALSE;
		}
	}
	
	return TRUE;
	
}
int main(int argc, char* argv[])
{
	// I need to figure out how to handle flags
	BOOL ReadIn = TRUE;
	char ActionBuff;
	BOOL bConvertFile = FALSE;
	std::string ConvertedFile;
	pcap_t* pFrame;
	const u_char* packet;
	struct pcap_pkthdr header;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	std::string Filename;
	
 	if(!LoadNpDlls())
	{
		printf("Failed to load the required DLL's\n");
		exit(1);
	}
	if(argc < 3)
	{
		printf("Not enough arguments\n");
		printf("\nUSAGE:\n");
		printf("\tTraceAnalyzer.exe [filename]\t\tReviews the input pcap/pcapng for any common issues\n");
		printf("\t\t\t -t\tParse TCP packets\n");
		printf("\t\t\t -u\tParse UDP packets\n");
		//I should add a flag for out report location
		exit(1);
	}

	if (!ParseArgs(argc, argv))
	{
		printf("Invalid command arguments\n");
		exit(1);
	}
	
	printf("Starting conversion of %s\n", argv[1]);
	if (!InitLogger(argv[1]))
	{
		printf("Failed to setup analysis\n");
		exit(1);
	}
	// Sometimes, we will see issues with pcapng files so I will need to add
	// some logic to convert the pcapng to a pcap
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
		printf("Unable to open the %s\n", source);
		printf("Reason %s\n", errbuf);
		//Function to convert to PCAPNG returns bool about whether to continue or not
		printf("Would you like to convert to pcap and try again? (y/n) ");
		while (ReadIn)
		{
			ActionBuff = getchar();
			switch (ActionBuff)
			{
			case 'y':
				ReadIn = FALSE;
				bConvertFile = TRUE;
				break;
			case 'n':
				ReadIn = FALSE;
			case '\n':
				break;
			default:
				printf("\nInvalid character please try again");
				break;
			}
		}
		if (bConvertFile)
		{
			bConvertFile = ConvertToPCAP(argv[1], ConvertedFile);
			//bConvertFile = FALSE;
		}
		if (!bConvertFile)
		{
			exit(1);
		}
		else
		{

			if (pcap_createsrcstr(source,
									PCAP_SRC_FILE,
				NULL,
				NULL,
				ConvertedFile.c_str(),
				errbuf) != 0)
			{
				printf("Error creating source string\n");
				exit(1);
			}
			if ((pFrame = pcap_open(source, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
			{
				printf("Failed to open the converted file\n");
				if (!DeleteFileA(ConvertedFile.c_str()))
				{
					printf("Failed to clean up file. Please delete %s\n", ConvertedFile);
				}
				exit(1);
			}
		}
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
		printf("Reason %s\n", errbuf);
		exit(1);
	}
	printf("Parsing %d packets\n", packet_counter);
	pcap_loop(pFrame, 0, packet_handler, NULL);
	pcap_close(pFrame);
	printf("\n");
	//fflush(stdout);
	printf("Completed conversion\n");
	return 0;
}

void packet_handler(u_char* temp1, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	/* I need to think of a way to manage the structures of conversations */
	struct tm ltime;
	char timebuf[64], timestr[64];
	ethernet_header *pEthHeader;
	ip_header *pIPHeader;
	u_int ip_len;
	time_t local_tv_sec, local_tv_usec;
	
	int i = 0;
	//(VOID)temp1;
	
	
	/* Lets convert the stamp of the packet into something useful */	
	local_tv_sec = header->ts.tv_sec;
	local_tv_usec = header->ts.tv_usec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timebuf, sizeof timestr, "%H:%M:%S", &ltime);
	snprintf(timestr, sizeof timestr, "%s.%06ld", timebuf, local_tv_usec);
	
	
	pEthHeader = (ethernet_header *)(pkt_data);
	/* Ignoring non-IPv4 for now*/
	if((int)pEthHeader->type == 0x08)
	{
		pIPHeader = (ip_header *) (pkt_data + 14);
		if(pIPHeader->proto == g_L4Flags)
		{
			ip_len = (pIPHeader->ver_ihl & 0xf) * 4;
			CheckPacket(timestr, pIPHeader, ip_len);
		}
	}
	current_parsed++;
	printf("In progress: %9.2f %%\r", (float)(((float)current_parsed / (float)packet_counter) * 100));

}

BOOL ConvertToPCAP(const std::string Filename, std::string &ConvertedFile)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	char* TempPath;
	std::string OutPath;
	std::string args;
	size_t requiredSize;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	getenv_s(&requiredSize, NULL, 0, "TEMP");
	if (requiredSize == 0)
	{
		printf("Couldn't find env variable\n");
		return FALSE;
	}
	TempPath = (char*)malloc(requiredSize * sizeof(char));
	getenv_s(&requiredSize, TempPath, requiredSize, "TEMP");
	OutPath = (std::string)TempPath + "\\temp.pcap";
	//strcat_s(OutPath, MAX_PATH, "\\temp.pcap");
	args = "\"C:\\Program Files\\WireShark\\editcap.exe\" -F pcap " + Filename + " " + OutPath;
	//sprintf_s(args, MAX_PATH, "\"C:\\Program Files\\WireShark\\editcap.exe\" -F pcap %s %s", Filename, OutPath);
	//std::cout << args << std::endl;
	//printf("Args string %s\n", args);
	if (!CreateProcessA(NULL,
						(LPSTR)args.c_str(),
						NULL,
						NULL,
						FALSE,
						0,
						NULL,
						NULL,
						&si,
						&pi))
	{
		printf("Failed to convert %s to pcap\n", Filename);
		printf("Failed with Error %lu\n", GetLastError());
		return FALSE;
	}
	if (GetLastError() != 0)
	{
		printf("Ran into error %d\n", GetLastError());
		return FALSE;
	}
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	ConvertedFile = OutPath;
	//strcpy_s(&ConvertedFile, MAX_PATH, OutPath);
	return TRUE;
}


