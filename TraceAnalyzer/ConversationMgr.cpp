#include "ConversationMgr.h"
#include <cstdlib>
#include <string>
#include "Logger.h"

std::vector<frame*> g_vFrames;
char g_timestr[64];
BOOL CompareIPAddr(ip_address ip1, ip_address ip2);
BOOL CheckConversation(frame *currentFrame, frame *tempFrame, int match, int count); // Maybe I should overload this so I don't need to have to deal with a return from CheckPacket
std::string FrameToStr(frame *conversionFrame);

BOOL CompareIPAddr(ip_address ip1, ip_address ip2)
{
	if(ip1.oct1 == ip2.oct1 &&
		ip1.oct2 == ip2.oct2 &&
		ip1.oct3 == ip2.oct3 &&
		ip1.oct4 == ip2.oct4)
		return TRUE;
	return FALSE;
}
const char* ProtocolToString(BYTE proto)
{
	const char *ProtoStr;
	switch(proto)
	{
		case 6:
			ProtoStr = "TCP";
			break;
		case 17:
			ProtoStr = "UDP";
			break;
		default:
			ProtoStr = "UNKNOWN";
			break;
	}
	
	return ProtoStr;
	
}
std::string FrameToStr(frame *conversionFrame)
{
	
	//Convert the frame to a string with the following structure
	// PROTOCOLS Src_IP.Src_Port -> Dst_IP.Dst_Port
	LPCSTR ProtoStr;
	char pRetBuff[MAX_PATH];
	int Result = 0;
	ProtoStr = ProtocolToString(conversionFrame->iphdr.proto);
	Result = sprintf_s(pRetBuff, MAX_PATH, "%s\t%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d", ProtoStr,
		conversionFrame->iphdr.saddr.oct1,
		conversionFrame->iphdr.saddr.oct2,
		conversionFrame->iphdr.saddr.oct3,
		conversionFrame->iphdr.saddr.oct4,
		conversionFrame->src_port,
		conversionFrame->iphdr.daddr.oct1,
		conversionFrame->iphdr.daddr.oct2,
		conversionFrame->iphdr.daddr.oct3,
		conversionFrame->iphdr.daddr.oct4,
		conversionFrame->dst_port);
	if(Result <= 0)
	{
		printf("Failed write to the ret buffer\n");
		strcpy_s(pRetBuff, MAX_PATH, "Unable to write string\n");
	}

	return pRetBuff;
	
	
}
BOOL CheckConversation(frame *currentFrame, frame *tempFrame, int match, int count)
{
	std::string ContentHeader;
	char ContentPayload[MAX_PATH];
	if (match == 2)
	{
		return TRUE;
	}
	if (count == 2)
	{
		return FALSE;
	}
	if (currentFrame == NULL)
	{
		return FALSE;
	}

	//IP Layer
	if((tempFrame->issue_flags & IPv4_TTL_MANIPULATION) != IPv4_TTL_MANIPULATION && (currentFrame->issue_flags & IPv4_TTL_MANIPULATION) != IPv4_TTL_MANIPULATION)
	{
		if(abs(currentFrame->iphdr.ttl - tempFrame->iphdr.ttl) >= 30)
		{
			//We have a TTL manipulation!
			//Write this to a log somewhere
			//I should have a flag system for the convesations to see if we already have hit one of these flags
			ContentHeader = FrameToStr(tempFrame);
			sprintf_s(ContentPayload, MAX_PATH, "%s TTL manipulation found.\nQuestions:\nAre we communicating with a UNIX device?\nWhat does our traffic route look like?\n", ContentHeader.c_str());
			WriteToReport(g_timestr, ContentPayload, LogType::WARN);
			currentFrame->issue_flags |= IPv4_TTL_MANIPULATION;
		}
	}
	
	//Working with TCP
	if(currentFrame->iphdr.proto == 6)
	{
		// Do our TCP RFL checks
		// WARN
		// SYN Retransmits we need to try 2 times
		if((tempFrame->issue_flags & TCP_SYNRT) != TCP_SYNRT && (currentFrame->issue_flags & TCP_SYNRT) != TCP_SYNRT)
		{
			if ((currentFrame->tcphdr.flags & SYN) == SYN)
			{

				if ((tempFrame->tcphdr.flags & (SYN & ACK)) != (SYN & ACK))
				{
					//We match the behavior of breaking the expected behavior
					match++;
					count++;
					if (CheckConversation(currentFrame->prev_frame, currentFrame, match, count))
					{
						ContentHeader = FrameToStr(tempFrame);
						sprintf_s(ContentPayload, MAX_PATH, "%s TCP SYN Retransmission found.\nQuestions\nDo we see the packet arrive on the destination?\nDo we have a TCP listener on the destination port?\n", ContentHeader.c_str());
						WriteToReport(g_timestr, ContentPayload, LogType::WARN);
						//I need to set the flag for TCP_SYNRT
						currentFrame->issue_flags |= TCP_SYNRT;
						return FALSE;
					}
					match = 0;
					count = 0;
				}
			}
		}
		// TCP Retransmits
		if((tempFrame->issue_flags & TCP_RT) != TCP_RT && (currentFrame->issue_flags & TCP_RT) != TCP_RT)
		{
			if (currentFrame->tcphdr.seq == tempFrame->tcphdr.seq && (tempFrame->tcphdr.flags & SYN) != SYN)
			{
				//I might need more robust logic for this...
				match++;
				count++;
				if (CheckConversation(currentFrame->prev_frame, tempFrame, match, count))
				{
					ContentHeader = FrameToStr(tempFrame);
					sprintf_s(ContentPayload, MAX_PATH, "%s TCP Retransmission found.\n",ContentHeader);
					WriteToReport(g_timestr, ContentPayload, LogType::WARN);
					currentFrame->issue_flags |= TCP_RT;
					return TRUE;
				}
				match = 0;
				count = 0;
			}
		}
		//TCP Zero Window
		if ((currentFrame->issue_flags & TCP_ZERO_WINDOW) != TCP_ZERO_WINDOW)
		{
			if (tempFrame->tcphdr.window == 0 && (tempFrame->tcphdr.flags & ACK) == ACK)
			{
				ContentHeader = FrameToStr(tempFrame);
				sprintf_s(ContentPayload, MAX_PATH, "%s TCP Zero Window found\n", ContentHeader);
				WriteToReport(g_timestr, ContentPayload, LogType::INFO);
				currentFrame->issue_flags |= TCP_ZERO_WINDOW;
			}
		}
		// INFO
		// RST
		if ((currentFrame->issue_flags & TCP_RST) != TCP_RST)
		{
			if (((tempFrame->tcphdr.flags & RST) == RST || (currentFrame->tcphdr.flags & (RST)) == RST) && (currentFrame->tcphdr.flags & FIN) != FIN)
			{
				ContentHeader = FrameToStr(tempFrame);
				sprintf_s(ContentPayload, MAX_PATH, "%s TCP RST found.\n", ContentHeader);
				WriteToReport(g_timestr, ContentPayload, LogType::INFO);
				currentFrame->issue_flags |= TCP_RST;
			}
		}
		// MSS
		// RTT
		
	}
	else if(currentFrame->iphdr.proto == 17)
	{
		// Do our UDP RFL checks
		// I'm gonna need to think about this a bit more...
		
	}
	
	return FALSE;
	
}

void CheckPacket(char timestr[64], ip_header *iphdr, u_int ip_len) //This function needs a rework to keep the memory valid
{
	BOOL bAdded = FALSE;
	u_short src_port, dst_port;
	icmp_header *pICMPHeader;
	tcp_header* pTCPHeader = new tcp_header();
	udp_header* pUDPHeader = new udp_header();
	frame *tempFrame = new frame();
	
	strcpy_s(g_timestr, 64, timestr);
	switch(iphdr->proto)
	{
		case 1:
			pICMPHeader = (icmp_header *)((BYTE *)iphdr + ip_len);
			src_port = 0;
			dst_port = 0;
			break;
		case 6:
			pTCPHeader = (tcp_header *)((u_char *)iphdr + ip_len);
			src_port = ntohs(pTCPHeader->sprt);
			dst_port = ntohs(pTCPHeader->dprt);
			break;
		case 17:
			pUDPHeader = (udp_header *)((u_char *)iphdr + ip_len);
			src_port = ntohs(pUDPHeader->sprt);
			dst_port = ntohs(pUDPHeader->dprt);
			break;
		default:
			src_port = 0;
			dst_port = 0;
			break;
	}

	tempFrame->iphdr = *iphdr;
	tempFrame->tcphdr = *pTCPHeader;
	tempFrame->udphdr = *pUDPHeader;
	tempFrame->src_port = src_port;
	tempFrame->dst_port = dst_port;
	tempFrame->prev_frame = NULL;
	//TODO: I need better variable naming
	//printf("%s", FrameToStr(tempFrame).c_str()); //For debugging info
	if (g_vFrames.size() == 0) // This might be redundant now
	{
		g_vFrames.push_back(tempFrame);
		//printf("Created new convo\n"); //more debug info
	}
	//I need to think about how to handle source dest IP combo
	//For example A1:B2 should go into the same frame list as B2:A1 but not B1:A2
	// This is going to have awful Big O notation...
	else
	{
		for (int i = g_vFrames.size(); i > 0; i--)
		{
			frame* currentFrame = g_vFrames.at(i - 1);
			//frame currentFrame = currentConvo[-1];
			//Broadest down to most specific
			if (currentFrame->iphdr.proto == iphdr->proto)
			{
				//Starting with matching IP addresses
				if ((CompareIPAddr(currentFrame->iphdr.saddr, iphdr->saddr) && CompareIPAddr(currentFrame->iphdr.daddr, iphdr->daddr)) //Compare if source == source and dst == dst
					|| (CompareIPAddr(currentFrame->iphdr.daddr, iphdr->saddr) && CompareIPAddr(currentFrame->iphdr.saddr, iphdr->daddr))) //Compare if source == dst and dst == soruce
				{
					//Next we need to check our ports
					if ((currentFrame->src_port == src_port && currentFrame->dst_port == dst_port)
						|| (currentFrame->dst_port == src_port && currentFrame->src_port == dst_port))
					{
						//I should just check against last frame for now but w/e
						CheckConversation(currentFrame, tempFrame, 0, 0);
						tempFrame->prev_frame = currentFrame;
						tempFrame->issue_flags = currentFrame->issue_flags;
						if ((tempFrame->tcphdr.flags & (RST | FIN)) == (RST | FIN)) //This is wrong
						{
							g_vFrames.pop_back();
						}
						else
						{
							//currentConvo.push_back(tempFrame);
							g_vFrames[i - 1] = tempFrame;
							bAdded = TRUE;
							//printf("Added to existing convo\n"); //more debug info
							break;
						}
					}
				}
			}
		}
		if (!bAdded)
		{
			g_vFrames.push_back(tempFrame);
			//printf("Created new convo\n"); //Debug info
		}
	}
}
	
