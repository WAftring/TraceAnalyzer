#include "ConversationMgr.h"
#include <cstdlib>
#include "Logger.h"
#pragma warning(disable : 4996)
std::vector<frame*> g_vFrames;

BOOL CompareIPAddr(ip_address ip1, ip_address ip2);
BOOL CheckConversation(frame *currentFrame, frame *tempFrame, int match, int count); // Maybe I should overload this so I don't need to have to deal with a return from CheckPacket
char* FrameToStr(frame *conversionFrame);

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
		case 17:
			ProtoStr = "UDP";
		default:
			ProtoStr = "UNKNOWN";
	}
	
	return ProtoStr;
	
}
char* FrameToStr(frame *conversionFrame)
{
	
	//Convert the frame to a string with the following structure
	// PROTOCOLS Src_IP.Src_Port -> Dst_IP.Dst_Port
	LPCSTR ProtoStr;
	LPSTR pRetBuff = NULL;
	ProtoStr = ProtocolToString(conversionFrame->iphdr->proto);
	if (sprintf(pRetBuff, "%s\t%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d", ProtoStr,
		conversionFrame->iphdr->saddr.oct1,
		conversionFrame->iphdr->saddr.oct2,
		conversionFrame->iphdr->saddr.oct3,
		conversionFrame->iphdr->saddr.oct4,
		conversionFrame->src_port,
		conversionFrame->iphdr->daddr.oct1,
		conversionFrame->iphdr->daddr.oct2,
		conversionFrame->iphdr->daddr.oct3,
		conversionFrame->iphdr->daddr.oct4,
		conversionFrame->dst_port))
	{
		printf("Failed write to the ret buffer\n");
	}
	return pRetBuff;
	
	
}
BOOL CheckConversation(frame *currentFrame, frame *tempFrame, int match, int count)
{
	LPSTR ContentHeader;
	LPSTR ContentPayload = NULL;
	if (match == 3)
	{
		return TRUE;
	}
	if (count == 3)
	{
		return FALSE;
	}
	//General
	if(abs(currentFrame->iphdr->ttl - tempFrame->iphdr->ttl) >= 30)
	{
		//We have a TTL manipulation!
		//Write this to a log somewhere
		//I should have a flag system for the convesations to see if we already have hit one of these flags
		ContentHeader = FrameToStr(tempFrame);
		sprintf(ContentPayload, "%s TTL manipulation found.\nQuestions:\nAre we communicating with a UNIX device?\nWhat does our traffic route look like?", ContentHeader);
		WriteToReport(ContentPayload, LogType::WARN);

		
	}
	if(currentFrame->iphdr->proto == 6)
	{
		// Do our TCP RFL checks
		// WARN
		// SYN Retransmits we need to try 4 times
		if ((currentFrame->tcphdr->flags & SYN) == SYN)
		{

			if ((tempFrame->tcphdr->flags & (SYN | ACK)) != (SYN | ACK))
			{
				//We match the behavior of breaking the expected behavior
				match++;
				count++;
				if (CheckConversation(currentFrame->prev_frame, currentFrame, match, count))
				{
					ContentHeader = FrameToStr(tempFrame);
					sprintf(ContentPayload, "%s TCP SYN Retransmission found.\nQuestions\nDo we see the packet arrive on the destination?\nDo we have a TCP listener on the destination port?", ContentHeader);
					WriteToReport(ContentPayload, LogType::WARN);
					return TRUE;
				}
			}
		}
		// TCP Retransmits
		if (currentFrame->tcphdr->seq == tempFrame->tcphdr->seq)
		{
			//I might need more robust logic for this...
			match++;
			count++;
			if (CheckConversation(currentFrame->prev_frame, tempFrame, match, count))
			{
				ContentHeader = FrameToStr(tempFrame);
				sprintf(ContentPayload, "%s TCP Retransmission found.\n");
				return TRUE;
			}
		}
		//TCP Zero Window
		// INFO
		// RST
		// MSS
		// RTT
		
	}
	else if(currentFrame->iphdr->proto == 17)
	{
		// Do our UDP RFL checks
		// I'm gonna need to think about this a bit more...
		
	}
	
	return FALSE;
	
}

void CheckPacket(char timestr[16], ip_header *iphdr, u_int ip_len) //This function needs a rework to keep the memory valid
{
	BOOL bAdded = FALSE;
	u_short src_port, dst_port;
	icmp_header *pICMPHeader;
	tcp_header* pTCPHeader = new tcp_header();
	udp_header* pUDPHeader = new udp_header();
	frame *tempFrame = new frame();
	
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

	tempFrame->iphdr = iphdr;
	tempFrame->tcphdr = pTCPHeader;
	tempFrame->udphdr = pUDPHeader;
	tempFrame->src_port = src_port;
	tempFrame->dst_port = dst_port;
	tempFrame->prev_frame = NULL;
	//TODO: I need better variable naming
	
	if (g_vFrames.size() == 0) // This might be redundant now
	{
		g_vFrames.push_back(tempFrame);
	}
	//I need to think about how to handle source dest IP combo
	//For example A1:B2 should go into the same frame list as B2:A1 but not B1:A2
	// This is going to have awful Big O notation...
	else
	{
		for (int i = 0; i < g_vFrames.size(); i++)
		{
			frame *currentFrame = g_vFrames.at(i);
			//frame currentFrame = currentConvo[-1];
			//Broadest down to most specific
			if (currentFrame->iphdr->proto == iphdr->proto)
			{
				//Starting with matching IP addresses
				if ((CompareIPAddr(currentFrame->iphdr->saddr, iphdr->saddr) && CompareIPAddr(currentFrame->iphdr->daddr, iphdr->daddr)) //Compare if source == source and dst == dst
					|| (CompareIPAddr(currentFrame->iphdr->daddr, iphdr->saddr) && CompareIPAddr(currentFrame->iphdr->saddr, iphdr->daddr))) //Compare if source == dst and dst == soruce
				{
					//Next we need to check our ports
					if ((currentFrame->src_port == src_port && currentFrame->dst_port == dst_port)
						|| (currentFrame->dst_port == src_port && currentFrame->src_port == dst_port))
					{
						//I should just check against last frame for now but w/e
						CheckConversation(currentFrame, tempFrame,0,0);
						tempFrame->prev_frame = currentFrame;
						//currentConvo.push_back(tempFrame);
						g_vFrames[i] = tempFrame;
						bAdded = TRUE;
					}
				}
			}
			if (!bAdded)
			{
				g_vFrames.push_back(tempFrame);
			}
		}
	}
	
}