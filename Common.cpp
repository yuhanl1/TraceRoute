#include "stdafx.h"
#include "Common.h"

#define MAX_IP_ADDRESS_NUMB 8
//#define MAX_PROTOCOL_NUMB 11
using namespace network;

//protocol protocols[] = 
//{  
//	{IPPROTO_IP  , "IP"},
//	{IPPROTO_ICMP, "ICMP"},  
//	{IPPROTO_IGMP, "IGMP"}, 
//	{IPPROTO_GGP , "GGP"},  
//	{IPPROTO_TCP , "TCP"},  
//	{IPPROTO_PUP , "PUP"},  
//	{IPPROTO_UDP , "UDP"},  
//	{IPPROTO_IDP , "IDP"},  
//	{IPPROTO_ND  , "NP" },  
//	{IPPROTO_RAW , "RAW"},  
//	{IPPROTO_MAX , "MAX"}
//};

char* network::IPLongToAddress(u_long lIP)
{   

	static char cIP[MAX_IP_ADDRESS_NUMB][3*4+3+1];
	static short IPCount;
	u_char *p;

	p = (u_char *)&lIP;
	IPCount = (IPCount + 1 == MAX_IP_ADDRESS_NUMB ? 0 : IPCount + 1);
	sprintf_s(cIP[IPCount], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return cIP[IPCount];
}

unsigned char* network::IPAddressToChar(char* Fchar)
{
	char* ip_str = Fchar;
	char ip_num_str[4][4];
	unsigned char ip_num[4];

	int len = strlen(ip_str);
	int pos1 = 0, pos2 = 0;
	int index = 0;
	while (pos2 <= len) 
	{
		while (ip_str[pos2] != '.' && pos2 < len)	pos2++;
		memcpy(ip_num_str[index], &ip_str[pos1], pos2-pos1);
		ip_num_str[index][pos2-pos1] = '\0';
		index++;
		pos1 = pos2 + 1;
		pos2 += 2;
	}

	long ip = 0;
	for (int i = 0; i < 4; i++)
	{
		ip_num[i] = (unsigned char)atoi(ip_num_str[i]);
		ip = ip | ip_num[i];
		if (i < 3)	ip = ip << 8;
	}
	unsigned char* x = ip_num;
	return ip_num;

}

char* network::MacCharToAddress(unsigned char* chMAC)
{							
	static unsigned char uMac[18];
	for(int i=0; i < 17; i++)
	{
		if ((i+1) % 3)
		{
			if (!(i % 3))
			{
				if ((chMAC[i/3] >> 4) < 0x0A)
				{
					uMac[i] = (chMAC[i/3] >> 4) + 48;
				}
				else
				{
					uMac[i] = (chMAC[i/3] >> 4) + 55;
				}
				if ((chMAC[i/3] & 0x0F) < 0x0A)
				{
					uMac[i+1] = (chMAC[i/3] & 0x0F) + 48;
				}
				else
				{
					uMac[i+1] = (chMAC[i/3] & 0x0F) + 55;
				}
			}
		}
		else
		{
			uMac[i] = '-';
		}
	}
	uMac[17] = '\0';
	return (char*)uMac;
}

//char* network::ProtocolCharToName(u_char cProtocol)
//{
//	static char* pUnknownProtocol = "Unknown";
//
//	int i = 0;
//	for( ; i < MAX_PROTOCOL_NUMB; i++)
//	{
//		if (protocols[i].type == cProtocol)
//			return protocols[i].name;
//	}
//	return pUnknownProtocol;
//}

unsigned short network::CheckSum(unsigned short *szBUF,int iSize)
{   
	unsigned long ckSum=0;
	for(;iSize>1;iSize-=sizeof(unsigned short))
		ckSum+=*szBUF++;
	if(iSize==1)
		ckSum+=*(unsigned char *)szBUF;
	ckSum=(ckSum>>16)+(ckSum&0xffff);
	ckSum+=(ckSum>>16);
	return(unsigned short )(~ckSum);
}
