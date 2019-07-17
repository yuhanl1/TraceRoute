#pragma once

#include <string>
#include <vector>
#include <pcap.h>

#pragma pack(push)
#pragma pack(1)

using namespace std;

namespace network
{
	//帧头结构
	struct EthernetHead
	{
		u_char m_cDestMac[6];
		u_char m_cSourceMac[6];
		u_short m_sType;
	};

	//ip地址结构
	struct IPAddress{
		u_char m_cByte1;
		u_char m_cByte2;
		u_char m_cByte3;
		u_char m_cByte4;
	};

	//ip头结构
	struct IPHeader
	{ 
		unsigned char m_version_len;
		unsigned char m_type;
		unsigned short m_total_len;
		unsigned short m_identifier;
		unsigned short m_frag_and_flags;
		unsigned char m_ttl;
		unsigned char m_protocol;
		unsigned short m_checksum;

		unsigned long m_sourceIP;
		unsigned long m_destIP;

	};

	//ICMP数据报头 
	struct ICMPHeader
	{ 
		unsigned char m_type;
		unsigned char m_code;
		unsigned short m_checksum;
		unsigned short m_id;
		unsigned short m_seq;
	};

	//icmp包
	struct ICMPPacket
	{
		EthernetHead m_eth;
		IPHeader m_iph;
		ICMPHeader m_icmph;

	};
	//网络适配器设备
	struct NicDevice
	{
		pcap_if_t* m_pPcapIf;
		string m_strDeviceName;
		string m_strDeviceDescription;
		u_long m_lIPAddress;
		u_long m_lSubnetMask;
		u_long m_lGateway;
		u_char m_cMacAddress[6];
		u_char m_cGatewayMacAddress[6];
	};
	typedef vector<NicDevice*> NicDeviceVector;

	//将长整形数据转换为格式化的字符串地址形式
	char* IPLongToAddress(u_long lIP);
	//格式化的字符串地址转换为字符数组形式
	unsigned char* IPAddressToChar(char* pIP);
	//Mac字符数组转换为格式化的字符串地址
	char* MacCharToAddress(unsigned char* pMac);
	//char* ProtocolCharToName(u_char cProtocol);
	//计算校验和
	unsigned short CheckSum(unsigned short *szBUF,int iSize);
}

#pragma pack(pop)