#include "StdAfx.h"
#include <pcap.h>
#include <Packet32.h>
#include <map>

#include "NicDevice.h"

CNicDevice::CNicDevice()
{
	this->InitAllDevices();
}

void CNicDevice::InitAllDevices()
{
	this->Destory();

    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE];
    map<string, pcap_if*> pDeviceMap;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        ::AfxMessageBox(errbuf);
        ::exit(1);
    }

    for (d = alldevs; d != NULL; d = d->next)
        pDeviceMap[string(d->name)] = d;

    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;

    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

    if (::GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        ::free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen); 
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        while (pAdapter) {
            NicDevice* pNicDevice = (NicDevice*)calloc(1,sizeof(NicDevice));

			pNicDevice->m_strDeviceName = string("\\Device\\NPF_");
			pNicDevice->m_strDeviceName.append(pAdapter->AdapterName);
			pNicDevice->m_pPcapIf = pDeviceMap[pNicDevice->m_strDeviceName];
			pNicDevice->m_strDeviceDescription = string(pAdapter->Description);
			::memcpy(pNicDevice->m_cMacAddress, pAdapter->Address, 6);
			pNicDevice->m_lIPAddress = ::inet_addr(pAdapter->IpAddressList.IpAddress.String);
			pNicDevice->m_lSubnetMask = ::inet_addr(pAdapter->IpAddressList.IpMask.String);
			pNicDevice->m_lGateway = ::inet_addr(pAdapter->GatewayList.IpAddress.String);
            if (pNicDevice->m_lGateway != 0)
            {
                ULONG ulLen = 6;
                ::SendARP(pNicDevice->m_lGateway, 0, pNicDevice->m_cGatewayMacAddress, &ulLen);
            }
            pAdapter = pAdapter->Next;
			this->m_pNicDeviceVector.push_back(pNicDevice);
        }
    }
	pDeviceMap.clear();
}


void CNicDevice::GetMacAddr(NicDevice* pNicDevice) const
{
	LPADAPTER lpAdapter = ::PacketOpenAdapter((PCHAR)pNicDevice->m_strDeviceName.c_str());//#include <Packet32.h>

    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
    {
        return ;
    }

    PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)::malloc(6 + sizeof(PACKET_OID_DATA));
    if (OidData == NULL)
    {
        ::PacketCloseAdapter(lpAdapter);
        return ;
    }

    OidData->Oid = OID_802_3_CURRENT_ADDRESS;
    OidData->Length = 6;
    ::memset(OidData->Data, 0, 6);
    BOOLEAN Status = ::PacketRequest(lpAdapter, FALSE, OidData);
    if(Status)
    {
		::memcpy(&pNicDevice->m_cMacAddress, (u_char*)(OidData->Data), 6);
    }

    ::free(OidData);
    ::PacketCloseAdapter(lpAdapter);
}

string CNicDevice::GetMacAddr(int index) const
{
	return string(MacCharToAddress(GetDevice(index)->m_cMacAddress));
}

string CNicDevice::GetIPAddr(int index) const
{
	return string(IPLongToAddress(GetDevice(index)->m_lIPAddress));
}

NicDevice* CNicDevice::GetDevice(int index) const
{
    if (index >= 0 && index < (int)this->m_pNicDeviceVector.size())
        return this->m_pNicDeviceVector[index];
    return NULL;
}

size_t CNicDevice::Size(void)
{
    return this->m_pNicDeviceVector.size();
}

string CNicDevice::GetSubnetMask(int index) const
{
	return string(IPLongToAddress(GetDevice(index)->m_lSubnetMask));
}

string CNicDevice::GetDefaultGw(int index) const
{
	return string(IPLongToAddress(GetDevice(index)->m_lGateway));
}

string CNicDevice::GetGwMacAddr(int index) const
{
	return string(MacCharToAddress(GetDevice(index)->m_cGatewayMacAddress));

}

void CNicDevice::Destory()
{
	NicDeviceVector::iterator itNicDeviceVector = this->m_pNicDeviceVector.begin();
	while(itNicDeviceVector!=this->m_pNicDeviceVector.end())
	{
		free(*itNicDeviceVector);
		itNicDeviceVector++;
	}
	this->m_pNicDeviceVector.clear();
}

CNicDevice::~CNicDevice()
{
	this->Destory();
}