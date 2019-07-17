#pragma once
#include "Common.h"       //存放ARP包结构

using namespace network;
class CNicDevice
{
public:
	CNicDevice();
	void InitAllDevices();
	NicDevice* GetDevice(int index) const;
	string GetIPAddr(int index) const;
	string GetMacAddr(int index) const;
	string GetSubnetMask(int index) const;
	string GetDefaultGw(int index) const;
	string GetGwMacAddr(int index) const;
	size_t Size(void);
	void Destory();
	~CNicDevice();

protected:
	void GetMacAddr(NicDevice* device) const;

private:
	NicDeviceVector m_pNicDeviceVector;

};