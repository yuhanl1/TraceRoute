
//  : ʵ���ļ�
//

#include "stdafx.h"
#include "TraceRoute.h"
#include "TraceRouteDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//�Զ���
#define WM_RECEIVE_ONE_PACKET (WM_USER + 100)

pcap_t* fp;
CNicDevice oNicDevice;
unsigned long lDstIP;
int iIndex = 0;
bool bRecvFlag = FALSE;
bool bFinishFlag = FALSE;
bool bLoseFlag = FALSE;
bool bLosePackFlag = FALSE;
bool bfailFlag = FALSE;
bool bfailtoRecieveFlag = FALSE;
LARGE_INTEGER begin_time;
LARGE_INTEGER end_time;
LONGLONG time_fre;
LONGLONG time_elapsed;
LARGE_INTEGER litmp;
BYTE nf1, nf2, nf3, nf4;
int packcount = 0;
int maxLoop;
//�����̵߳Ļص�����
void packet_handler(u_char *param,const struct pcap_pkthdr *header,const u_char *pkt_data)
{
	char* pBuffer = (char*)calloc(12,sizeof(char));
	QueryPerformanceCounter(&end_time);
	time_elapsed = end_time.QuadPart - begin_time.QuadPart;//����ʱ��
	if (bLoseFlag == true){
		bLosePackFlag = true;
		bLoseFlag = false;
		memcpy(pBuffer, pkt_data + 26, 4);
		memcpy(&pBuffer[4], &time_elapsed, 8);
		PostMessage((HWND)param, WM_RECEIVE_ONE_PACKET, (WPARAM)0, (LPARAM)pBuffer);
		bRecvFlag = true;
	}
	else{
		if (*(pkt_data + 23) == 0x01 && *(pkt_data + 34) == 0x0b && *(pkt_data + 35) == 0x00)//34��35λΪʱ�䳬����������11 ttl=0ʱ���� //23λ��icmp������ֵ
		{
			if (*(pkt_data + 58) == nf1 && *(pkt_data + 59) == nf2&&*(pkt_data + 60) == nf3&&*(pkt_data + 61) == nf4)//��װ��icmp���������ֶε�IP��ͷ���ñ�ͷ�Ƿ��͵�echo�����ip��ͷ������Ŀ�ĵ�ַ���������һ�µġ�
			{
				memcpy(pBuffer, pkt_data + 26, 4);
				memcpy(&pBuffer[4], &time_elapsed, 8);
				PostMessage((HWND)param, WM_RECEIVE_ONE_PACKET, (WPARAM)0, (LPARAM)pBuffer);
				bRecvFlag = true;
			}
		}
		else if (*(pkt_data + 23) == 0x01 && *(pkt_data + 34) == 0x00 && *(pkt_data + 35) == 0x00)//�ش��� ���յ�Ż���
		{
			memcpy(pBuffer, pkt_data + 26, 4);
			memcpy(&pBuffer[4], &time_elapsed, 8);
			PostMessage((HWND)param, WM_RECEIVE_ONE_PACKET, (WPARAM)0, (LPARAM)pBuffer);
			bFinishFlag = true;
		}
		else
		{
			//free(pBuffer);
			packcount++;
			//packcount++;//�յ��Ķ��ǲ���Ҫ�İ����1
		}
		//if (packcount == 50)
		//{
		//	packcount = 0;
		//	bLoseFlag == true;
		//	memcpy(pBuffer, pkt_data + 26, 4);
		//	memcpy(&pBuffer[4], &time_elapsed, 8);
		//	PostMessage((HWND)param, WM_RECEIVE_ONE_PACKET, (WPARAM)0, (LPARAM)pBuffer);
		//	//bRecvFlag = true;
		//}
	}
}

//�����߳�
UINT RecvFucnction(LPVOID pParam)
{
	pcap_loop(fp,0,packet_handler,(u_char*)pParam);
	//for (int i = 0; i < 10; i++){
	//	if (bRecvFlag == false)
	//	{
	//		pcap_loop(fp, 0, packet_handler, (u_char*)pParam);
	//	}
	//}
	//if (bRecvFlag == false)
	//{
	//	bLoseFlag = true;
	//	pcap_loop(fp, 0, packet_handler, (u_char*)pParam);
	//}
	return 0;
}
//�����߳�
UINT SendFucnction(LPVOID pParam)
{
	unsigned char* pMessage = (unsigned char*)calloc(1,sizeof(ICMPPacket)+32);
	ICMPPacket* pICMPPacket = (ICMPPacket*)pMessage;
	pICMPPacket->m_eth.m_cDestMac[0]=oNicDevice.GetDevice(iIndex)->m_cGatewayMacAddress[0];
	pICMPPacket->m_eth.m_cDestMac[1]=oNicDevice.GetDevice(iIndex)->m_cGatewayMacAddress[1];
	pICMPPacket->m_eth.m_cDestMac[2]=oNicDevice.GetDevice(iIndex)->m_cGatewayMacAddress[2];
	pICMPPacket->m_eth.m_cDestMac[3]=oNicDevice.GetDevice(iIndex)->m_cGatewayMacAddress[3];
	pICMPPacket->m_eth.m_cDestMac[4]=oNicDevice.GetDevice(iIndex)->m_cGatewayMacAddress[4];
	pICMPPacket->m_eth.m_cDestMac[5]=oNicDevice.GetDevice(iIndex)->m_cGatewayMacAddress[5];
	pICMPPacket->m_eth.m_cSourceMac[0]=oNicDevice.GetDevice(iIndex)->m_cMacAddress[0];
	pICMPPacket->m_eth.m_cSourceMac[1]=oNicDevice.GetDevice(iIndex)->m_cMacAddress[1];
	pICMPPacket->m_eth.m_cSourceMac[2]=oNicDevice.GetDevice(iIndex)->m_cMacAddress[2];
	pICMPPacket->m_eth.m_cSourceMac[3]=oNicDevice.GetDevice(iIndex)->m_cMacAddress[3];
	pICMPPacket->m_eth.m_cSourceMac[4]=oNicDevice.GetDevice(iIndex)->m_cMacAddress[4];
	pICMPPacket->m_eth.m_cSourceMac[5]=oNicDevice.GetDevice(iIndex)->m_cMacAddress[5];
	pICMPPacket->m_eth.m_sType = htons(0x0800);

	pICMPPacket->m_iph.m_version_len = (4<<4|sizeof(IPHeader)/sizeof(unsigned long));
	pICMPPacket->m_iph.m_type = 0x00;
	//icmp�����ܳ���Ϊ60�ֽڣ�����20�ֽڵ�ͷ+8�ֽ�icmpͷ+32�ֽ���䣩�ܳ��ȷ�Χ46-1500
	pICMPPacket->m_iph.m_total_len = htons(0x3c);
	pICMPPacket->m_iph.m_identifier = htons(0x0000);///////////////////////
	pICMPPacket->m_iph.m_frag_and_flags = htons(0x0000);
	pICMPPacket->m_iph.m_ttl = 0x01;
	pICMPPacket->m_iph.m_protocol = 0x01;
	pICMPPacket->m_iph.m_checksum = htons(0x0000);//////
	pICMPPacket->m_iph.m_sourceIP = oNicDevice.GetDevice(iIndex)->m_lIPAddress;
	pICMPPacket->m_iph.m_destIP = lDstIP;
	
	pICMPPacket->m_icmph.m_type = 0x08;
	pICMPPacket->m_icmph.m_code = 0x00;
	pICMPPacket->m_icmph.m_checksum = 0x0000;//////
	pICMPPacket->m_icmph.m_id = 0x0000;////////
	pICMPPacket->m_icmph.m_seq = 0x0000;/////////
	pICMPPacket->m_icmph.m_checksum = CheckSum((unsigned short*)&pICMPPacket->m_icmph,sizeof(ICMPHeader));
	QueryPerformanceFrequency(&litmp);//���������ʱ��
    time_fre = litmp.QuadPart;
	while(!bFinishFlag)
	{
		if(bRecvFlag && (!bFinishFlag))//�������ٷ� ����һֱ��
		{
			bRecvFlag = FALSE;
			if(pICMPPacket->m_iph.m_ttl<0xff)//ttl��󲻳���ȫ1
			{
				pICMPPacket->m_iph.m_checksum = CheckSum((unsigned short*)&pICMPPacket->m_iph,
					sizeof(IPHeader));
				QueryPerformanceCounter(&begin_time);
				if (pcap_sendpacket(fp, pMessage, 74) != 0)
				{
					return -1;
				}
				pICMPPacket->m_iph.m_ttl++;//ttl ��1��ʼ���μ�1��Ȼ������յ��İ�
				pICMPPacket->m_iph.m_checksum = 0x0000;
				Sleep(5000);
				if (bRecvFlag == false)
				{
					bLoseFlag = true;
				}
			}
		}
		else
			Sleep(1);
	}

	return 0;
}


// CTraceRouteDlg �Ի���




CTraceRouteDlg::CTraceRouteDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CTraceRouteDlg::IDD, pParent)
{
	//m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_hIcon = AfxGetApp()->LoadIcon(IDI_APPLICATION);
	
}

void CTraceRouteDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_IP, m_EditIP);
	DDX_Control(pDX, IDC_BUTTON_START, m_ButtonStart);
	DDX_Control(pDX, IDC_BUTTON_EXIT, m_ButtonExit);
	DDX_Control(pDX, IDC_LIST_ROUTE, m_ListCtrlTrace);
	DDX_Control(pDX, IDC_COMBO_NIC_DEVICE, m_ComboBoxNICDevice);
	DDX_Control(pDX, IDC_IPADDRESS3, m_IPaddressControl);
}

BEGIN_MESSAGE_MAP(CTraceRouteDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_START, &CTraceRouteDlg::OnBnClickedButtonStart)
	ON_BN_CLICKED(IDC_BUTTON_EXIT, &CTraceRouteDlg::OnBnClickedButtonExit)
	ON_MESSAGE(WM_RECEIVE_ONE_PACKET,OnUpdateTrace)//���յ���ʱ�򣬵��ú�������list
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_ROUTE, &CTraceRouteDlg::OnLvnItemchangedListRoute)
	ON_BN_CLICKED(IDC_BUTTON_START2, &CTraceRouteDlg::OnBnClickedButtonStart2)
END_MESSAGE_MAP()


// CTraceRouteDlg ��Ϣ�������

BOOL CTraceRouteDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	WSADATA wsaData;
	WORD wVersionRequested;
	wVersionRequested=MAKEWORD(2,2);
	if(WSAStartup(wVersionRequested,&wsaData)!=0)
		MessageBox(NULL,"error",NULL);
	this->m_ListCtrlTrace.InsertColumn(1,"����",LVCFMT_CENTER,100);
	this->m_ListCtrlTrace.InsertColumn(2,"����ʱ��/����",LVCFMT_CENTER,140);
	this->m_ListCtrlTrace.InsertColumn(3,"�ڵ�IP��ַ",LVCFMT_CENTER,180);
	this->m_ListCtrlTrace.InsertColumn(4, "��ע��Ϣ", LVCFMT_CENTER, 215);
	//this->m_ListCtrlTrace.InsertColumn(4,"RouterName",LVCFMT_CENTER,152);
	for(int i=0;i<int(oNicDevice.Size());i++)
		this->m_ComboBoxNICDevice.AddString(oNicDevice.GetDevice(i)->m_pPcapIf->description);
	this->m_ComboBoxNICDevice.SetCurSel(1);

	this->m_bClickFlag = false;
	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CTraceRouteDlg::OnSysCommand(UINT nID, LPARAM lParam)
{

		CDialogEx::OnSysCommand(nID, lParam);
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CTraceRouteDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CTraceRouteDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CTraceRouteDlg::OnBnClickedButtonStart()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if(!this->m_bClickFlag)
	{
		this->m_bClickFlag = TRUE;
		this->m_EditIP.EnableWindow(FALSE);
		this->m_IPaddressControl.EnableWindow(FALSE);
		this->m_ButtonStart.SetWindowTextA("ֹͣ");
		this->m_ComboBoxNICDevice.EnableWindow(FALSE);
		this->m_ListCtrlTrace.DeleteAllItems();
		char errbuf[1024];
		iIndex = this->m_ComboBoxNICDevice.GetCurSel();
		CString strMaxLoop, strDstIP;
		this->m_EditIP.GetWindowTextA(strMaxLoop);
		maxLoop = _ttoi(strMaxLoop);
		//BYTE nf1, nf2, nf3, nf4;
		this->m_IPaddressControl.GetAddress(nf1, nf2, nf3, nf4);
		strDstIP.Format("%d.%d.%d.%d", nf1, nf2, nf3, nf4);
		lDstIP = *((unsigned long *)network::IPAddressToChar(strDstIP.GetBuffer(strDstIP.GetLength())));//Ŀ��IP��ַ���벢ת�����ַ���
		fp = pcap_open(oNicDevice.GetDevice(iIndex)->m_pPcapIf->name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf);
			struct bpf_program fcode;//���˾��
		if (pcap_compile(fp, &fcode, "ip", 1, ((struct sockaddr_in *)(oNicDevice.GetDevice(iIndex)->m_pPcapIf->addresses->netmask))->sin_addr.S_un.S_addr) <0 )//����
		{
			exit(-1);
		}
		if (pcap_setfilter(fp, &fcode)<0)//����
		{
			exit(-1);
		}
		this->m_pThreadRecv = AfxBeginThread(RecvFucnction,GetSafeHwnd());//���ý����߳�
		this->m_pThreadSend = AfxBeginThread(SendFucnction,GetSafeHwnd());//���÷����߳�
		bLoseFlag = false;
		bLosePackFlag = false;
		bfailFlag = false;
		bfailtoRecieveFlag = false;
		bRecvFlag = true;
	}
	else
	{
		this->m_bClickFlag = FALSE;
		this->m_EditIP.EnableWindow(TRUE);
		this->m_ButtonStart.SetWindowTextA("��ʼ���");
		this->m_ComboBoxNICDevice.EnableWindow(TRUE);
		this->m_IPaddressControl.EnableWindow(TRUE);
		DWORD dwExitCode;
		pcap_close(fp);
		::GetExitCodeThread(this->m_pThreadSend,&dwExitCode);
		while(dwExitCode==STILL_ACTIVE)
		{
			Sleep(500);
			::GetExitCodeThread(this->m_pThreadSend,&dwExitCode);
		}
		::GetExitCodeThread(this->m_pThreadRecv,&dwExitCode);
		while(dwExitCode==STILL_ACTIVE)
		{
			Sleep(500);
			::GetExitCodeThread(this->m_pThreadRecv,&dwExitCode);
		}
	}
}


void CTraceRouteDlg::OnBnClickedButtonExit()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if(this->m_bClickFlag)
	{
		DWORD dwExitCode;
		pcap_close(fp);
		::GetExitCodeThread(this->m_pThreadSend,&dwExitCode);
		while(dwExitCode==STILL_ACTIVE)
		{
			Sleep(500);
			::GetExitCodeThread(this->m_pThreadSend,&dwExitCode);
		}
		::GetExitCodeThread(this->m_pThreadRecv,&dwExitCode);
		while(dwExitCode==STILL_ACTIVE)
		{
			Sleep(500);
			::GetExitCodeThread(this->m_pThreadRecv,&dwExitCode);
		}

	}
	exit(1);
}

LRESULT CTraceRouteDlg::OnUpdateTrace(WPARAM wparam, LPARAM lParam)
{
	CString strTemp;
	u_char* cParam = (u_char*)lParam;
	LONGLONG llTime = *((LONGLONG*)&cParam[4]);
	if ((llTime*1.0) / (time_fre) > 0.03){
		if (bFinishFlag == true)//����ڵ�
		{
			int iItemCount = this->m_ListCtrlTrace.GetItemCount();//���ж������Զ�����
			this->m_ListCtrlTrace.InsertItem(iItemCount, "");
			strTemp.Format("%d", iItemCount + 1);
			this->m_ListCtrlTrace.SetItemText(iItemCount, 0, strTemp);
			strTemp.Format("%f", (llTime*1.0) / (time_fre));
			this->m_ListCtrlTrace.SetItemText(iItemCount, 1, strTemp);
			this->m_ListCtrlTrace.SetItemText(iItemCount, 2, IPLongToAddress(*((long*)cParam)));
			this->m_ListCtrlTrace.SetItemText(iItemCount, 3, "Echo Reply");
			iItemCount = this->m_ListCtrlTrace.GetItemCount();//�Զ�����
			this->m_ListCtrlTrace.InsertItem(iItemCount, "");
			strTemp.Format("%d", iItemCount);
			this->m_ListCtrlTrace.SetItemText(iItemCount, 0, strTemp);
			strTemp.Format("%f", (llTime*1.0) / (time_fre));
			this->m_ListCtrlTrace.SetItemText(iItemCount, 1, "--");
			this->m_ListCtrlTrace.SetItemText(iItemCount, 2, "�ѵ�������");
			this->m_ListCtrlTrace.SetItemText(iItemCount, 3, "׷�ٳɹ���");
			CTraceRouteDlg::OnBnClickedButtonStart();
		}
		else if (bLosePackFlag == true)
		{
			if (this->m_ListCtrlTrace.GetItemCount() == maxLoop)
			{
				int iItemCount = this->m_ListCtrlTrace.GetItemCount();//���ж������Զ�����
				this->m_ListCtrlTrace.InsertItem(iItemCount, "");
				strTemp.Format("%d", iItemCount);
				this->m_ListCtrlTrace.SetItemText(iItemCount, 0, strTemp);
				this->m_ListCtrlTrace.SetItemText(iItemCount, 1, "--");
				this->m_ListCtrlTrace.SetItemText(iItemCount, 2, "Ŀ�Ľڵ㲻�ɴ�");
				this->m_ListCtrlTrace.SetItemText(iItemCount, 3, "׷��ʧ�ܣ�");
				CTraceRouteDlg::OnBnClickedButtonStart();
			}
			else{
				int iItemCount = this->m_ListCtrlTrace.GetItemCount();//���ж������Զ�����
				this->m_ListCtrlTrace.InsertItem(iItemCount, "");
				strTemp.Format("%d", iItemCount + 1);
				this->m_ListCtrlTrace.SetItemText(iItemCount, 0, strTemp);
				this->m_ListCtrlTrace.SetItemText(iItemCount, 1, "��ʱ");
				this->m_ListCtrlTrace.SetItemText(iItemCount, 2, "*");
				this->m_ListCtrlTrace.SetItemText(iItemCount, 3, "�ڵ�δ����");
				bLosePackFlag == false;
				bRecvFlag == true;
			}
		}
		//else if (bfailtoRecieveFlag == true)
		//{
		//
		//}
		else{
			int iItemCount = this->m_ListCtrlTrace.GetItemCount();//���ж������Զ�����
			this->m_ListCtrlTrace.InsertItem(iItemCount, "");
			strTemp.Format("%d", iItemCount + 1);
			this->m_ListCtrlTrace.SetItemText(iItemCount, 0, strTemp);
			strTemp.Format("%f", (llTime*1.0) / (time_fre));
			this->m_ListCtrlTrace.SetItemText(iItemCount, 1, strTemp);
			this->m_ListCtrlTrace.SetItemText(iItemCount, 2, IPLongToAddress(*((long*)cParam)));
			this->m_ListCtrlTrace.SetItemText(iItemCount, 3, "Network unreachable for TOS");
		}
	}
	free(cParam);
	return 1;

}

void CTraceRouteDlg::OnLvnItemchangedListRoute(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: Add your control notification handler code here
	*pResult = 0;
}


void CTraceRouteDlg::OnBnClickedButtonStart2()
{
	// TODO: Add your control notification handler code here
	MessageBox("����һ���򵥵�·����׷�ٳ�������Ŀ��IP��ַ������ģ��Tracent׷�ٵ���Ŀ��IP��ַ�м��ÿһ��·������IP��ַ����������Ӧʱ�䡣\n\t\t\t��Ȩ�����꺭��ë�á�����÷���С�");
}
