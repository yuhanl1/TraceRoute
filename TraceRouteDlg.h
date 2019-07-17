
// TraceRouteDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"

#include "NicDevice.h"

// CTraceRouteDlg �Ի���
class CTraceRouteDlg : public CDialogEx
{
// ����
public:
	CTraceRouteDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_TRACEROUTE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonStart();
	afx_msg void OnBnClickedButtonExit();
	CWinThread* m_pThreadSend;
	CWinThread* m_pThreadRecv;
	bool m_bClickFlag;
	CEdit m_EditIP;
	CButton m_ButtonStart;
	CButton m_ButtonExit;
	CListCtrl m_ListCtrlTrace;
	CIPAddressCtrl m_IPaddressControl;
//	afx_msg void OnCbnSelchangeComboNicDevice();
	CComboBox m_ComboBoxNICDevice;
	afx_msg LRESULT OnUpdateTrace(WPARAM wparam, LPARAM lParam);//�������ͱ���ΪLRESULT
	afx_msg void OnLvnItemchangedListRoute(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButtonStart2();
};
