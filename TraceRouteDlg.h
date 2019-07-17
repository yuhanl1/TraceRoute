
// TraceRouteDlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"

#include "NicDevice.h"

// CTraceRouteDlg 对话框
class CTraceRouteDlg : public CDialogEx
{
// 构造
public:
	CTraceRouteDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_TRACEROUTE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
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
	afx_msg LRESULT OnUpdateTrace(WPARAM wparam, LPARAM lParam);//返回类型必须为LRESULT
	afx_msg void OnLvnItemchangedListRoute(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButtonStart2();
};
