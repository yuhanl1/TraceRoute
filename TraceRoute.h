
// TraceRoute.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CTraceRouteApp:
// �йش����ʵ�֣������ TraceRoute.cpp
//

class CTraceRouteApp : public CWinApp
{
public:
	CTraceRouteApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CTraceRouteApp theApp;