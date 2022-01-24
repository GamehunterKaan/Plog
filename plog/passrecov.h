/*	Benjamin DELPY `gentilkiwi`
	blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : creativecommons.org/licenses/by/4.0/
*/
#pragma once

#include "globals.h"
#include "modules/kuhl_m_standard.h"
#include "modules/sekurlsa/kuhl_m_sekurlsa.h"
#include "modules/kerberos/kuhl_m_kerberos.h"
#include "modules/kuhl_m_privilege.h"
#include "modules/kuhl_m_lsadump.h"
#include "modules/dpapi/kuhl_m_dpapi.h"

#include <io.h>
#include <fcntl.h>
#define DELAYIMP_INSECURE_WRITABLE_HOOKS
#include <delayimp.h>

extern VOID WINAPI RtlGetNtVersionNumbers(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);

int wmain(int argc, wchar_t * argv[]);
void passrecov_begin();
void passrecov_end(NTSTATUS status);

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType);

NTSTATUS passrecov_initOrClean(BOOL Init);

NTSTATUS passrecov_doLocal(wchar_t * input);
NTSTATUS passrecov_dispatchCommand(wchar_t * input);

#if defined(_POWERKATZ)
__declspec(dllexport) wchar_t * powershell_reflective_passrecov(LPCWSTR input);
#elif defined(_WINDLL)
void CALLBACK passrecov_dll(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow);
#if defined(_M_X64) || defined(_M_ARM64)
#pragma comment(linker, "/export:mainW=passrecov_dll")
#elif defined(_M_IX86)
#pragma comment(linker, "/export:mainW=_passrecov_dll@16")
#endif
#endif