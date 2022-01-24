/*	Benjamin DELPY `gentilkiwi`
	blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_standard.h"

const KUHL_M_C kuhl_m_c_standard[] = {
	{kuhl_m_standard_exit,		L"exit",		L"Quit passrecov"},
	{kuhl_m_standard_cls,		L"cls",			L"Clear screen (doesn\'t work with redirections, like PsExec)"},
	{kuhl_m_standard_log,		L"log",			L"Log passrecov input/output to file"},
	{kuhl_m_standard_cd,		L"cd",			L"Change or display current directory"},
	{kuhl_m_standard_localtime,	L"localtime",	L"Displays system local date and time (OJ command)"},
	{kuhl_m_standard_hostname,	L"hostname",	L"Displays system local hostname"},
};
const KUHL_M kuhl_m_standard = {
	L"standard",	L"Standard module",	L"Basic commands (does not require module name)",
	ARRAYSIZE(kuhl_m_c_standard), kuhl_m_c_standard, NULL, NULL
};

NTSTATUS kuhl_m_standard_exit(int argc, wchar_t * argv[])
{
	return argc ? STATUS_THREAD_IS_TERMINATING : STATUS_PROCESS_IS_TERMINATING;
}

NTSTATUS kuhl_m_standard_cls(int argc, wchar_t * argv[])
{
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD coord = {0, 0};
	DWORD count;
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	GetConsoleScreenBufferInfo(hStdOut, &csbi);
	FillConsoleOutputCharacter(hStdOut, L' ', csbi.dwSize.X * csbi.dwSize.Y, coord, &count);
	SetConsoleCursorPosition(hStdOut, coord);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_log(int argc, wchar_t * argv[])
{
	PCWCHAR filename = (kull_m_string_args_byName(argc, argv, L"stop", NULL, NULL) ? NULL : (argc ? argv[0] : MIMIKATZ_DEFAULT_LOG));
	kprintf(L"Using \'%s\' for logfile : %s\n", filename, kull_m_output_file(filename) ? L"OK" : L"KO");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_cd(int argc, wchar_t * argv[])
{
	wchar_t * buffer;
	if(kull_m_file_getCurrentDirectory(&buffer))
	{
		if(argc)
			kprintf(L"Cur: ");
		kprintf(L"%s\n", buffer);
		LocalFree(buffer);
	}
	else PRINT_ERROR_AUTO(L"kull_m_file_getCurrentDirectory");

	if(argc)
	{
		if(SetCurrentDirectory(argv[0]))
		{
			if(kull_m_file_getCurrentDirectory(&buffer))
			{
				kprintf(L"New: %s\n", buffer);
				LocalFree(buffer);
			}
			else PRINT_ERROR_AUTO(L"kull_m_file_getCurrentDirectory");
		}
		else PRINT_ERROR_AUTO(L"SetCurrentDirectory");
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_localtime(int argc, wchar_t * argv[])
{
	FILETIME ft;
	TIME_ZONE_INFORMATION tzi;
	DWORD dwTzi;
	GetSystemTimeAsFileTime(&ft);
	dwTzi = GetTimeZoneInformation(&tzi);
	kprintf(L"Local: "); kull_m_string_displayLocalFileTime(&ft); kprintf(L"\n");
	if(dwTzi != TIME_ZONE_ID_INVALID && dwTzi != TIME_ZONE_ID_UNKNOWN)
		kprintf(L"Zone : %.32s\n", (dwTzi == TIME_ZONE_ID_STANDARD) ? tzi.StandardName : tzi.DaylightName);
	kprintf(L"UTC  : "); kull_m_string_displayFileTime(&ft); kprintf(L"\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_hostname(int argc, wchar_t * argv[])
{
	wchar_t *buffer;
	if(kull_m_net_getComputerName(TRUE, &buffer))
	{
		kprintf(L"%s", buffer);
		LocalFree(buffer);
	}
	if(kull_m_net_getComputerName(FALSE, &buffer))
	{
		kprintf(L" (%s)", buffer);
		LocalFree(buffer);
	}
	kprintf(L"\n");
	return STATUS_SUCCESS;
}