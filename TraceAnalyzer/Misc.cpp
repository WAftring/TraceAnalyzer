#include "Misc.h"
#pragma warning(disable : 4996)
bool LoadNpDlls()
{
	BOOL(WINAPI *SetDllDirectory)(LPCSTR);
	char sysdir_name[512];
	int len;
	
	SetDllDirectory = (BOOL(WINAPI*)(LPCSTR)) GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetDllDirectoryA");
	if(SetDllDirectory == NULL)
	{
		printf("Failed set DLL directory\n");
		return FALSE;
	}
	else 
	{
		len = GetSystemDirectoryA(sysdir_name, 480);
		if(!len)
		{
			printf("Failed to get system directory\n");
			return FALSE;
		}
		strcat(sysdir_name, "\\Npcap");
		if(SetDllDirectoryA(sysdir_name) == 0)
		{
			printf("Failed to SetDllDirectory(\"System\\Npcap\")");
			return FALSE;
		}
	}
	return TRUE;
}