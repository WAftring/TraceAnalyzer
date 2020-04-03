#include <windows.h>
#include <string>
#include <Shlwapi.h>
#include "Logger.h"
#pragma warning(disable : 4996)
char g_LogPath[MAX_PATH];

BOOL InitLogger(const char* Path)
{
	std::string LogPath;
	BOOL ReadIn = TRUE;
	BOOL Res = FALSE;
	char ActionBuff;
	char ReportIntro[MAX_PATH];
	const size_t lastSlash = ((std::string)Path).rfind('\\');
	
	if (std::string::npos != lastSlash)
	{
		LogPath = (((std::string)Path).substr(0, lastSlash));
	}
	else
	{
		printf("Couldn't get log path\n");
		return FALSE;
	}
	LogPath.append("\\Trace_Report.log");
	strcpy(g_LogPath, LogPath.c_str());
	//Testing if the path exists, if yes clear it else, create it
	if(PathFileExistsA(g_LogPath))
	{
		printf("Previous log file exists what would you like to do? (o)verwrite/(e)xit\n");
		while(ReadIn)
		{
			ActionBuff = getchar();
			switch(ActionBuff)
			{
				case 'o':
					if(!DeleteFileA(g_LogPath))
					{
						printf("Failed to delete old logfile\n");
						exit(1);
					}
					ReadIn = FALSE;
					break;
				case 'e':
					printf("Please handle the old log file\n");
					exit(0);
					break;
				case '\n':
					break;
				default:
					printf("Please enter a valid character (o)verwrite/(e)xit\n");
					break;
			}
		}
	}
	sprintf(ReportIntro, "Trace Analysis\n%s\n==========\n\n", Path);
	WriteToReport(ReportIntro, LogType::HEADER);
	return TRUE;

	
}

VOID WriteToReport(char* Content, LogType type)
{
	HANDLE hFile;
	std::string WriteStr;
	DWORD dwBytesToWrite;
	DWORD dwBytesWritten;
	BOOL bErrorFlag = FALSE;

	hFile = CreateFileA(g_LogPath,
		FILE_APPEND_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		hFile = CreateFileA(g_LogPath,
			FILE_APPEND_DATA,
			FILE_SHARE_READ,
			NULL,
			CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
	}
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to write to file\n");
		bErrorFlag = TRUE;
	}
	switch (type)
	{
	case HEADER:

		break;
	case WARN:
		WriteStr.append("[WARN] ");
		break;
	case INFO:
		WriteStr.append("[INFO] ");
		break;
	}
	WriteStr.append(Content);
	dwBytesToWrite = strlen(WriteStr.c_str());
	if (!bErrorFlag)
	{
		bErrorFlag = FALSE;
		while (dwBytesToWrite > 0)
		{
			bErrorFlag = WriteFile(hFile,
				WriteStr.c_str(),
				dwBytesToWrite,
				&dwBytesWritten,
				NULL);

			if (!bErrorFlag)
			{
				printf("Failed to write to a file\n");
				break;
			}

			Content += dwBytesWritten;
			dwBytesToWrite -= dwBytesWritten;
		}

		CloseHandle(hFile);
	}
}