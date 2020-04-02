#include <windows.h>
#include <string>
#include "Logger.h"
#pragma warning(disable : 4996)
char g_LogPath[MAX_PATH];

BOOL InitLogger(const char* Path)
{
	//TODO: Add logic for if file already exists
	DWORD dwRetVal;
	std::string LogPath;
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
	sprintf(ReportIntro, "Trace Analysis\n%s", Path);
	strcpy(g_LogPath, LogPath.c_str());
	WriteToReport(ReportIntro, LogType::HEADER);
	return TRUE;

	
}

VOID WriteToReport(char* Content, LogType type)
{
	HANDLE hFile;
	DWORD dwBytesToWrite = strlen(Content);
	DWORD dwBytesWritten;
	BOOL bErrorFlag = FALSE;

	hFile = CreateFileA(g_LogPath,
		FILE_APPEND_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to write to file\n");
		bErrorFlag = TRUE;
	}
	if (!bErrorFlag)
	{
		bErrorFlag = FALSE;
		while (dwBytesToWrite > 0)
		{
			bErrorFlag = WriteFile(hFile,
				Content,
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