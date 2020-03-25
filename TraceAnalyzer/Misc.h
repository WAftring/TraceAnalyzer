#pragma once
#include <windows.h>
#include <stdio.h>
typedef int (__cdecl *MYPROC)(LPSTR);
bool LoadNpDlls();

