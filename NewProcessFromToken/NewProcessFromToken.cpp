//  Copyright 2015 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

#include "stdafx.h"
#include <strsafe.h>
#include <sddl.h>
#include <vector>

BOOL SetTokenIL(HANDLE hToken, DWORD dwIntegrityLevel)
{

	BOOL                  fRet = FALSE;
	PSID                  pIntegritySid = NULL;
	TOKEN_MANDATORY_LABEL TIL = { 0 };

	// Low integrity SID
	WCHAR wszIntegritySid[32];

	if (FAILED(StringCbPrintf(wszIntegritySid, sizeof(wszIntegritySid), L"S-1-16-%d", dwIntegrityLevel)))
	{
		printf("Error creating IL SID\n");
		goto CleanExit;
	}

	fRet = ConvertStringSidToSid(wszIntegritySid, &pIntegritySid);

	if (!fRet)
	{
		printf("Error converting IL string %d\n", GetLastError());
		goto CleanExit;
	}

	TIL.Label.Attributes = SE_GROUP_INTEGRITY;
	TIL.Label.Sid = pIntegritySid;

	fRet = SetTokenInformation(hToken,
		TokenIntegrityLevel,
		&TIL,
		sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid));

	if (!fRet)
	{
		printf("Error setting IL %d\n", GetLastError());
		goto CleanExit;
	}

CleanExit:

	LocalFree(pIntegritySid);

	return fRet;
}

int ParseILLevel(LPCWSTR ilstr)
{
	int il = 0;
	switch (tolower(ilstr[0]))
	{
	case 'u':
		il = SECURITY_MANDATORY_UNTRUSTED_RID;
		break;
	case 'l':
		il = SECURITY_MANDATORY_LOW_RID;
		break;
	case 'm':
		il = SECURITY_MANDATORY_MEDIUM_RID;
		break;
	case 'h':
		il = SECURITY_MANDATORY_HIGH_RID;
		break;
	case 's':
		il = SECURITY_MANDATORY_SYSTEM_RID;
		break;
	default:
		il = wcstoul(ilstr, 0, 0);
		break;
	}

	return il;
}

#define DEC_AND_CHECK_ARGC() if (--argc <= 0) { return false; }

bool ParseArgs(int argc, WCHAR** argv, int* pid, bool* parentprocess, WCHAR** cmdline, int* illevel)
{
	WCHAR** curr_arg = &argv[1];

	DEC_AND_CHECK_ARGC();

	while (*curr_arg[0] == '-')
	{
		if (wcscmp(*curr_arg, L"-p") == 0)
		{
			*parentprocess = true;		
		}
		if (wcscmp(*curr_arg, L"-il") == 0)
		{
			curr_arg++;
			DEC_AND_CHECK_ARGC();
			*illevel = ParseILLevel(*curr_arg);		
		}

		curr_arg++;
		DEC_AND_CHECK_ARGC();
	}

	if (argc < 2)
	{
		return false;
	}

	*pid = wcstoul(*curr_arg, 0, 0);
	curr_arg++;
	*cmdline = *curr_arg;

	return true;
}

int _tmain(int argc, _TCHAR* argv[])
{
	bool parentprocess = false;
	WCHAR* cmdline = nullptr;
	int pid = 0;
	int illevel = -1;

	if (!ParseArgs(argc, argv, &pid, &parentprocess, &cmdline, &illevel))
	{
		printf("NewProcessFromToken: [-p] pid cmdline\n");
		printf("Options:\n");
		printf("-p : Use parent process technique to create the new process\n");
		printf("-il level: Set the process IL level\n");
	}
	else
	{
		if (pid == 0)
		{
			pid = GetCurrentProcessId();
		}

		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 
			FALSE, pid);
		if (hProcess)
		{
			if (!parentprocess)
			{
				HANDLE hToken;

				if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
				{
					HANDLE hDupToken;

					if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &hDupToken))
					{
						if (illevel >= 0)
						{
							SetTokenIL(hDupToken, illevel);
						}

						STARTUPINFO startInfo = { 0 };
						PROCESS_INFORMATION procInfo = { 0 };

						startInfo.cb = sizeof(startInfo);

						if (CreateProcessAsUserW(hDupToken, nullptr, cmdline, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startInfo, &procInfo))
						{
							printf("Created process %d\n", procInfo.dwProcessId);
						}
						else
						{
							printf("Error CPAU %d\n", GetLastError());
						}
					}
					else
					{
						printf("Error Dup: %d\n", GetLastError());
					}
				}
				else
				{
					printf("Error OPT: %d\n", GetLastError());
				}
			}
			else
			{
				SIZE_T size = 0;

				InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
					
				std::vector<BYTE> attrlist(size);
				LPPROC_THREAD_ATTRIBUTE_LIST pattrlist = (LPPROC_THREAD_ATTRIBUTE_LIST)&attrlist[0];

				InitializeProcThreadAttributeList(pattrlist, 1, 0, &size);

				if (UpdateProcThreadAttribute(pattrlist, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(hProcess), nullptr, nullptr))
				{
					STARTUPINFOEX startInfo = { 0 };
					PROCESS_INFORMATION procInfo = { 0 };

					startInfo.StartupInfo.cb = sizeof(startInfo);
					startInfo.lpAttributeList = pattrlist;

					if (CreateProcess(nullptr, cmdline, nullptr, nullptr, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, 
						nullptr, nullptr, &startInfo.StartupInfo, &procInfo))
					{
						printf("Created process %d\n", procInfo.dwProcessId);
						if (illevel >= 0)
						{
							HANDLE hToken;

							if (OpenProcessToken(procInfo.hProcess, TOKEN_ALL_ACCESS, &hToken))
							{
								SetTokenIL(hToken, illevel);
							}								
						}

						ResumeThread(procInfo.hThread);
					}
					else
					{
						printf("Error: CreateProcess %d\n", GetLastError());
					}
				}


				DeleteProcThreadAttributeList(pattrlist);
			}

		}
		else
		{
			printf("Error OP: %d\n", GetLastError());
		}
	}

	return 0;
}

