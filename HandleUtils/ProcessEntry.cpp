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
#include "ProcessEntry.h"

#include <vector>
#include <sddl.h>
#include "ScopedHandle.h"
#include "WindowsInternals.h"

#pragma comment(lib, "advapi32.lib")

std::vector<unsigned char> GetTokenInfo(HANDLE hToken, TOKEN_INFORMATION_CLASS tokenClass)
{
	std::vector<unsigned char> ret;
	DWORD cbTokenInfo;	

	if (!GetTokenInformation(hToken, tokenClass, nullptr, 0, &cbTokenInfo))
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			ret.resize(cbTokenInfo);			

			if (!GetTokenInformation(hToken, tokenClass, &ret[0], (DWORD)ret.size(), &cbTokenInfo))
			{	
				ret.clear();
			}
		}
	}

	return ret;
}

BOOL EnableDebugPrivilege()
{
	HANDLE hToken;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		return FALSE;
	}
	LUID luid;

	if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
	{
		TOKEN_PRIVILEGES tp;

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
	}

	CloseHandle(hToken);

	return TRUE;
}

unsigned int GetProcessIntegrityLevel(HANDLE hToken)
{
	std::vector<unsigned char> tokenIL = GetTokenInfo(hToken, TokenIntegrityLevel);

	if (tokenIL.size() > 0)
	{
		PTOKEN_MANDATORY_LABEL il = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(&tokenIL[0]);

		return *GetSidSubAuthority(il->Label.Sid, 0);
	}
	else
	{
		return 0xFFFFFFFF;
	}
}

#define MAX_NAME 256

String^ GetTokenUsername(HANDLE hToken)
{
	std::vector<unsigned char> tokenUsername = GetTokenInfo(hToken, TokenUser);

	if (tokenUsername.size() > 0)
	{
		PTOKEN_USER user = reinterpret_cast<PTOKEN_USER>(&tokenUsername[0]);

		std::vector<wchar_t> name(MAX_NAME);
		std::vector<wchar_t> domain(MAX_NAME);
		DWORD dwNameSize = MAX_NAME;
		DWORD dwDomainSize = MAX_NAME;
		SID_NAME_USE sidNameUse;
		String^ ret = "";

		if (LookupAccountSid(nullptr, user->User.Sid, &name[0], &dwNameSize, &domain[0], &dwDomainSize, &sidNameUse))
		{
			ret = gcnew String(&domain[0]);
			ret += "\\";
			ret += gcnew String(&name[0]);			
		}
		else
		{
			LPWSTR lpSid;

			if (ConvertSidToStringSidW(user->User.Sid, &lpSid))
			{
				ret = gcnew String(lpSid);
				LocalFree(lpSid);
			}
		}

		return ret;
	}
	
	return "";
}

namespace TokenLibrary
{
	ProcessEntry::ProcessEntry(System::Diagnostics::Process^ process)
	{
		this->Name = process->ProcessName;
		this->Pid = process->Id;
		this->SessionId = process->SessionId;
		
		EnableDebugPrivilege();

		ScopedHandle hProcess(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, this->Pid), false);

		if (hProcess.IsValid())
		{
			ScopedHandle hToken;

			if (::OpenProcessToken(hProcess, TOKEN_QUERY | READ_CONTROL | TOKEN_QUERY_SOURCE, hToken.GetBuffer()))
			{
				this->_token = gcnew UserToken(hToken.DetachAsNativeHandle());											
			}

			this->_process = hProcess.DetachAsNativeHandle();
		}
	}

	System::Collections::Generic::List<ProcessEntry^>^ ProcessEntry::GetProcesses(bool all)
	{
		array<System::Diagnostics::Process^>^ ps = System::Diagnostics::Process::GetProcesses();
		System::Collections::Generic::List<ProcessEntry^>^ ret = gcnew System::Collections::Generic::List<ProcessEntry^>();

		for (int i = 0; i < ps->Length; ++i)
		{
			ProcessEntry^ entry = gcnew ProcessEntry(ps[i]);
			if (all || entry->_process != nullptr)
			{
				ret->Add(entry);
			}
			ps[i]->Close();
		}

		return ret;
	}

	System::Collections::Generic::List<ProcessEntry^>^ ProcessEntry::GetProcesses()
	{
		return ProcessEntry::GetProcesses(false);
	}

	System::Collections::Generic::List<ThreadEntry^>^ ProcessEntry::GetThreadsWithTokens()
	{
		System::Collections::Generic::List<ThreadEntry^>^ ret = gcnew System::Collections::Generic::List<ThreadEntry^>();
		EnableDebugPrivilege();

		DEFINE_NTDLL(NtGetNextThread);

		ScopedHandle hThread;
		ScopedHandle hNextThread;
		while (NT_SUCCESS(fNtGetNextThread(_process->DangerousGetHandle().ToPointer(),
			hThread, THREAD_QUERY_INFORMATION, 0, 0, hNextThread.GetBuffer())))
		{
			ScopedHandle hToken;
			if (::OpenThreadToken(hNextThread, MAXIMUM_ALLOWED, TRUE, hToken.GetBuffer()))
			{
				ret->Add(gcnew ThreadEntry(GetThreadId(hNextThread), this, gcnew UserToken(hToken.DetachAsNativeHandle())));
			}			
			
			hThread.Reset(hNextThread);			
		}

		return ret;
	}
}