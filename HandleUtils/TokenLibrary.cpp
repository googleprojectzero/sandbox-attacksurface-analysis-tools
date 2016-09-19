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
#include "TokenLibrary.h"
#include "ScopedHandle.h"
#include <winsafer.h>
#include <Wtsapi32.h>
#include <sddl.h>
#include "typed_buffer.h"

#pragma comment(lib, "Wtsapi32.lib")

NativeHandle^ LogonS4U(System::String^ user, System::String^ realm, SECURITY_LOGON_TYPE type);
typedef BOOL (WINAPI *fLogonUserExExW)(
	_In_      LPCWSTR        lpszUsername,
	_In_opt_  LPCWSTR        lpszDomain,
	_In_opt_  LPCWSTR        lpszPassword,
	_In_      DWORD         dwLogonType,
	_In_      DWORD         dwLogonProvider,
	_In_opt_  PTOKEN_GROUPS pTokenGroups,
	_Out_opt_ PHANDLE       phToken,
	_Out_opt_ PSID          *ppLogonSid,
	_Out_opt_ PVOID         *ppProfileBuffer,
	_Out_opt_ LPDWORD       pdwProfileLength,
	_Out_opt_ PQUOTA_LIMITS pQuotaLimits
	);

ScopedHandle CaptureImpersonationToken();

typedef int(__stdcall* _GetClipboardAccessToken)(PHANDLE hToken, ACCESS_MASK DesiredAccess);

namespace TokenLibrary
{
	UserToken^ TokenUtils::GetLogonS4UToken(String^ user, String^ realm, LogonType logonType)
	{
		SECURITY_LOGON_TYPE seclogon_type;

		switch(logonType)
		{
		case LogonType::Batch:
			seclogon_type = Batch;
			break;
		case LogonType::Interactive:
			seclogon_type = Interactive;
			break;
		case LogonType::Network:
			seclogon_type = Network;
			break;
		default:
			throw gcnew ArgumentException("Invalid logon type for S4U");
		}

		return gcnew UserToken(::LogonS4U(user, realm, seclogon_type));
	}

	UserToken^ TokenUtils::GetAnonymousToken()
	{
		if (ImpersonateAnonymousToken(GetCurrentThread()))
		{
			ScopedHandle handle;

			if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_QUERY_SOURCE | READ_CONTROL, TRUE, handle.GetBuffer()))
			{
				RevertToSelf();
				return gcnew UserToken(handle.DetachAsNativeHandle());
			}
			else
			{
				DWORD dwLastError = ::GetLastError();

				RevertToSelf();

				throw gcnew System::ComponentModel::Win32Exception(dwLastError);
			}
		}
		else
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}
	}

	UserToken^ TokenUtils::GetLogonUserToken(System::String^ username, System::String^ domain, System::String^ password, 
		array<UserGroup^>^ groups, LogonType logonType)
	{
		pin_ptr<const wchar_t> pusername = PtrToStringChars(username);
		pin_ptr<const wchar_t> pdomain;
		pin_ptr<const wchar_t> ppassword;

		if (domain != nullptr)
		{
			pdomain = PtrToStringChars(domain);
		}

		if (password != nullptr)
		{
			ppassword = PtrToStringChars(password);
		}

		DWORD dwLogonType;

		switch (logonType)
		{
		case LogonType::Batch:
			dwLogonType = LOGON32_LOGON_BATCH;
			break;
		case LogonType::Interactive:
			dwLogonType = LOGON32_LOGON_INTERACTIVE;
			break;
		case LogonType::Network:
			dwLogonType = LOGON32_LOGON_NETWORK;
			break;
		case LogonType::NetworkCleartext:
			dwLogonType = LOGON32_LOGON_NETWORK_CLEARTEXT;
			break;
		case LogonType::NewCredentials:
			dwLogonType = LOGON32_LOGON_NEW_CREDENTIALS;
			break;
		case LogonType::Service:
			dwLogonType = LOGON32_LOGON_SERVICE;
			break;
		default:
			throw gcnew ArgumentException("Invalid logon type");
		}

		ScopedHandle handle;

		fLogonUserExExW pfLogonUserExExW = (fLogonUserExExW)GetProcAddress(GetModuleHandle(L"Advapi32"),
			"LogonUserExExW");
		if (pfLogonUserExExW && (groups != nullptr) && (groups->Length > 0))
		{
			typed_buffer_ptr<TOKEN_GROUPS> pgroups;
			PTOKEN_GROUPS pg = nullptr;

			System::IO::MemoryStream^ ms = gcnew System::IO::MemoryStream();
			System::Collections::Generic::List<int>^ sid_pos = gcnew System::Collections::Generic::List<int>();

			for each (UserGroup^ group in groups)
			{
				array<byte>^ sid_bytes = gcnew array<byte>(group->Sid->BinaryLength);
				group->Sid->GetBinaryForm(sid_bytes, 0);

				sid_pos->Add((int)ms->Position);
				ms->Write(sid_bytes, 0, sid_bytes->Length);					
			}

			array<byte>^ sid_bytes = ms->ToArray();

			pgroups.reset(sizeof(TOKEN_GROUPS) + (sizeof(SID_AND_ATTRIBUTES) * (groups->Length - 1) + sid_bytes->Length));
			IntPtr base_sid(pgroups.bytes() + sizeof(TOKEN_GROUPS) + (sizeof(SID_AND_ATTRIBUTES) * (groups->Length - 1)));

			System::Runtime::InteropServices::Marshal::Copy(sid_bytes, 0, base_sid, sid_bytes->Length);

			for (int i = 0; i < sid_pos->Count; ++i)
			{									
				pgroups->Groups[i].Sid = (base_sid + sid_pos[i]).ToPointer();
				pgroups->Groups[i].Attributes = (unsigned int)groups[i]->Flags;
			}
			pgroups->GroupCount = groups->Length;
			pg = pgroups;			
		
			if (!pfLogonUserExExW(pusername, domain != nullptr ? pdomain : nullptr, password != nullptr ? ppassword : nullptr,
				dwLogonType, LOGON32_PROVIDER_DEFAULT, pg, handle.GetBuffer(), nullptr, nullptr, nullptr, nullptr))
			{
				throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
			}
		}
		else
		{
			if (!LogonUser(pusername, domain != nullptr ? pdomain : nullptr, password != nullptr ? ppassword : nullptr,
				dwLogonType, LOGON32_PROVIDER_DEFAULT, handle.GetBuffer()))
			{
				throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
			}				
		}

		return gcnew UserToken(handle.DetachAsNativeHandle());
	}

	UserToken^ TokenUtils::GetTokenFromBits()
	{
		ScopedHandle handle = CaptureImpersonationToken();

		return gcnew UserToken(handle.DetachAsNativeHandle());
	}

	UserToken^ TokenUtils::GetTokenFromThread()
	{
		ScopedHandle handle;

		if (::OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_QUERY_SOURCE | READ_CONTROL, TRUE, handle.GetBuffer()))
		{
			return gcnew UserToken(handle.DetachAsNativeHandle());
		}
		else
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}
	}

	UserToken^ TokenUtils::GetTokenFromCurrentProcess()
	{
		ScopedHandle handle;

		if (::OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_QUERY_SOURCE | READ_CONTROL, handle.GetBuffer()))
		{
			return gcnew UserToken(handle.DetachAsNativeHandle());
		}
		else
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}		
	}

	UserToken^ TokenUtils::GetTokenFromClipboard()
	{
		_GetClipboardAccessToken fGetClipboardAccessToken = (_GetClipboardAccessToken)GetProcAddress(LoadLibrary(L"user32.dll"), "GetClipboardAccessToken");

		if (fGetClipboardAccessToken)
		{
			ScopedHandle handle;

			if (fGetClipboardAccessToken(handle.GetBuffer(), TOKEN_QUERY | TOKEN_QUERY_SOURCE | READ_CONTROL))
			{
				return gcnew UserToken(handle.DetachAsNativeHandle());
			}
			else
			{
				throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
			}
		}
		else
		{
			throw gcnew System::InvalidOperationException("GetClipboardAccessToken doesn't exist");
		}
	}

	UserToken^ TokenUtils::CreateProcessForToken(System::String^ cmdline, UserToken^ token, bool make_interactive)
	{
		STARTUPINFO startInfo = { 0 };
		PROCESS_INFORMATION procInfo = { 0 };
		pin_ptr<const wchar_t> cl = PtrToStringChars(cmdline);
		startInfo.cb = sizeof(startInfo);
		UserToken^ duptoken = token->DuplicateToken(TokenType::Primary, TokenImpersonationLevel::Anonymous);

		try
		{
			if (make_interactive)
			{
				startInfo.lpDesktop = L"WinSta0\\Default";
				DWORD dwSessionId;
				
				::ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId);
				if (!::SetTokenInformation(duptoken->Handle.ToPointer(), TokenSessionId, &dwSessionId, sizeof(dwSessionId)))
				{
					throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
				}
			}

			if (CreateProcessAsUser(duptoken->Handle.ToPointer(), nullptr, const_cast<wchar_t*>(cl),
				nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startInfo, &procInfo) || 
				CreateProcessWithTokenW(duptoken->Handle.ToPointer(), 0, nullptr, const_cast<wchar_t*>(cl),
				0, nullptr, nullptr, &startInfo, &procInfo))
			{
				ScopedHandle handle;

				::OpenProcessToken(procInfo.hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE | READ_CONTROL, handle.GetBuffer());

				CloseHandle(procInfo.hProcess);
				CloseHandle(procInfo.hThread);

				return gcnew UserToken(handle.DetachAsNativeHandle());
			}
			else
			{
				throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
			}
		}
		finally
		{
			duptoken->Close();
		}
	}

	UserToken^ TokenUtils::GetTokenFromSaferLevel(UserToken^ token, SaferLevel level, bool make_inert)
	{
		SAFER_LEVEL_HANDLE handle;
		UserToken^ duptoken = nullptr;

		if (SaferCreateLevel(SAFER_SCOPEID_USER, (DWORD)level, SAFER_LEVEL_OPEN, &handle, nullptr))
		{
			try
			{
				duptoken = token->DuplicateHandle(TOKEN_ALL_ACCESS);
				ScopedHandle outhandle;

				if (SaferComputeTokenFromLevel(handle, duptoken->Handle.ToPointer(), outhandle.GetBuffer(), make_inert ? SAFER_TOKEN_MAKE_INERT : 0, nullptr))
				{
					return gcnew UserToken(outhandle.DetachAsNativeHandle());
				}
				else
				{
					throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
				}
			}
			finally
			{
				SaferCloseLevel(handle);
			}
		}
		else
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}
	}

	array<UserToken^>^ TokenUtils::GetSessionTokens()
	{
		System::Collections::Generic::List<UserToken^>^ tokens = gcnew System::Collections::Generic::List<UserToken^>();
		PWTS_SESSION_INFO pSessions;
		DWORD dwSessionCount;

		if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &dwSessionCount))
		{
			for (DWORD i = 0; i < dwSessionCount; ++i)
			{
				ScopedHandle handle;
				if (WTSQueryUserToken(i, handle.GetBuffer()))
				{
					tokens->Add(gcnew UserToken(handle.DetachAsNativeHandle()));
				}
			}
			WTSFreeMemory(pSessions);
		}

		return tokens->ToArray();
	}

  struct LocalFreeDeleter
  {
    typedef void* pointer;
    void operator()(void* p) {
      ::LocalFree(p);
    }
  };

  System::Security::Principal::SecurityIdentifier^ TokenUtils::StringSidToSecurityIdentitfier(String^ sid)
  {
    pin_ptr<const wchar_t> psid = PtrToStringChars(sid);
    PSID p;
    if (!::ConvertStringSidToSid(psid, &p))
      throw gcnew System::ComponentModel::Win32Exception();
    std::unique_ptr<void, LocalFreeDeleter> sid_buf = nullptr;
    sid_buf.reset(p);

    return gcnew System::Security::Principal::SecurityIdentifier(IntPtr(p));
  }
}

