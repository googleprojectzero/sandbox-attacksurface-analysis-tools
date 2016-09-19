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
#include <Ntsecapi.h>
#include <vcclr.h>
#include "typed_buffer.h"
#include "ScopedHandle.h"

#pragma comment(lib, "secur32.lib") 
#pragma comment(lib, "Advapi32.lib")

static void TestError(NTSTATUS s) {
	if (s) {
		throw gcnew System::ComponentModel::Win32Exception(LsaNtStatusToWinError(s));
	}	
}

static void InitLsaString(LSA_STRING* lsastr, char* str)
{
	size_t len = strlen(str);
	lsastr->Length = (USHORT)len;
	lsastr->MaximumLength = lsastr->Length + 1;
	lsastr->Buffer = str;
}

static ScopedHandle s4uLogon(const wchar_t* user, const wchar_t* realm, SECURITY_LOGON_TYPE type) { 
	
	HANDLE hlsa;	
	LSA_STRING pkgName;

	TestError(LsaConnectUntrusted(&hlsa));
	InitLsaString(&pkgName, "Negotiate");

	ULONG authnPkg;
	TestError(LsaLookupAuthenticationPackage(hlsa, &pkgName, &authnPkg));
	const DWORD cchUPN = static_cast<DWORD>(wcslen(user));
	const DWORD cbUPN = cchUPN * sizeof(wchar_t);
	const DWORD cchREALM = static_cast<DWORD>(wcslen(realm));
	const DWORD cbREALM = cchREALM * sizeof(wchar_t);

	typed_buffer_ptr<KERB_S4U_LOGON> s4uLogon(sizeof(KERB_S4U_LOGON) + cbUPN + cbREALM);
	
	s4uLogon->MessageType = KerbS4ULogon;
	s4uLogon->ClientUpn.Buffer = (wchar_t*)(s4uLogon.bytes() + sizeof(KERB_S4U_LOGON));
	CopyMemory(s4uLogon->ClientUpn.Buffer, user, cbUPN);
	s4uLogon->ClientUpn.Length = (USHORT)cbUPN;
	s4uLogon->ClientUpn.MaximumLength = (USHORT)cbUPN;  
	
	s4uLogon->ClientRealm.Buffer = (wchar_t*)(s4uLogon.bytes() + cbUPN + sizeof(KERB_S4U_LOGON));
	memcpy(s4uLogon->ClientRealm.Buffer, realm, cbREALM);
	s4uLogon->ClientRealm.Length = (USHORT)cbREALM;
	s4uLogon->ClientRealm.MaximumLength = (USHORT)cbREALM;

	TOKEN_SOURCE tokenSource;
	AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);
	
	strcpy_s(tokenSource.SourceName, 8, "NtLmSsp");
	LSA_STRING originName;
	InitLsaString(&originName, "S4U"); 
	void* profile = 0;
	DWORD cbProfile = 0;
	LUID logonId;	
	QUOTA_LIMITS quotaLimits;
	NTSTATUS subStatus;

	ScopedHandle htok;

	TestError(LsaLogonUser(hlsa, &originName, type, authnPkg, 
		s4uLogon, static_cast<ULONG>(s4uLogon.size()), 0,
		&tokenSource, &profile, &cbProfile, &logonId, htok.GetBuffer(),
		&quotaLimits, &subStatus));  

	LsaFreeReturnBuffer(profile);
	LsaClose(hlsa);

	return htok;
}

HandleUtils::NativeHandle^ LogonS4U(System::String^ user, System::String^ realm, SECURITY_LOGON_TYPE type)
{
	pin_ptr<const wchar_t> user_p = PtrToStringChars(user);
	pin_ptr<const wchar_t> realm_p = PtrToStringChars(realm);

	ScopedHandle handle = s4uLogon(user_p, realm_p, type);

	return gcnew HandleUtils::NativeHandle(System::IntPtr(handle.Detach()));
}