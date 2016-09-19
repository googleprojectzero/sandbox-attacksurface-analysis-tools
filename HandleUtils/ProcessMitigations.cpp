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
#include "ProcessMitigations.h"
#include "typed_buffer.h"
#include "WindowsInternals.h"
#include <memory>

namespace TokenLibrary
{
	namespace
	{
		#define XProcessSignaturePolicy static_cast<PROCESS_MITIGATION_POLICY>(8)
		#define XProcessFontDisablePolicy static_cast<PROCESS_MITIGATION_POLICY>(9)
		#define XProcessImageLoadPolicy static_cast<PROCESS_MITIGATION_POLICY>(10)
		
		typedef struct _XPROCESS_MITIGATION_FONT_DISABLE_POLICY {
			DWORD DisableNonSystemFonts : 1;
			DWORD AuditNonSystemFontLoading : 1;
			DWORD ReservedFlags : 30;		
		} XPROCESS_MITIGATION_FONT_DISABLE_POLICY;

		typedef struct _XPROCESS_MITIGATION_IMAGE_LOAD_POLICY {			
			DWORD NoRemoteImages : 1;
			DWORD NoLowMandatoryLabelImages : 1;
			DWORD ReservedFlags : 30;
		} XPROCESS_MITIGATION_IMAGE_LOAD_POLICY;

		typedef decltype(::GetProcessMitigationPolicy)* GetProcessMitigationPolicyType;
				
		template<typename T> bool GetMitigationPolicy(HandleUtils::NativeHandle^ h, PROCESS_MITIGATION_POLICY policy, T& buffer)
		{
			GetProcessMitigationPolicyType GetProcessMitigationPolicyFunc =
				reinterpret_cast<GetProcessMitigationPolicyType>(GetProcAddress(
				GetModuleHandle(L"kernel32.dll"), "GetProcessMitigationPolicy"));
			if (GetProcessMitigationPolicyFunc)
			{
				HANDLE proc = h->DangerousGetHandle().ToPointer();
				return !!GetProcessMitigationPolicyFunc(proc, policy, &buffer, sizeof(T));
			}
			else
			{
				return false;
			}
		}
	}

	ProcessMitigations::ProcessMitigations(HandleUtils::NativeHandle^ process)
	{
    HandleUtils::NativeHandle^ h = process->Duplicate(PROCESS_QUERY_INFORMATION);
		try
		{
			PROCESS_MITIGATION_DEP_POLICY dep_policy;
			if (GetMitigationPolicy(h, ProcessDEPPolicy, dep_policy))
			{
				DisableAtlThunkEmulation = !!dep_policy.DisableAtlThunkEmulation;
				DepEnabled = !!dep_policy.Enable;
				DepPermanent = !!dep_policy.Permanent;
			}

			PROCESS_MITIGATION_ASLR_POLICY aslr_policy;
			if (GetMitigationPolicy(h, ProcessASLRPolicy, aslr_policy))
			{
				DisallowStrippedImages = aslr_policy.DisallowStrippedImages;
				EnableBottomUpRandomization = aslr_policy.EnableBottomUpRandomization;
				EnableForceRelocateImages = aslr_policy.EnableForceRelocateImages;
				EnableHighEntropy = aslr_policy.EnableHighEntropy;				
			}

			PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscall_policy;
			if (GetMitigationPolicy(h, ProcessSystemCallDisablePolicy, syscall_policy))
			{
				DisallowWin32kSystemCalls = syscall_policy.DisallowWin32kSystemCalls;
			}

			PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handle_policy;
			if (GetMitigationPolicy(h, ProcessStrictHandleCheckPolicy, handle_policy))
			{
				HandleExceptionsPermanentlyEnabled = handle_policy.HandleExceptionsPermanentlyEnabled;
				RaiseExceptionOnInvalidHandleReference = handle_policy.RaiseExceptionOnInvalidHandleReference;
			}

			XPROCESS_MITIGATION_FONT_DISABLE_POLICY font_policy;
			if (GetMitigationPolicy(h, XProcessFontDisablePolicy, font_policy))
			{
				DisableNonSystemFonts = font_policy.DisableNonSystemFonts;
				AuditNonSystemFontLoading = font_policy.AuditNonSystemFontLoading;
			}

			PROCESS_MITIGATION_DYNAMIC_CODE_POLICY code_policy;
			if (GetMitigationPolicy(h, ProcessDynamicCodePolicy, code_policy))
			{
				ProhibitDynamicCode = code_policy.ProhibitDynamicCode;
			}

			PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ext_policy;
			if (GetMitigationPolicy(h, ProcessExtensionPointDisablePolicy, ext_policy))
			{
				DisableExtensionPoints = ext_policy.DisableExtensionPoints;
			}

			// ProcessSignaturePolicy doesn't seem to actually work on Windows 8, use the NT form.
			DEFINE_NTDLL(NtQueryInformationProcess);
			HandleUtils::PROCESS_MITIGATION policy = {};
			policy.MitigationType = ProcessSignaturePolicy;
			ULONG ReturnedLength = 0;
			if (NT_SUCCESS(fNtQueryInformationProcess(h->DangerousGetHandle().ToPointer(), 
				HandleUtils::ProcessMitigation, &policy, sizeof(policy), &ReturnedLength)))
			{
				MicrosoftSignedOnly = policy.Result & 1;
				StoreSignedOnly = (policy.Result & 2) == 2;
				SignedMitigationOptIn = (policy.Result & 4) == 4;
			}

			XPROCESS_MITIGATION_IMAGE_LOAD_POLICY image_policy;
			if (GetMitigationPolicy(h, XProcessImageLoadPolicy, image_policy))
			{
				NoRemoteImages = image_policy.NoRemoteImages;
				NoLowMandatoryLabelImages = image_policy.NoLowMandatoryLabelImages;
			}
		}
		finally
		{
			h->Close();
		}
	}
}