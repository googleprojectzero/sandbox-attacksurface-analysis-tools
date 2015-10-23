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
#include "SecurityInformationImpl.h"

HRESULT __stdcall SecurityInformationImpl::GetObjectInformation(PSI_OBJECT_INFO pObjectInfo)
{
	memset(pObjectInfo, 0, sizeof(SI_OBJECT_INFO));

	pObjectInfo->dwFlags = SI_READONLY | SI_ADVANCED;
	pObjectInfo->pszObjectName = const_cast<LPWSTR>(m_obj_name.c_str());

	return S_OK;
}

HRESULT __stdcall SecurityInformationImpl::GetSecurity(SECURITY_INFORMATION RequestedInformation,
	PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
	BOOL fDefault)
{
	DWORD length_needed;
	if (!GetKernelObjectSecurity(m_handle, RequestedInformation, nullptr, 0, &length_needed) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		PSECURITY_DESCRIPTOR psd = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(0, length_needed));

		if (GetKernelObjectSecurity(m_handle, RequestedInformation, psd, length_needed, &length_needed))
		{
			*ppSecurityDescriptor = psd;
			return S_OK;
		}
	}

	return E_ACCESSDENIED;
}

HRESULT __stdcall SecurityInformationImpl::SetSecurity(SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR pSecurityDescriptor)
{
	if (SetKernelObjectSecurity(m_handle, SecurityInformation, pSecurityDescriptor))
	{
		return S_OK;
	}
	else
	{
		return E_ACCESSDENIED;
	}
}

HRESULT __stdcall SecurityInformationImpl::GetAccessRights(const GUID* pguidObjectType,
	DWORD dwFlags, // SI_EDIT_AUDITS, SI_EDIT_PROPERTIES
	PSI_ACCESS *ppAccess,
	ULONG *pcAccesses,
	ULONG *piDefaultAccess)
{
	*ppAccess = &m_access_map[0];
	*pcAccesses = static_cast<ULONG>(m_access_map.size());
	*piDefaultAccess = 0;

	return S_OK;
}

HRESULT __stdcall SecurityInformationImpl::MapGeneric(const GUID *pguidObjectType,
	UCHAR *pAceFlags,
	ACCESS_MASK *pMask)
{
	MapGenericMask(pMask, &m_mapping);

	return S_OK;
}

HRESULT __stdcall SecurityInformationImpl::GetInheritTypes(PSI_INHERIT_TYPE *ppInheritTypes,
	ULONG *pcInheritTypes)
{
	ppInheritTypes = nullptr;
	*pcInheritTypes = 0;

	return S_OK;
}

HRESULT __stdcall SecurityInformationImpl::PropertySheetPageCallback(HWND hwnd, UINT uMsg, SI_PAGE_TYPE uPage)
{
	return S_OK;
}

