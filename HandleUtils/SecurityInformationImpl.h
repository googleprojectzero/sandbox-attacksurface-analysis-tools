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

#pragma once

#include <Windows.h>
#include <Aclui.h>
#include <string>
#include <vector>
#include <vcclr.h>
#include "ScopedHandle.h"

class SecurityInformationImpl : public ISecurityInformation
{
	LONG m_lRefCount;	
	GENERIC_MAPPING m_mapping;	
	std::vector<std::wstring> m_names;
	std::vector<SI_ACCESS> m_access_map;
	std::wstring m_obj_name;
	ScopedHandle m_handle;

	SecurityInformationImpl(const SecurityInformationImpl&) = delete;
	SecurityInformationImpl& operator=(const SecurityInformationImpl&) = delete;

public:
	SecurityInformationImpl(System::String^ obj_name, const ScopedHandle& handle,
		System::Collections::Generic::Dictionary<unsigned int, System::String^>^ names, 
		const GENERIC_MAPPING& mapping) : m_lRefCount(1), m_mapping(mapping), m_handle(handle)
	{		
		pin_ptr<const wchar_t> pobj_name = PtrToStringChars(obj_name);
		m_obj_name = pobj_name;

		m_names.resize(names->Count);
		m_access_map.resize(names->Count);
		int i = 0;

		for each(auto pair in names)
		{
			pin_ptr<const wchar_t> pname = PtrToStringChars(pair.Value);			

			m_names[i] = pname;

			SI_ACCESS& si = m_access_map[i];
						
			si.mask = pair.Key;
			si.pszName = m_names[i].c_str();
			si.dwFlags = SI_ACCESS_SPECIFIC | SI_ACCESS_GENERAL;				

			i++;
		}		
	}

	~SecurityInformationImpl()
	{
	}

	HRESULT __stdcall QueryInterface(REFIID riid, LPVOID *ppvObj)
	{
		
		if (riid == __uuidof(IUnknown))
		{
			*ppvObj = this;
		}
		else if (riid == __uuidof(ISecurityInformation))
		{		
			*ppvObj = this;
		}
		else
		{
			*ppvObj = NULL;
			return E_NOINTERFACE;
		}

		AddRef();
		return NOERROR;
	}

	ULONG __stdcall AddRef()
	{		
		return InterlockedIncrement(&m_lRefCount);
	}

	ULONG __stdcall Release()
	{
		ULONG  ulCount = InterlockedDecrement(&m_lRefCount);

		if (0 == ulCount)
		{
			delete this;
		}

		return ulCount;
	}

	// *** ISecurityInformation methods ***
	STDMETHOD(GetObjectInformation) (PSI_OBJECT_INFO pObjectInfo);
	STDMETHOD(GetSecurity) (SECURITY_INFORMATION RequestedInformation,
		PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
		BOOL fDefault);
	STDMETHOD(SetSecurity) (SECURITY_INFORMATION SecurityInformation,
		PSECURITY_DESCRIPTOR pSecurityDescriptor);
	STDMETHOD(GetAccessRights) (const GUID* pguidObjectType,
		DWORD dwFlags, // SI_EDIT_AUDITS, SI_EDIT_PROPERTIES
		PSI_ACCESS *ppAccess,
		ULONG *pcAccesses,
		ULONG *piDefaultAccess);
	STDMETHOD(MapGeneric) (const GUID *pguidObjectType,
		UCHAR *pAceFlags,
		ACCESS_MASK *pMask);
	STDMETHOD(GetInheritTypes) (PSI_INHERIT_TYPE *ppInheritTypes,
		ULONG *pcInheritTypes);
	STDMETHOD(PropertySheetPageCallback)(HWND hwnd, UINT uMsg, SI_PAGE_TYPE uPage);	
};

