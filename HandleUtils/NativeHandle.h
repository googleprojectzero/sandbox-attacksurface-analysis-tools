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

public ref class NativeHandle : public Microsoft::Win32::SafeHandles::SafeHandleZeroOrMinusOneIsInvalid
{
	static System::IntPtr DupHandle(System::IntPtr h, unsigned int access_rights, bool same_access)
	{
		HANDLE hDup;

		if (!::DuplicateHandle(GetCurrentProcess(), h.ToPointer(),
			GetCurrentProcess(), &hDup, access_rights, FALSE, same_access ? DUPLICATE_SAME_ACCESS : 0))
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}

		return System::IntPtr(hDup);
	}

protected:
	virtual bool ReleaseHandle() override {
		return ::CloseHandle(this->handle.ToPointer()) == TRUE;
	}

public:
	NativeHandle(System::IntPtr h) : NativeHandle(h, false) {
	}

	NativeHandle(System::IntPtr h, bool duplicate) : SafeHandleZeroOrMinusOneIsInvalid(false) {
		this->SetHandle(duplicate ? DupHandle(h, 0, true) : h);
	}

	NativeHandle::~NativeHandle()
	{
	}

	NativeHandle^ Duplicate()
	{
		return gcnew NativeHandle(DupHandle(this->DangerousGetHandle(), 0, true));
	}

	NativeHandle^ Duplicate(DWORD access_rights)
	{
		return gcnew NativeHandle(DupHandle(this->DangerousGetHandle(), access_rights, false));
	}
};

