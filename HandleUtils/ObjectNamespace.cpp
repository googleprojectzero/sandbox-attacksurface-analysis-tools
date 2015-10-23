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
#include "ObjectNamespace.h"
#include "WindowsInternals.h"
#include <vcclr.h>

namespace HandleUtils {

	ObjectNamespace::ObjectNamespace()
	{
	}

	ObjectDirectory^ ObjectNamespace::OpenDirectory(System::String^ object_path)
	{		
		return gcnew ObjectDirectory(object_path);	
	}	

	ObjectDirectory^ ObjectNamespace::OpenSessionDirectory(int sessionid)
	{
		return gcnew ObjectDirectory(System::String::Format("\\Sessions\\{0}", sessionid));
	}

	ObjectDirectory^ ObjectNamespace::OpenSessionDirectory()
	{
		DWORD sessionId;

		if (ProcessIdToSessionId(GetCurrentProcessId(), &sessionId))
		{
			return OpenSessionDirectory(sessionId);
		}
		else
		{
			throw gcnew System::ComponentModel::Win32Exception(GetLastError());
		}		
	}

	System::String^ ObjectNamespace::ReadSymlink(System::String^ symlink_path)
	{		
		OBJECT_ATTRIBUTES_WITH_NAME obj_attr(symlink_path, OBJ_CASE_INSENSITIVE, nullptr);

		DEFINE_NTDLL(NtOpenSymbolicLinkObject);
		DEFINE_NTDLL(NtQuerySymbolicLinkObject);

		HANDLE link_handle;

		NTSTATUS status = fNtOpenSymbolicLinkObject(&link_handle, SYMBOLIC_LINK_QUERY, &obj_attr);

		if (!NT_SUCCESS(status))
		{
			throw gcnew System::ComponentModel::Win32Exception(NtStatusToWin32(status));
		}

		ULONG length;

		UNICODE_STRING_WITH_BUF link_target(16 * 1024);

		status = fNtQuerySymbolicLinkObject(link_handle, &link_target, &length);

		if (link_handle != nullptr)
		{
			::CloseHandle(link_handle);
		}

		if (status != STATUS_SUCCESS)
		{
			throw gcnew System::ComponentModel::Win32Exception(NtStatusToWin32(status));
		}

		return link_target.ToString();
	}
}