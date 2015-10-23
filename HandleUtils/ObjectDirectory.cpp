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
#include "ObjectDirectory.h"
#include "ObjectDirectoryEntry.h"
#include "WindowsInternals.h"
#include "HandleUtils.h"
#include "ScopedHandle.h"
#include "typed_buffer.h"

#include <vcclr.h>

namespace HandleUtils {

	using namespace System;
	using namespace System::Collections::Generic;

	void ObjectDirectory::PopulateEntries()
	{		
		bool readacl = true;
		this->_entries = gcnew List<ObjectDirectoryEntry^>();

		ScopedHandle obj_dir;

		OBJECT_ATTRIBUTES_WITH_NAME obj_attr(this->_orig_path, OBJ_CASE_INSENSITIVE, nullptr);

		DEFINE_NTDLL(NtOpenDirectoryObject);
		DEFINE_NTDLL(NtQueryDirectoryObject);

		NTSTATUS status = fNtOpenDirectoryObject(obj_dir.GetBuffer(), READ_CONTROL | DIRECTORY_QUERY, &obj_attr);
		if (status == STATUS_ACCESS_DENIED)
		{
			readacl = false;
			status = fNtOpenDirectoryObject(obj_dir.GetBuffer(), DIRECTORY_QUERY, &obj_attr);
		}

		if (!NT_SUCCESS(status))
		{
			throw gcnew System::ComponentModel::Win32Exception(NtStatusToWin32(status));
		}				

		if (readacl)
		{
			_sd = GetSecurityDescriptor(obj_dir);
			_sddl = NativeBridge::GetStringSecurityDescriptor(_sd);
		}
		else
		{
			_sd = gcnew array<unsigned char>(0);
			_sddl = "";
		}

		_full_path = QueryObjectName(obj_dir);
		if (String::IsNullOrWhiteSpace(_full_path))
		{
			_full_path = _orig_path;
		}

		ULONG context = 0;
		typed_buffer_ptr<DIRECTORY_BASIC_INFORMATION> dir_info(2048);
		ULONG length = 0;

		while ((status = fNtQueryDirectoryObject(obj_dir, dir_info, (ULONG)dir_info.size(), 
			TRUE, FALSE, &context, &length)) != STATUS_NO_MORE_ENTRIES)
		{
			if (!NT_SUCCESS(status))
			{
				throw gcnew System::ComponentModel::Win32Exception(NtStatusToWin32(status));
			}

			ObjectDirectoryEntry^ entry = gcnew ObjectDirectoryEntry(UnicodeNameToString(dir_info->ObjectName), UnicodeNameToString(dir_info->ObjectTypeName), this);

			this->_entries->Add(entry);
		}
	}

	ObjectDirectory::ObjectDirectory(System::String^ name) 		
	{		
		_orig_path = name;				
		PopulateEntries();		
	}

}