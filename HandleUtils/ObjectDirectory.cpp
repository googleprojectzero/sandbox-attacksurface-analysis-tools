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
#include "TokenLibrary.h"

#include <vcclr.h>
#include <memory>
#include <sddl.h>

namespace HandleUtils {

  using namespace System;
  using namespace System::Collections::Generic;
  using namespace System::Security::Principal;

  struct LocalFreeDeleter
  {
    typedef void* pointer;
    void operator()(void* p) {
      ::LocalFree(p);
    }
  };

  class BoundaryDescriptor
  {
  public:
    BoundaryDescriptor(String^ name)
      : boundary_desc_(nullptr) {
      pin_ptr<const wchar_t> pname = PtrToStringChars(name);
      boundary_desc_ = ::CreateBoundaryDescriptorW(pname, 0);
      if (!boundary_desc_)
        throw gcnew System::ComponentModel::Win32Exception();
    }

    ~BoundaryDescriptor() {
      if (boundary_desc_) {
        DeleteBoundaryDescriptor(boundary_desc_);
      }
    }

    void AddSid(String^ sid)
    {      
      pin_ptr<const wchar_t> psid = PtrToStringChars(sid);
      PSID p;      
      if (!::ConvertStringSidToSid(psid, &p))
        throw gcnew System::ComponentModel::Win32Exception();
      std::unique_ptr<void, LocalFreeDeleter> sid_buf = nullptr;
      sid_buf.reset(p);

      SID_IDENTIFIER_AUTHORITY il_id_auth = { {0,0,0,0,0,0x10} };      
      PSID_IDENTIFIER_AUTHORITY sid_id_auth = GetSidIdentifierAuthority(p);

      if (memcmp(il_id_auth.Value, sid_id_auth->Value, sizeof(il_id_auth.Value)) == 0)
      {
        if (!::AddIntegrityLabelToBoundaryDescriptor(&boundary_desc_, p))
          throw gcnew System::ComponentModel::Win32Exception();
      }
      else
      {
        if (!AddSIDToBoundaryDescriptor(&boundary_desc_, p))
          throw gcnew System::ComponentModel::Win32Exception();
      }
    }
    
    HANDLE boundry_desc() {
      return boundary_desc_;
    }

  private:
    HANDLE boundary_desc_;
  };

  NativeHandle^ ObjectDirectory::OpenPath(ObjectDirectory^ root, System::String^ path)
  {    
    ScopedHandle obj_dir;
    
    OBJECT_ATTRIBUTES_WITH_NAME obj_attr(path, OBJ_CASE_INSENSITIVE, 
      root != nullptr ? root->Handle->DangerousGetHandle().ToPointer() : nullptr);

    DEFINE_NTDLL(NtOpenDirectoryObject);

    NTSTATUS status = fNtOpenDirectoryObject(obj_dir.GetBuffer(), MAXIMUM_ALLOWED, &obj_attr);

    if (!NT_SUCCESS(status))
    {
      throw gcnew System::ComponentModel::Win32Exception(NtStatusToWin32(status));
    }

    return obj_dir.DetachAsNativeHandle();
  }

  NativeHandle^ ObjectDirectory::OpenNamespace(System::String^ path)
  {
    array<String^>^ parts = path->Split('@', 2);
    String^ obj_name = parts->Length > 1 ? parts[1] : parts[0];

    BoundaryDescriptor boundary(obj_name);

    if (parts->Length > 1)
    {
      for each (String^ sid in parts[0]->Split(':'))
      {
        boundary.AddSid(sid);
      }
    }

    String^ prefix = Guid::NewGuid().ToString();
    pin_ptr<const wchar_t> pprefix = PtrToStringChars(prefix);

    ScopedHandle ns(::OpenPrivateNamespaceW(boundary.boundry_desc(), pprefix), false);
    if (!ns.IsValid())
      throw gcnew System::ComponentModel::Win32Exception();
    
    return ns.DetachAsNativeHandle();
  }

	void ObjectDirectory::PopulateEntries()
	{		
		bool readacl = true;
		this->_entries = gcnew List<ObjectDirectoryEntry^>();    
    
    unsigned int granted_access = NativeBridge::GetGrantedAccess(_handle);

		if ((granted_access & READ_CONTROL) == READ_CONTROL)
		{
			_sd = GetSecurityDescriptor(_handle->DangerousGetHandle().ToPointer());
			_sddl = NativeBridge::GetStringSecurityDescriptor(_sd);
		}
		else
		{
			_sd = gcnew array<unsigned char>(0);
			_sddl = "";
		}

		_full_path = QueryObjectName(_handle->DangerousGetHandle().ToPointer());
		if (String::IsNullOrWhiteSpace(_full_path))
		{
			_full_path = _orig_path;
		}

    if ((granted_access & DIRECTORY_QUERY) != DIRECTORY_QUERY)
      return;

		ULONG context = 0;
		typed_buffer_ptr<DIRECTORY_BASIC_INFORMATION> dir_info(2048);
		ULONG length = 0;
    NTSTATUS status = 0;

    DEFINE_NTDLL(NtQueryDirectoryObject);

		while ((status = fNtQueryDirectoryObject(_handle->DangerousGetHandle().ToPointer(), 
      dir_info, (ULONG)dir_info.size(),
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

	ObjectDirectory::ObjectDirectory(ObjectDirectory^ root, System::String^ name)
	{		
    _orig_path = name;

    if (this->_orig_path->StartsWith("\\") || root != nullptr)
    {
      _handle = OpenPath(root, this->_orig_path);
    }
    else
    {
      _handle = OpenNamespace(this->_orig_path);
    }

		PopulateEntries();
	}

  ObjectDirectory^ ObjectDirectory::Duplicate()
  {
    ObjectDirectory^ ret = gcnew ObjectDirectory();
    ret->_sddl = _sddl;
    ret->_sd = (array<unsigned char>^)_sd->Clone();
    ret->_orig_path = _orig_path;
    ret->_full_path = _full_path;
    ret->_entries = gcnew  System::Collections::Generic::List<ObjectDirectoryEntry^>();
    for each(ObjectDirectoryEntry^ entry in _entries)
    {
      ret->_entries->Add(gcnew ObjectDirectoryEntry(entry->ObjectName, entry->TypeName, ret));
    }
    ret->_handle = _handle->Duplicate();
    return ret;
  }

}