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
#include <windows.h>
#include <stdio.h>
#include <sddl.h>
#include <vcclr.h>
#include <string>
#include <AccCtrl.h>
#include <AclAPI.h>
#include <vector>
#include "ScopedHandle.h"
#include "HandleUtils.h"
#include "WindowsInternals.h"
#include "typed_buffer.h"
#include "SecurityInformationImpl.h"
#include "UserToken.h"

#pragma comment(lib, "user32.lib")

std::vector<unsigned char> GetTokenInfo(HANDLE hToken, TOKEN_INFORMATION_CLASS tokenClass);

namespace HandleUtils {
	using namespace System::Collections::Generic;
	using namespace System::Threading;

	List<HandleEntry^>^ NativeBridge::GetHandlesForPid(int pid)
	{
		return GetHandlesForPid(pid, false);
	}

	static bool QueryObjectNameInternal(HANDLE dupHandle, LPVOID buffer, SIZE_T bufferLen)
	{
		ULONG returnLength;

		memset(buffer, 0, bufferLen);

		_NtQueryObject NtQueryObject = (_NtQueryObject)
			GetNtProcAddress("NtQueryObject");

		if (NtQueryObject(dupHandle, ObjectNameInformation, nullptr, 0, &returnLength) == STATUS_INFO_LENGTH_MISMATCH)
		{
			typed_buffer_ptr<UNICODE_STRING> objectNameInfo(returnLength);

			if (NT_SUCCESS(NtQueryObject(
				dupHandle,
				ObjectNameInformation,
				objectNameInfo,
				(ULONG)objectNameInfo.size(),
				&returnLength
				)))
			{
				if (objectNameInfo->Length > 0)
				{
					SIZE_T maxLen = objectNameInfo->Length > bufferLen ? bufferLen : objectNameInfo->Length;

					memcpy(buffer, objectNameInfo->Buffer, maxLen);
				}
			}
		}

		return true;
	}

	ref class QueryStructure
	{
	public:

		HANDLE dupHandle;
		String^ name;

		void RunThread()
		{
			array<unsigned char>^ buf = gcnew array<unsigned char>(0x10000);

			pin_ptr<unsigned char> p = &buf[0];

			name = "";

			if (QueryObjectNameInternal(dupHandle, p, buf->Length))
			{
				name = gcnew String(reinterpret_cast<wchar_t*>(p));
			}
		}
	};

	String^ QueryObjectName(HANDLE h)
	{
		WCHAR* buf = new WCHAR[32768];
		String^ ret = "";

		if (QueryObjectNameInternal(h, buf, 32768 * sizeof(WCHAR)))
		{
			ret = gcnew String(buf);
		}

		delete[] buf;

		return ret;
	}

	String^ QueryObjectNameAsync(HANDLE h)
	{
		QueryStructure^ query = gcnew QueryStructure();

		query->dupHandle = h;

		Thread^ t = gcnew Thread(gcnew ThreadStart(query, &QueryStructure::RunThread));
		t->IsBackground = true;
		t->Start();
		t->Join(1000);

		return query->name;
	}

	typedef BOOL(*fGetSecurity)(HANDLE, PSECURITY_DESCRIPTOR, DWORD, LPDWORD);

	array<unsigned char>^ GetSecurityDescriptorGeneric(HANDLE h, fGetSecurity fgs)
	{
		array<unsigned char>^ ret = nullptr;
		ScopedHandle dupHandle;

		if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), dupHandle.GetBuffer(), READ_CONTROL, FALSE, 0))
		{
			if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), dupHandle.GetBuffer(), 0, FALSE, DUPLICATE_SAME_ACCESS))
			{
				dupHandle.Reset(nullptr);
			}
		}

		if (dupHandle.IsValid())
		{
			DWORD lengthNeeded = 0;
			if (!fgs(dupHandle,
				nullptr, 0, &lengthNeeded) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				ret = gcnew array<unsigned char>(lengthNeeded);

				pin_ptr<unsigned char> p = &ret[0];

				if (!fgs(dupHandle,
					reinterpret_cast<PSECURITY_DESCRIPTOR>(p), lengthNeeded, &lengthNeeded))
				{
					ret = nullptr;
				}
			}
		}

		return ret;
	}

	BOOL GetKOS(HANDLE h, PSECURITY_DESCRIPTOR psd, DWORD length, LPDWORD lengthNeeded)
	{
		return GetKernelObjectSecurity(h, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
			psd, length, lengthNeeded);
	}

	BOOL GetUOS(HANDLE h, PSECURITY_DESCRIPTOR psd, DWORD length, LPDWORD lengthNeeded)
	{
		SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
		return GetUserObjectSecurity(h, &si, psd, length, lengthNeeded);
	}

	SE_OBJECT_TYPE NameToObjectType(String^ type)
	{
		type = type->ToLower();

		if (type->Equals("file"))
		{
			return SE_FILE_OBJECT;
		}
		else if (type->Equals("windowstation") || type->Equals("desktop"))
		{
			return SE_WINDOW_OBJECT;
		}
		else if (type->Equals("key"))
		{
			return SE_REGISTRY_KEY;
		}
		else
		{
			// Make an assumption that it's a kernel object 
			return SE_KERNEL_OBJECT;
		}
	}

	array<unsigned char>^ GetSecurityDescriptor(HANDLE h, System::String^ typeName)
	{
		SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
		SE_OBJECT_TYPE type = NameToObjectType(typeName);
		PSECURITY_DESCRIPTOR psd;

		HANDLE dupHandle = nullptr;

		if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dupHandle, READ_CONTROL, FALSE, 0))
		{
			if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
			{
				return gcnew array<unsigned char>(0);
			}
		}

		DWORD status = GetSecurityInfo(dupHandle, type, si, nullptr, nullptr, nullptr, nullptr, &psd);
		if (status == 0)
		{
			array<unsigned char>^ ret = gcnew array<unsigned char>(GetSecurityDescriptorLength(psd));

			pin_ptr<unsigned char> p = &ret[0];

			memcpy(p, psd, ret->Length);

			LocalFree(psd);

			return ret;
		}
		else
		{
			return gcnew array<unsigned char>(0);
		}
	}

	array<unsigned char>^ NativeBridge::GetNamedSecurityDescriptor(System::String^ name, System::String^ typeName)
	{
		SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;

		pin_ptr<const wchar_t> pname = PtrToStringChars(name);
		PSECURITY_DESCRIPTOR psd;

		DWORD status = GetNamedSecurityInfoW(pname, NameToObjectType(typeName), si, nullptr, nullptr, nullptr, nullptr, &psd);
		if (status == 0)
		{
			array<unsigned char>^ ret = gcnew array<unsigned char>(GetSecurityDescriptorLength(psd));

			pin_ptr<unsigned char> p = &ret[0];

			memcpy(p, psd, ret->Length);

			LocalFree(psd);

			return ret;
		}
		else
		{
			return gcnew array<unsigned char>(0);
		}
	}

	array<unsigned char>^ GetSecurityDescriptor(HANDLE h)
	{
		array<unsigned char>^ ret = GetSecurityDescriptorGeneric(h, GetKOS);

		if (ret == nullptr)
		{
			ret = GetSecurityDescriptorGeneric(h, GetUOS);
		}

		return ret;
	}

	array<unsigned char>^ NativeBridge::GetSecurityDescriptorForHandle(NativeHandle^ handle)
	{
		return GetSecurityDescriptor(handle->DangerousGetHandle().ToPointer());
	}

	System::String^ NativeBridge::GetStringSecurityDescriptor(array<unsigned char>^ sd)
	{
		System::String^ ret = "";

		if ((sd != nullptr) && (sd->Length > 0))
		{
			pin_ptr<unsigned char> p = &sd[0];
			LPWSTR sddl;

			if (ConvertSecurityDescriptorToStringSecurityDescriptor(reinterpret_cast<PSECURITY_DESCRIPTOR>(p),
				SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
				&sddl, nullptr))
			{
				ret = gcnew System::String(sddl);

				LocalFree(sddl);
			}
		}

		return ret;
	}

	BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
	{
		TOKEN_PRIVILEGES tp;
		LUID luid;

		if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());			
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (bEnablePrivilege)
		{
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		}
		else
		{
			tp.Privileges[0].Attributes = 0;
		}

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
		{
			return FALSE;
		}

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			return FALSE;
		}

		return TRUE;
	}

	bool NativeBridge::EnablePrivilege(String^ privname, bool enable)
	{
		try
		{
			ScopedHandle hToken;
			::OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, hToken.GetBuffer());

			pin_ptr<const wchar_t> pname = PtrToStringChars(privname);

			return SetPrivilege(hToken, pname, enable) == TRUE;
		}
		catch (System::ComponentModel::Win32Exception^)
		{
			return false;
		}
	}

	String^ QueryProcessName(HANDLE h)
	{
		ScopedHandle dupHandle;

		if (DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(),
			dupHandle.GetBuffer(), PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0))
		{
			return String::Format("process:{0}", GetProcessId(dupHandle));
		}
		else
		{
			return "";
		}
	}

	String^ QueryThreadName(HANDLE h)
	{
		HANDLE dupHandle;

		if (DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dupHandle, THREAD_QUERY_LIMITED_INFORMATION, FALSE, 0))
		{
			return String::Format("thread:{0}", GetThreadId(dupHandle));
		}
		else
		{
			return "";
		}
	}

	typed_buffer_ptr<OBJECT_TYPE_INFORMATION> GetHandleTypeInfo(HANDLE h)
	{
		_NtQueryObject NtQueryObject = (_NtQueryObject)
			GetNtProcAddress("NtQueryObject");
		typed_buffer_ptr<OBJECT_TYPE_INFORMATION> objectTypeInfo(0x1000);

		/* Query the object type. */
		if (!NT_SUCCESS(NtQueryObject(
			h,
			ObjectTypeInformation,
			objectTypeInfo,
			(ULONG)objectTypeInfo.size(),
			NULL
			)))
		{
			objectTypeInfo.reset(0);
		}

		return objectTypeInfo;
	}

	ScopedHandle OpenProcessWithDebugPriv(DWORD AccessMask, int pid)
	{
		try
		{
			NativeBridge::EnablePrivilege(SE_DEBUG_NAME, true);

			ScopedHandle handle(::OpenProcess(AccessMask, FALSE, pid), false);

			return handle;
		}
		finally
		{
			NativeBridge::EnablePrivilege(SE_DEBUG_NAME, false);
		}
	}

	ScopedHandle OpenProcessTokenWithBackupPriv(HANDLE hProcess, DWORD AccessMask)
	{
		try
		{
			NativeBridge::EnablePrivilege(SE_BACKUP_NAME, true);

			ScopedHandle handle;
			
			if (!::OpenProcessToken(hProcess, AccessMask, handle.GetBuffer()))
			{
				throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
			}

			return handle;
		}
		finally
		{
			NativeBridge::EnablePrivilege(SE_BACKUP_NAME, false);
		}
	}

	List<HandleEntry^>^ NativeBridge::GetHandlesForPid(int pid, bool noquery)
	{
		try
		{
			_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
				GetNtProcAddress("NtQuerySystemInformation");
			_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)
				GetNtProcAddress("NtDuplicateObject");
			_NtQueryObject NtQueryObject = (_NtQueryObject)
				GetNtProcAddress("NtQueryObject");
			NTSTATUS status;

			ScopedHandle processHandle = OpenProcessWithDebugPriv(PROCESS_DUP_HANDLE, pid);
			ULONG i;
			List<HandleEntry^>^ ret = gcnew List<HandleEntry^>();
			
			typed_buffer_ptr<SYSTEM_HANDLE_INFORMATION> handleInfo(0x10000);

			/* NtQuerySystemInformation won't give us the correct buffer size,
			so we guess by doubling the buffer size. */
			while ((status = NtQuerySystemInformation(
				SystemHandleInformation,
				handleInfo,
				(ULONG)handleInfo.size(),
				nullptr
				)) == STATUS_INFO_LENGTH_MISMATCH)
			{
				handleInfo.reset(handleInfo.size() * 2);
			}

			/* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
			if (!NT_SUCCESS(status))
			{
				throw gcnew InvalidOperationException("NtQuerySystemInformation failed");
			}

			for (i = 0; i < handleInfo->HandleCount; i++)
			{
				HandleEntry^ entry = gcnew HandleEntry();
				SYSTEM_HANDLE handle = handleInfo->Handles[i];
				ScopedHandle dupHandle;

				/* Check if this handle belongs to the PID the user specified. */
				if (handle.ProcessId != pid)
					continue;

				entry->Handle = IntPtr(handle.Handle);
				entry->TypeName = "UnknownType";
				entry->Object = IntPtr(handle.Object);
				entry->Flags = handle.Flags;
				entry->GrantedAccess = handle.GrantedAccess;
				entry->ProcessId = handle.ProcessId;
				entry->ObjectTypeNumber = handle.ObjectTypeNumber;
				entry->ObjectName = "(unknown)";

				if (NT_SUCCESS(NtDuplicateObject(
					processHandle,
					reinterpret_cast<HANDLE>(handle.Handle),
					GetCurrentProcess(),
					dupHandle.GetBuffer(),
					0,
					0,
					0
					)))
				{
					typed_buffer_ptr<OBJECT_TYPE_INFORMATION> objectTypeInfo(0x1000);

					/* Query the object type. */
					if (!NT_SUCCESS(NtQueryObject(
						dupHandle,
						ObjectTypeInformation,
						objectTypeInfo,
						(ULONG)objectTypeInfo.size(),
						NULL
						)))
					{
						continue;
					}

					entry->TypeName = UnicodeNameToString(objectTypeInfo->Name);
					entry->SecurityDescriptor = GetSecurityDescriptor(dupHandle, entry->TypeName);
					entry->StringSecurityDescriptor = GetStringSecurityDescriptor(entry->SecurityDescriptor);

					if (!noquery)
					{
						if (entry->TypeName->Equals("File"))
						{
							entry->ObjectName = QueryObjectNameAsync(dupHandle);
						}
						else
						{
							if (entry->TypeName->Equals("Process"))
							{
								entry->ObjectName = QueryProcessName(dupHandle);
							}
							else if (entry->TypeName->Equals("Thread"))
							{
								entry->ObjectName = QueryThreadName(dupHandle);
							}
							else if (entry->TypeName->Equals("Token"))
							{
								NativeHandle^ handle = gcnew NativeHandle(IntPtr(dupHandle), true);
								TokenLibrary::UserToken^ token = gcnew TokenLibrary::UserToken(handle->Duplicate(MAXIMUM_ALLOWED));
								try
								{
									entry->ObjectName = String::Format("{0} {1}@{2:X}",
										token->GetTokenType(), token->GetUser()->GetName(), token->GetAuthenticationId());
								}
								catch(...)
								{
									entry->ObjectName = "Unknown Token";
								}
								finally
								{
									token->Close();
								}
							}
							else
							{
								entry->ObjectName = QueryObjectName(dupHandle);
							}
						}

						if (entry->ObjectName->Length > 0)
						{
							entry->HasName = true;
						}
						else
						{
							entry->ObjectName = "(unknown)";
						}
					}
				}

				ret->Add(entry);
			}

			return ret;
		}
		finally
		{
			EnablePrivilege(SE_DEBUG_NAME, false);
		}
	}

	NativeHandle^ NativeBridge::DuplicateHandleFromProcess(int pid, IntPtr handle, unsigned int desiredAccess, DuplicateHandleOptions options)
	{
		ScopedHandle hProcess(OpenProcessWithDebugPriv(PROCESS_DUP_HANDLE, pid));

		if (!hProcess.IsValid())
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}

		HANDLE hResult;

		if (!::DuplicateHandle(hProcess, reinterpret_cast<HANDLE>(handle.ToPointer()), ::GetCurrentProcess(),
			&hResult, static_cast<int>(desiredAccess), FALSE, static_cast<int>(options)))
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}

		return gcnew NativeHandle(IntPtr(hResult));
	}

	NativeHandle^ NativeBridge::DuplicateHandleFromProcess(HandleEntry^ handle, unsigned int desiredAccess, DuplicateHandleOptions options)
	{
		return DuplicateHandleFromProcess(handle->ProcessId, handle->Handle, desiredAccess, options);
	}

	NativeMappedFile^ MapFileCommon(HANDLE sectionHandle, bool writable)
	{
		DWORD dwAccess = FILE_MAP_READ;
		if (writable)
		{
			dwAccess |= FILE_MAP_WRITE;
		}

		LPVOID lpView = ::MapViewOfFile(sectionHandle, dwAccess, 0, 0, 0);
		if (lpView == nullptr)
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}

		MEMORY_BASIC_INFORMATION memInfo = { 0 };

		VirtualQuery((LPBYTE)lpView, &memInfo, sizeof(memInfo));

		SIZE_T size = memInfo.RegionSize - (static_cast<char*>(lpView)-static_cast<char*>(memInfo.AllocationBase));

		return gcnew NativeMappedFile(IntPtr(lpView), (long)size);
	}

	NativeMappedFile^ NativeBridge::MapFile(String^ name, bool writable)
	{
		OBJECT_ATTRIBUTES_WITH_NAME obj_attr(name, OBJ_CASE_INSENSITIVE, nullptr);
		ScopedHandle obj;
		
		DEFINE_NTDLL(NtOpenSection);

		ACCESS_MASK access = SECTION_MAP_READ | (writable ? SECTION_MAP_WRITE : 0);

		NTSTATUS status = fNtOpenSection(obj.GetBuffer(), access, &obj_attr);
		
		if (!NT_SUCCESS(status))
		{
			throw gcnew System::ComponentModel::Win32Exception(NtStatusToWin32(status));
		}

		return MapFileCommon(obj, writable);
	}

	NativeMappedFile^ NativeBridge::MapFile(NativeHandle^ sectionHandle, bool writable)
	{
		return MapFileCommon(sectionHandle->DangerousGetHandle().ToPointer(), writable);
	}

	long NativeBridge::GetSectionSize(NativeHandle^ sectionHandle)
	{
		NativeMappedFile^ map = MapFile(sectionHandle, false);

		__try
		{
			return map->GetSize();
		}
		__finally
		{
			map->Close();
		}
	}

	NTSTATUS OpenNameWithType(PHANDLE ph, ACCESS_MASK access, System::String^ name, System::String^ type)
	{
		String^ type_name = type->ToLowerInvariant();

		if (type_name->Equals("directory"))
		{
			// Reuse ObjectDirectory
			
		}

		return 0;
	}

	NativeHandle^ NativeBridge::CreateImpersonationToken(NativeHandle^ token, TokenSecurityLevel level)
	{		
		NativeHandle^ duphandle = token->Duplicate(TOKEN_DUPLICATE);
		
		try
		{
			ScopedHandle imptoken;

			if (!DuplicateTokenEx(duphandle->DangerousGetHandle().ToPointer(), TOKEN_ALL_ACCESS,
				nullptr, (SECURITY_IMPERSONATION_LEVEL)level, TokenImpersonation, imptoken.GetBuffer()))
			{
				throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
			}

			return gcnew NativeHandle(IntPtr(imptoken.Detach()));
		}
		finally
		{
			duphandle->Close();
		}
	}

	NativeHandle^ NativeBridge::CreatePrimaryToken(NativeHandle^ token)
	{
		NativeHandle^ duphandle = token->Duplicate(TOKEN_DUPLICATE);

		try
		{
			ScopedHandle imptoken;

			if (!DuplicateTokenEx(duphandle->DangerousGetHandle().ToPointer(), TOKEN_ALL_ACCESS, nullptr,
				SecurityImpersonation, TokenPrimary, imptoken.GetBuffer()))
			{
				throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
			}

			return gcnew NativeHandle(IntPtr(imptoken.Detach()));
		}
		finally
		{
			duphandle->Close();
		}
	}

	ImpersonateProcess^ NativeBridge::Impersonate(int pid, TokenSecurityLevel level)
	{
		NativeHandle^ token = OpenProcessToken(pid);

		try
		{
			return gcnew ImpersonateProcess(CreateImpersonationToken(token, level));
		}
		finally
		{
			delete token;
		}
	}

	ScopedHandle OpenObjectForNameAndType(System::String^ name, System::String^ type_name, ACCESS_MASK DesiredAccess)
	{
		OBJECT_ATTRIBUTES_WITH_NAME obj_attr(name, OBJ_CASE_INSENSITIVE, nullptr);
		ScopedHandle obj;
		NTSTATUS status;

		NativeBridge::EnablePrivilege(SE_BACKUP_NAME, true);

		try
		{
			String^ type = type_name->ToLower();

			if (type->Equals("directory"))
			{
				DEFINE_NTDLL(NtOpenDirectoryObject);

				status = fNtOpenDirectoryObject(obj.GetBuffer(), DesiredAccess, &obj_attr);
			}
			else if (type->Equals("event"))
			{
				DEFINE_NTDLL(NtOpenEvent);

				status = fNtOpenEvent(obj.GetBuffer(), DesiredAccess, &obj_attr);
			}
			else if (type->Equals("section"))
			{
				DEFINE_NTDLL(NtOpenSection);

				status = fNtOpenSection(obj.GetBuffer(), DesiredAccess, &obj_attr);
			}
			else if (type->Equals("mutant"))
			{
				DEFINE_NTDLL(NtOpenMutant);

				status = fNtOpenMutant(obj.GetBuffer(), DesiredAccess, &obj_attr);
			}
			else if (type->Equals("semaphore"))
			{
				DEFINE_NTDLL(NtOpenSemaphore);

				status = fNtOpenSemaphore(obj.GetBuffer(), DesiredAccess, &obj_attr);
			}
			else if (type->Equals("job"))
			{
				DEFINE_NTDLL(NtOpenJobObject);

				status = fNtOpenJobObject(obj.GetBuffer(), DesiredAccess, &obj_attr);
			}
			else if (type->Equals("symboliclink"))
			{
				DEFINE_NTDLL(NtOpenSymbolicLinkObject);

				status = fNtOpenSymbolicLinkObject(obj.GetBuffer(), DesiredAccess, &obj_attr);
			}
			else if (type->Equals("file") || type->Equals("device"))
			{
				DEFINE_NTDLL(NtOpenFile);
				IO_STATUS_BLOCK iostatus = { 0 };

				status = fNtOpenFile(obj.GetBuffer(), DesiredAccess, &obj_attr, &iostatus, 
					FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);
			}
			else
			{
				throw gcnew System::ArgumentException(String::Format("Can't read Security Descriptor for type {0}", type_name));
			}

			if (!NT_SUCCESS(status))
			{
				throw gcnew System::ComponentModel::Win32Exception(NtStatusToWin32(status));
			}

			return obj;
		}
		finally
		{
			NativeBridge::EnablePrivilege(SE_BACKUP_NAME, false);
		}
	}

	array<unsigned char>^ NativeBridge::GetSecurityDescriptorForNameAndType(System::String^ name, System::String^ type)
	{		
		return GetSecurityDescriptor(OpenObjectForNameAndType(name, type, READ_CONTROL));		
	}

	NativeHandle^ NativeBridge::OpenProcessToken(int pid)
	{
		ScopedHandle hProcess(OpenProcessWithDebugPriv(PROCESS_QUERY_INFORMATION, pid));
		if (!hProcess.IsValid())
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}

		ScopedHandle hToken;
		
		if (!::OpenProcessToken(hProcess, MAXIMUM_ALLOWED, hToken.GetBuffer()))
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}

		return gcnew NativeHandle(IntPtr(hToken.Detach()));
	}	

	NativeHandle^ NativeBridge::OpenProcessToken(NativeHandle^ process)
	{
		ScopedHandle hToken;

		if (!::OpenProcessToken(process->DangerousGetHandle().ToPointer(), MAXIMUM_ALLOWED, hToken.GetBuffer()))
		{
			return nullptr;
		}

		return gcnew NativeHandle(IntPtr(hToken.Detach()));
	}

	NativeHandle^ NativeBridge::OpenThreadToken(NativeHandle^ thread)
	{
		ScopedHandle hToken;

		if (!::OpenThreadToken(thread->DangerousGetHandle().ToPointer(), MAXIMUM_ALLOWED, FALSE, hToken.GetBuffer()))
		{
			return nullptr;
		}

		return gcnew NativeHandle(IntPtr(hToken.Detach()));
	}

	int NativeBridge::GetPidForProcess(NativeHandle^ handle)
	{
		return GetProcessId(handle->DangerousGetHandle().ToPointer());
	}

	int NativeBridge::GetTidForThread(NativeHandle^ handle)
	{
		return GetThreadId(handle->DangerousGetHandle().ToPointer());
	}

	unsigned int NativeBridge::GetAllowedAccess(NativeHandle^ token, ObjectTypeInfo^ type, unsigned int access_mask, array<unsigned char>^ sd)
	{
		DWORD granted = 0;
		GENERIC_MAPPING mapping;
		BOOL status;
		pin_ptr<unsigned char> psd = &sd[0];
		PRIVILEGE_SET PrivilegeSet = { 0 };
		DWORD dwPrivSetSize = sizeof(PRIVILEGE_SET);	
		ScopedHandle imptoken;

		if (!DuplicateTokenEx(token->DangerousGetHandle().ToPointer(), 0, nullptr, SecurityImpersonation, TokenImpersonation, imptoken.GetBuffer()))
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}

		mapping.GenericRead = type->GenericReadMapping;
		mapping.GenericWrite = type->GenericWriteMapping;
		mapping.GenericExecute = type->GenericExecuteMapping;
		mapping.GenericAll = type->GenericAllMapping;
		
		if (!AccessCheck(reinterpret_cast<PSECURITY_DESCRIPTOR>(psd), imptoken,
			access_mask, &mapping, &PrivilegeSet, &dwPrivSetSize, &granted, &status) || !status)
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}

		return granted;
	}

	unsigned int NativeBridge::GetGrantedAccess(NativeHandle^ handle)
	{
		DEFINE_NTDLL(NtQueryObject);		
		PUBLIC_OBJECT_BASIC_INFORMATION basic_info = { 0 };
		ULONG size_returned = 0;

		NTSTATUS status = fNtQueryObject(handle->DangerousGetHandle().ToPointer(), ObjectBasicInformation, &basic_info, sizeof(basic_info), &size_returned);
		if(status == 0)
		{
			return basic_info.GrantedAccess;
		}
		else
		{
			throw gcnew System::ComponentModel::Win32Exception(NtStatusToWin32(status));
		}
	}

	array<NativeHandle^>^ NativeBridge::GetProcesses()
	{
		try
		{
			NativeBridge::EnablePrivilege(SE_DEBUG_NAME, true);

			List<NativeHandle^>^ processes = gcnew List<NativeHandle^>();
			DEFINE_NTDLL(NtGetNextProcess);
			ScopedHandle handle;

			while (fNtGetNextProcess(handle, MAXIMUM_ALLOWED, 0, 0, handle.GetBuffer()) == 0)
			{
				processes->Add(gcnew NativeHandle(IntPtr(handle)));
			}

			// Detach last handle so it doesn't get closed
			(void)handle.Detach();

			return processes->ToArray();
		}
		finally
		{
			NativeBridge::EnablePrivilege(SE_DEBUG_NAME, false);
		}		
	}

	array<NativeHandle^>^ NativeBridge::GetThreadsForProcess(NativeHandle^ process)
	{
		try
		{
			NativeBridge::EnablePrivilege(SE_DEBUG_NAME, true);

			List<NativeHandle^>^ threads = gcnew List<NativeHandle^>();
			DEFINE_NTDLL(NtGetNextThread);
			ScopedHandle handle;

			while (fNtGetNextThread(process->DangerousGetHandle().ToPointer(), handle, MAXIMUM_ALLOWED, 0, 0, handle.GetBuffer()) == 0)
			{
				threads->Add(gcnew NativeHandle(IntPtr(handle)));
			}

			(void)handle.Detach();

			return threads->ToArray();
		}
		finally
		{
			NativeBridge::EnablePrivilege(SE_DEBUG_NAME, false);
		}
	}

	unsigned int NativeBridge::GetMaximumAccess(NativeHandle^ token, ObjectTypeInfo^ type, array<unsigned char>^ sd)
	{
		return GetAllowedAccess(token, type, MAXIMUM_ALLOWED, sd);
	}

	NativeHandle^ NativeBridge::CreateFileNative(System::String^ lpPath, unsigned int dwAccess,
		unsigned int dwAttributes, FileShareMode dwShareMode, FileCreateDisposition dwCreateDisposition, FileOpenOptions dwCreateOptions)
	{		
		OBJECT_ATTRIBUTES_WITH_NAME obj_attr(lpPath, OBJ_CASE_INSENSITIVE, nullptr);
		DEFINE_NTDLL(NtCreateFile);

		HANDLE hRet = NULL;
	
		IO_STATUS_BLOCK ioStatus = { 0 };

		NTSTATUS status = fNtCreateFile(&hRet, dwAccess, &obj_attr, &ioStatus, nullptr, 			
			dwAttributes, (unsigned int)dwShareMode, (unsigned int)dwCreateDisposition, (unsigned int)dwCreateOptions, nullptr, 0);

		if (NT_SUCCESS(status))
		{
			return gcnew NativeHandle(IntPtr(hRet));
		}
		else
		{
			throw gcnew System::ComponentModel::Win32Exception(NtStatusToWin32(status));
		}
	}	

	Type^ TypeNameToEnum(System::String^ name)
	{
		name = name->ToLower();

		if (name->Equals("directory"))
		{
			return DirectoryAccessRights::typeid;
		}
		else if (name->Equals("event"))
		{
			return EventAccessRights::typeid;
		}
		else if (name->Equals("section"))
		{
			return SectionAccessRights::typeid;
		}
		else if (name->Equals("mutant"))
		{
			return MutantAccessRights::typeid;
		}
		else if (name->Equals("semaphore"))
		{
			return SemaphoreAccessRights::typeid;
		}
		else if (name->Equals("job"))
		{
			return JobObjectAccessRights::typeid;
		}
		else if (name->Equals("symboliclink"))
		{
			return SymbolicLinkAccessRights::typeid;
		}
		else if (name->Equals("file") || name->Equals("device"))
		{
			return FileAccessRights::typeid;
		}
		else if (name->Equals("process"))
		{
			return ProcessAccessRights::typeid;
		}
		else if (name->Equals("token"))
		{
			return TokenAccessRights::typeid;
		}
		else
		{		
			throw gcnew ArgumentException("Can't get type for access rights");
		}	
	}

	static void AddEnumToDictionary(Dictionary<unsigned int, String^>^ access, Type^ enumType)
	{
		System::Text::RegularExpressions::Regex^ re = gcnew System::Text::RegularExpressions::Regex("([A-Z])");

		for each(unsigned int mask in System::Enum::GetValues(enumType))
		{
			access->Add(mask, re->Replace(Enum::GetName(enumType, mask), " $1")->Trim());
		}
	}

	static Dictionary<unsigned int, String^>^ GetMaskDictionary(Type^ enumType)
	{
		Dictionary<unsigned int, String^>^ access = gcnew Dictionary<unsigned int, String^>();

		AddEnumToDictionary(access, StandardAccessRights::typeid);
		AddEnumToDictionary(access, enumType);

		return access;
	}

	String^ NativeBridge::MapAccessToString(unsigned int access_mask, Type^ enumType)
	{
		if (access_mask == 0x1FFFFF)
		{
			return "Full Access";
		}

		Dictionary<unsigned int, String^>^ access = GetMaskDictionary(enumType);

		unsigned int unmapped = access_mask;

		List<String^>^ names = gcnew List<String^>();

		for each(KeyValuePair<unsigned int, String^> pair in access)
		{
			if ((pair.Key & unmapped) == pair.Key)
			{
				names->Add(pair.Value);
				unmapped &= ~pair.Key;
			}

			if (unmapped == 0)
			{
				break;
			}
		}		

		if (unmapped != 0)
		{
			names->Add(String::Format("0x{0:X}", unmapped));
		}
		else
		{
			if (names->Count == access->Count)
			{
				return "Full Access";
			}
		}

		return String::Join("|", names);
	}

	void NativeBridge::EditSecurity(System::IntPtr hwnd, System::String^ fullPath, System::String^ typeName, bool writeable)
	{
		ScopedHandle obj = HandleUtils::OpenObjectForNameAndType(fullPath, typeName, READ_CONTROL | (writeable ? WRITE_DAC : 0));
		int index = fullPath->LastIndexOf("\\");
		System::String^ object_name;
		if (index > 0)
		{
			object_name = fullPath->Substring(index + 1);
		}
		else
		{
			object_name = fullPath;
		}

		EditSecurity(hwnd, IntPtr(obj), object_name, typeName, writeable);
	}

	void NativeBridge::EditSecurity(System::IntPtr hwnd, System::IntPtr handle, System::String^ object_name, System::String^ typeName, bool writeable)
	{
		ScopedHandle obj(handle.ToPointer(), true);
		ObjectTypeInfo^ typeInfo = ObjectTypeInfo::GetTypeByName(typeName);

		GENERIC_MAPPING mapping;
		mapping.GenericAll = typeInfo->GenericAllMapping;
		mapping.GenericExecute = typeInfo->GenericExecuteMapping;
		mapping.GenericRead = typeInfo->GenericReadMapping;
		mapping.GenericWrite = typeInfo->GenericReadMapping;

		Dictionary<unsigned int, String^>^ access = GetMaskDictionary(TypeNameToEnum(typeName));

		SecurityInformationImpl* impl = new SecurityInformationImpl(object_name, obj, access, mapping);

		::EditSecurity(static_cast<HWND>(hwnd.ToPointer()), impl);

		impl->Release();
	}

	String^ NativeBridge::GetProcessPath(NativeHandle^ process)
	{
		array<unsigned char>^ ret = nullptr;
		ScopedHandle dupHandle;
		HANDLE hProcess = process->DangerousGetHandle().ToPointer();

		if (!DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), dupHandle.GetBuffer(), 
			PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0))
		{
			if (!DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), dupHandle.GetBuffer(), 0, FALSE, DUPLICATE_SAME_ACCESS))
			{
				dupHandle.Reset(nullptr);
			}
		}

		WCHAR buf[MAX_PATH];
		DWORD size = MAX_PATH;

		if (QueryFullProcessImageNameW(dupHandle, 0, buf, &size))
		{
			return gcnew String(buf);
		} 
		else
		{
			return "";
		}
	}

	NativeHandle^ NativeBridge::OpenProcess(int pid)
	{
		ScopedHandle hProcess(::OpenProcess(MAXIMUM_ALLOWED, FALSE, pid), false);

		if (hProcess.IsValid())
		{
			return gcnew NativeHandle(IntPtr(hProcess.Detach()));
		}
		else
		{
			throw gcnew System::ComponentModel::Win32Exception(::GetLastError());
		}
	}

	

	String^ NativeBridge::GetUserNameForToken(NativeHandle^ token)
	{
		auto user = GetTokenInfo(token->DangerousGetHandle().ToPointer(), TokenUser);
	
		if (user.size() > 0)
		{
			PTOKEN_USER puser = reinterpret_cast<PTOKEN_USER>(&user[0]);
			WCHAR name[256];
			WCHAR domain[256];
			SID_NAME_USE name_use;
			DWORD name_len = _countof(name);
			DWORD domain_len = _countof(domain);

			if (::LookupAccountSidW(nullptr, puser->User.Sid, name, &name_len, domain, &domain_len, &name_use))
			{				
				String^ fullname = gcnew String(domain);

				fullname += "\\";
				fullname += gcnew String(name);

				return fullname;
			}
		}

		return "";
	}
}