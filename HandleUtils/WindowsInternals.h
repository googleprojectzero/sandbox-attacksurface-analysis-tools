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

#include <string>
#include <vector>
#include <vcclr.h>
#include <strsafe.h>

namespace HandleUtils {

#include <Windows.h>
#include <ntstatus.h>
#include <winternl.h>

	typedef NTSTATUS(NTAPI* _NtCreateDirectoryObject)(PHANDLE DirHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
	typedef NTSTATUS(NTAPI* _NtCreateDirectoryObjectEx)(PHANDLE DirHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE BaseHandle, BOOLEAN Flag);
	typedef NTSTATUS(NTAPI* _NtOpenDirectoryObject)(PHANDLE DirHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
	typedef VOID(NTAPI *_RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
	typedef NTSTATUS(NTAPI *_NtCreateFile)(_Out_ PHANDLE FileHandle,
		_In_      ACCESS_MASK DesiredAccess,
		_In_      POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_     PIO_STATUS_BLOCK IoStatusBlock,
		_In_opt_  PLARGE_INTEGER AllocationSize,
		_In_      ULONG FileAttributes,
		_In_      ULONG ShareAccess,
		_In_      ULONG CreateDisposition,
		_In_      ULONG CreateOptions,
		_In_opt_  PVOID EaBuffer,
		_In_      ULONG EaLength);

#define SYMBOLIC_LINK_QUERY		 (0x1)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYMBOLIC_LINK_QUERY)

	typedef NTSTATUS(NTAPI* _NtOpenSymbolicLinkObject)(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
	typedef NTSTATUS(NTAPI* _NtQuerySymbolicLinkObject)(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength);
	typedef NTSTATUS(NTAPI* _NtCreateSymbolicLinkObject)(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING TargetName);
	typedef NTSTATUS(NTAPI* _NtOpenFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
		ULONG ShareAccess,
		ULONG OpenOptions);

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
#define ObjectAllInformation 3

	typedef NTSTATUS(NTAPI * _NtQuerySystemInformation)(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
		);
	typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
		HANDLE SourceProcessHandle,
		HANDLE SourceHandle,
		HANDLE TargetProcessHandle,
		PHANDLE TargetHandle,
		ACCESS_MASK DesiredAccess,
		ULONG Attributes,
		ULONG Options
		);
	typedef NTSTATUS(NTAPI *_NtQueryObject)(
		HANDLE ObjectHandle,
		ULONG ObjectInformationClass,
		PVOID ObjectInformation,
		ULONG ObjectInformationLength,
		PULONG ReturnLength
		);

	typedef ULONG(NTAPI* _RtlNtStatusToDosError)(NTSTATUS status);

	typedef struct _SYSTEM_HANDLE
	{
		ULONG ProcessId;
		BYTE ObjectTypeNumber;
		BYTE Flags;
		USHORT Handle;
		PVOID Object;
		ACCESS_MASK GrantedAccess;
	} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION
	{
		ULONG HandleCount;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

	typedef enum _POOL_TYPE
	{
		NonPagedPool,
		PagedPool,
		NonPagedPoolMustSucceed,
		DontUseThisType,
		NonPagedPoolCacheAligned,
		PagedPoolCacheAligned,
		NonPagedPoolCacheAlignedMustS
	} POOL_TYPE, *PPOOL_TYPE;

	typedef struct _OBJECT_TYPE_INFORMATION
	{
		UNICODE_STRING Name;
		ULONG TotalNumberOfObjects;
		ULONG TotalNumberOfHandles;
		ULONG TotalPagedPoolUsage;
		ULONG TotalNonPagedPoolUsage;
		ULONG TotalNamePoolUsage;
		ULONG TotalHandleTableUsage;
		ULONG HighWaterNumberOfObjects;
		ULONG HighWaterNumberOfHandles;
		ULONG HighWaterPagedPoolUsage;
		ULONG HighWaterNonPagedPoolUsage;
		ULONG HighWaterNamePoolUsage;
		ULONG HighWaterHandleTableUsage;
		ULONG InvalidAttributes;
		GENERIC_MAPPING GenericMapping;
		ULONG ValidAccess;
		BOOLEAN SecurityRequired;
		BOOLEAN MaintainHandleCount;
		USHORT MaintainTypeList;
		POOL_TYPE PoolType;
		ULONG PagedPoolUsage;
		ULONG NonPagedPoolUsage;
	} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

	typedef struct _OBJECT_ALL_TYPES_INFORMATION {
		ULONG NumberOfTypes;
		OBJECT_TYPE_INFORMATION TypeInformation[1];
	} OBJECT_ALL_TYPES_INFORMATION, *POBJECT_ALL_TYPES_INFORMATION;

	typedef struct _DIRECTORY_BASIC_INFORMATION
	{
		UNICODE_STRING ObjectName;
		UNICODE_STRING ObjectTypeName;
		BYTE data[1];
	} DIRECTORY_BASIC_INFORMATION, *PDIRECTORY_BASIC_INFORMATION;

	typedef NTSTATUS(NTAPI* _NtQueryDirectoryObject)(HANDLE DirHandle, PVOID Buffer, ULONG BufferLength,
		BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength);

	typedef NTSTATUS(NTAPI* _NtOpenEvent)(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes);

	typedef NTSTATUS(NTAPI *_NtOpenSection)(
		_Out_  PHANDLE SectionHandle,
		_In_   ACCESS_MASK DesiredAccess,
		_In_   POBJECT_ATTRIBUTES ObjectAttributes
		);

	typedef NTSTATUS(NTAPI *_NtOpenMutant)(
		_Out_  PHANDLE Handle,
		_In_   ACCESS_MASK DesiredAccess,
		_In_   POBJECT_ATTRIBUTES ObjectAttributes
		);

	typedef NTSTATUS(NTAPI *_NtOpenSemaphore)(
		_Out_  PHANDLE Handle,
		_In_   ACCESS_MASK DesiredAccess,
		_In_   POBJECT_ATTRIBUTES ObjectAttributes
		);

	typedef NTSTATUS(NTAPI *_NtOpenJobObject)(
		_Out_  PHANDLE Handle,
		_In_   ACCESS_MASK DesiredAccess,
		_In_   POBJECT_ATTRIBUTES ObjectAttributes
		);

	typedef NTSTATUS(NTAPI *_NtGetNextProcess)(
		HANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		ULONG HandleAttributes,
		ULONG Flags,
		PHANDLE NewProcessHandle);

	typedef NTSTATUS(NTAPI* _NtGetNextThread)(
		HANDLE ProcessHandle,
		HANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		ULONG HandleAttributes,
		ULONG Flags,
		PHANDLE NewThreadHandle
		);

#define DIRECTORY_QUERY 0x0001
#define DIRECTORY_TRAVERSE 0x0002
#define DIRECTORY_CREATE_OBJECT 0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY 0x0008
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
	
	inline PVOID GetNtProcAddress(PSTR ProcName)
	{
		return GetProcAddress(GetModuleHandleA("ntdll"), ProcName);
	}

	inline ULONG NtStatusToWin32(NTSTATUS status) {
		_RtlNtStatusToDosError func = (_RtlNtStatusToDosError)GetNtProcAddress("RtlNtStatusToDosError");

		return func(status);
	}

	inline System::String^ UnicodeNameToString(UNICODE_STRING& us) {
		return gcnew System::String(us.Buffer, 0, us.Length / sizeof(us.Buffer[0]));
	}

	struct UNICODE_STRING_WITH_BUF : UNICODE_STRING
	{				
		UNICODE_STRING_WITH_BUF(USHORT max_char_count) : backing_buf(max_char_count) {
			// Should be sure char_count isn't greater that WORD
			Length = 0;
			MaximumLength = max_char_count * sizeof(WCHAR);
			Buffer = &backing_buf[0];
		}

		UNICODE_STRING_WITH_BUF(LPWSTR str, USHORT max_char_count) 
			: UNICODE_STRING_WITH_BUF(max_char_count)
		{
			if (str != nullptr)
			{
				SetupString(str, wcslen(str));
			}
		}

		UNICODE_STRING_WITH_BUF(System::String^ str, USHORT max_char_count) : 
			UNICODE_STRING_WITH_BUF(max_char_count)
		{
			if (str != nullptr)
			{
				pin_ptr<const wchar_t> s = PtrToStringChars(str);

				SetupString(s, str->Length);
			}
		}

		UNICODE_STRING_WITH_BUF(System::String^ str) 
			: UNICODE_STRING_WITH_BUF(str, str == nullptr ? 0 : str->Length)
		{
		}

		System::String^ ToString() {
			return UnicodeNameToString(*this);
		}

	private:
		std::vector<WCHAR> backing_buf;

		void SetupString(LPCWSTR str, size_t length)
		{
			if (length <= backing_buf.size())
			{
				memcpy(&backing_buf[0], str, length*sizeof(WCHAR));
				Length = static_cast<USHORT>(length) * sizeof(WCHAR);
			}
		}
	};



#define DEFINE_NTDLL(x) HandleUtils::_ ## x f ## x = (HandleUtils::_ ## x)HandleUtils::GetNtProcAddress(#x)

	struct OBJECT_ATTRIBUTES_WITH_NAME : public OBJECT_ATTRIBUTES
	{		
		OBJECT_ATTRIBUTES_WITH_NAME(System::String^ Name, ULONG Attributes, HANDLE BaseDirectory) : _str(Name) {
			PUNICODE_STRING uni_string = nullptr;

			if (Name != nullptr)
			{
				uni_string = &_str;
			}

			InitializeObjectAttributes(this, uni_string, Attributes, BaseDirectory, nullptr);
		}

	private:

		UNICODE_STRING_WITH_BUF _str;
	};
}