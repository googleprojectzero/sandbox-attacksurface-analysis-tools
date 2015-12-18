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

#include "HandleEntry.h"
#include "NativeHandle.h"
#include "NativeMappedFile.h"
#include "ObjectTypeInfo.h"
#include "ImpersonateProcess.h"
#include "ScopedHandle.h"

using namespace System;
using namespace System::Collections::Generic;

namespace HandleUtils {

	[Flags]
	public enum class AccessRights : unsigned int
	{
		None = 0x0,
		SectionMapRead = 0x4,
		SectionMapWrite = 0x2,
	};

	[Flags]
	public enum class DuplicateHandleOptions : unsigned int
	{
		None = 0,
		DuplicateSameAccess = 0x2,
	};

	[Flags]
	public enum class StandardAccessRights : unsigned int
	{
		Delete = 0x00010000,
		ReadControl = 0x00020000,
		WriteDac = 0x00040000,
		WriteOwner = 0x00080000,
		Synchronize = 0x00100000,
	};

	[Flags]
	public enum class GenericAccessRights : unsigned int
	{
		GenericRead = 0x80000000U,
		GenericWrite = 0x40000000U,
		GenericExecute = 0x20000000U,
		GenericAll = 0x10000000U,
	};

	[Flags]
	public enum class DirectoryAccessRights : unsigned int
	{
		Query = 0x0001,
		Traverse = 0x0002,
		CreateObject = 0x0004,
		CreateSubdirectory = 0x0008
	};

	[Flags]
	public enum class EventAccessRights : unsigned int
	{
		QueryState = 0x0001,
		ModifyState = 0x0002,
	};

	[Flags]
	public enum class SectionAccessRights : unsigned int
	{
		Query = 0x0001,
		MapWrite = 0x0002,
		MapRead = 0x0004,
		MapExecute = 0x0008,
		ExtendSize = 0x0010,
		MapExecuteExplicit = 0x0020
	};

	[Flags]
	public enum class FileAccessRights : unsigned int
	{
		ReadData = 0x0001,
		WriteData = 0x0002,
		AppendData = 0x0004,
		ReadEa = 0x0008,
		WriteEa = 0x0010,
		Execute = 0x0020,
		DeleteChild = 0x0040,
		ReadAttributes = 0x0080,
		WriteAttributes = 0x0100,
	};

	[Flags]
	public enum class FileDirectoryAccessRights : unsigned int
	{
		ListDirectory = 0x0001,
		AddFile = 0x0002,
		AddSubDirectory = 0x0004,
		ReadEa = 0x0008,
		WriteEa = 0x0010,
		Traverse = 0x0020,
		DeleteChild = 0x0040,
		ReadAttributes = 0x0080,
		WriteAttributes = 0x0100,
	};


	[Flags]
	public enum class KeyAccessRights : unsigned int
	{
		QueryValue = 0x0001,
		SetValue = 0x0002,
		CreateSubKey = 0x0004,
		EnumerateSubKeys = 0x0008,
		Notify = 0x0010,
		CreateLink = 0x0020,
	};

	[Flags]
	public enum class MutantAccessRights : unsigned int
	{
		QueryState = 0x0001,
	};

	[Flags]
	public enum class SemaphoreAccessRights : unsigned int
	{
		QueryState = 0x0001,
		ModifyState = 0x0002,
	};

	[Flags]
	public enum class JobObjectAccessRights : unsigned int
	{
		AssignProcess = 0x0001,
		SetAttributes = 0x0002,
		Query = 0x0004,
		Terminate = 0x0008,
		SetSecurityAttributes = 0x0010
	};

	[Flags]
	public enum class ProcessAccessRights : unsigned int
	{
		CreateProcess = 0x0080,
		CreateThread = 0x0002,
		DupHandle = 0x0040,
		QueryInformation = 0x0400,
		QueryLimitedInformation = 0x1000,
		SetInformation = 0x0200,
		SetQuota = 0x0100,
		SuspendResume = 0x0800,
		Terminate = 0x0001,
		VmOperation = 0x0008,
		VmRead = 0x0010,
		VmWrite = 0x0020,
	};

	public enum class ThreadAccessRights : unsigned int
	{
		DirectImpersonation = 0x0200,
		GetContext = 0x0008,
		Impersonate = 0x0100,
		QueryInformation = 0x0040,
		QueryLimitedInformation = 0x0800,
		SetContext = 0x0010,
		SetInformation = 0x0020,
		SetLimitedInformation = 0x0400,
		SetToken = 0x0080,
		SuspendResume = 0x0002,
		Terminate = 0x0001,
	};

	public enum class TokenAccessRights : unsigned int
	{
		AssignPrimary = 0x0001,
		Duplicate = 0x0002,
		Impersonate = 0x0004,
		Query = 0x0008,
		QuerySource = 0x0010,
		AdjustPrivileges = 0x0020,
		AdjustGroups = 0x0040,
		AdjustDefault = 0x0080,
		AdjustSessionId = 0x0100,
	};

	[Flags]
	public enum class SymbolicLinkAccessRights : unsigned int
	{
		Query = 0x0001,
	};

	[Flags]
	public enum class FileOpenOptions : unsigned int
	{
		DIRECTORY_FILE = 0x00000001,
		WRITE_THROUGH = 0x00000002,
		SEQUENTIAL_ONLY = 0x00000004,
		NO_INTERMEDIATE_BUFFERING = 0x00000008,
		SYNCHRONOUS_IO_ALERT = 0x00000010,
		SYNCHRONOUS_IO_NONALERT = 0x00000020,
		NON_DIRECTORY_FILE = 0x00000040,
		CREATE_TREE_CONNECTION = 0x00000080,
		COMPLETE_IF_OPLOCKED = 0x00000100,
		NO_EA_KNOWLEDGE = 0x00000200,
		OPEN_REMOTE_INSTANCE = 0x00000400,
		RANDOM_ACCESS = 0x00000800,
		DELETE_ON_CLOSE = 0x00001000,
		OPEN_BY_FILE_ID = 0x00002000,
		OPEN_FOR_BACKUP_INTENT = 0x00004000,
		NO_COMPRESSION = 0x00008000,
		OPEN_REQUIRING_OPLOCK = 0x00010000,
		RESERVE_OPFILTER = 0x00100000,
		OPEN_REPARSE_POINT = 0x00200000,
		OPEN_NO_RECALL = 0x00400000,
		OPEN_FOR_FREE_SPACE_QUERY = 0x00800000,
	};

	[Flags]
	public enum class FileShareMode : unsigned int
	{
		Read = 0x00000001,
		Write = 0x00000002,
		Delete = 0x00000004,
		All = Read | Write | Delete
	};

	public enum class FileCreateDisposition : unsigned int
	{
		Supersede = 0x00000000,
		Open = 0x00000001,
		Create = 0x00000002,
		OpenIf = 0x00000003,
		Overwrite = 0x00000004,
		OverwriteIf = 0x00000005
	};

	public enum class TokenSecurityLevel : unsigned int
	{
		Anonymous = 0,
		Identification = 1,
		Impersonate = 2,
		Delegate = 3,
	};

	public ref class NativeBridge
	{		
	public:
		static List<HandleEntry^>^ GetHandlesForPid(int pid);		
		static List<HandleEntry^>^ GetHandlesForPid(int pid, bool noquery);
		static NativeHandle^ DuplicateHandleFromProcess(int pid, IntPtr handle, unsigned int desiredAccess, DuplicateHandleOptions options);
		static NativeHandle^ DuplicateHandleFromProcess(HandleEntry^ handle, unsigned int desiredAccess, DuplicateHandleOptions options);
		static NativeMappedFile^ MapFile(NativeHandle^ sectionHandle, bool writable);
		static NativeMappedFile^ MapFile(String^ name, bool writable);
		static long GetSectionSize(NativeHandle^ sectionHandle);		
		static array<unsigned char>^ GetNamedSecurityDescriptor(System::String^ name, System::String^ typeName);
		static System::String^ GetStringSecurityDescriptor(array<unsigned char>^ sd);
		static array<unsigned char>^ GetSecurityDescriptorForNameAndType(System::String^ name, System::String^ type);
		static array<unsigned char>^ GetSecurityDescriptorForHandle(NativeHandle^ handle);
		static NativeHandle^ OpenProcessToken(int pid);
		static NativeHandle^ OpenProcessToken(NativeHandle^ process);
		static NativeHandle^ OpenThreadToken(NativeHandle^ thread);
		static NativeHandle^ OpenProcessToken();
		static NativeHandle^ OpenThreadToken();
		static NativeHandle^ CreateImpersonationToken(NativeHandle^ token, TokenSecurityLevel level);
		static NativeHandle^ CreatePrimaryToken(NativeHandle^ token);
		static ImpersonateProcess^ Impersonate(int pid, TokenSecurityLevel level);
		static bool EnablePrivilege(String^ privname, bool enable);
		static unsigned int GetMaximumAccess(NativeHandle^ token, ObjectTypeInfo^ type, array<unsigned char>^ sd);
		static unsigned int GetAllowedAccess(NativeHandle^ token, ObjectTypeInfo^ type, unsigned int access_mask, array<unsigned char>^ sd);
		static NativeHandle^ CreateFileNative(System::String^ lpPath, unsigned int dwAccess,
			unsigned int dwAttributes, FileShareMode dwShareMode, FileCreateDisposition dwCreateDisposition, FileOpenOptions dwCreateOptions);		
		static void EditSecurity(System::IntPtr hwnd, System::String^ fullPath, System::String^ typeName, bool writeable);
		static void EditSecurity(System::IntPtr hwnd, System::IntPtr handle, System::String^ object_name, System::String^ typeName, bool writeable);
		static unsigned int GetGrantedAccess(NativeHandle^ handle);
		static array<NativeHandle^>^ GetProcesses();
		static array<NativeHandle^>^ GetThreadsForProcess(NativeHandle^ process);
		static String^ MapAccessToString(unsigned int access_mask, Type^ enumType);
		static int GetPidForProcess(NativeHandle^ handle);
		static int GetTidForThread(NativeHandle^ handle);
		static String^ GetProcessPath(NativeHandle^ process);
		static NativeHandle^ OpenProcess(int pid);
		static String^ GetUserNameForToken(NativeHandle^ token);
	};

	String^ QueryObjectName(HANDLE h);
	array<unsigned char>^ GetSecurityDescriptor(HANDLE h);			
	ScopedHandle OpenObjectForNameAndType(System::String^ name, System::String^ type, ACCESS_MASK DesiredAccess);
	Type^ TypeNameToEnum(System::String^ name);	
}
