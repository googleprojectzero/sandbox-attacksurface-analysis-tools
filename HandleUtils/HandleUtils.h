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

#include "ObjectTypeInfo.h"
#include "ScopedHandle.h"

using namespace System;
using namespace System::Collections::Generic;

namespace HandleUtils {



	public ref class NativeBridge
	{		
	public:
		static List<HandleEntry^>^ GetHandlesForPid(int pid);		
		static List<HandleEntry^>^ GetHandlesForPid(int pid, bool noquery);
		static NativeHandle^ DuplicateHandleFromProcess(int pid, IntPtr handle, unsigned int desiredAccess, DuplicateHandleOptions options);
		static NativeHandle^ DuplicateHandleFromProcess(HandleEntry^ handle, unsigned int desiredAccess, DuplicateHandleOptions options);
		static NativeMappedFile^ MapFile(NativeHandle^ sectionHandle, bool writable);
		static NativeMappedFile^ MapFile(String^ name, bool writable);
		static long long GetSectionSize(NativeHandle^ sectionHandle);		
		static array<unsigned char>^ GetNamedSecurityDescriptor(System::String^ name, System::String^ typeName);
		static System::String^ GetStringSecurityDescriptor(array<unsigned char>^ sd);
		static array<unsigned char>^ GetSecurityDescriptorForNameAndType(NativeHandle^ root, System::String^ name, System::String^ type);
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
		static void EditSecurity(System::IntPtr hwnd, NativeHandle^ root, System::String^ path, System::String^ typeName, bool writeable);
		static void EditSecurity(System::IntPtr hwnd, System::IntPtr handle, System::String^ object_name, System::String^ typeName, bool writeable);
		static unsigned int GetGrantedAccess(NativeHandle^ handle);
		static array<NativeHandle^>^ GetProcesses();
		static array<NativeHandle^>^ GetThreadsForProcess(NativeHandle^ process);
		static array<NativeHandle^>^ GetThreads();
		static String^ MapAccessToString(unsigned int access_mask, Type^ enumType);
		static int GetPidForProcess(NativeHandle^ handle);
		static int GetTidForThread(NativeHandle^ handle);
		static int GetPidForThread(NativeHandle^ handle);
		static String^ GetProcessPath(NativeHandle^ process);
		static NativeHandle^ OpenProcess(int pid);
		static NativeHandle^ OpenThread(int tid);
		static String^ GetUserNameForToken(NativeHandle^ token);
		static NativeHandle^ OpenObject(NativeHandle^ root, String^ name, String^ type, GenericAccessRights access);
	};

	String^ QueryObjectName(HANDLE h);
	array<unsigned char>^ GetSecurityDescriptor(HANDLE h);			
	ScopedHandle OpenObjectForNameAndType(NativeHandle^ handle, System::String^ name, System::String^ type, ACCESS_MASK DesiredAccess);
	Type^ TypeNameToEnum(System::String^ name);	
}
