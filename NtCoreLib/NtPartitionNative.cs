﻿//  Copyright 2018 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Utilities.Reflection;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib;

#pragma warning disable 1591
[Flags]
public enum MemoryPartitionAccessRights : uint
{
    None = 0,
    [SDKName("MEMORY_PARTITION_QUERY_ACCESS")]
    Query = 1,
    [SDKName("MEMORY_PARTITION_MODIFY_ACCESS")]
    Modify = 2,
    [SDKName("GENERIC_READ")]
    GenericRead = GenericAccessRights.GenericRead,
    [SDKName("GENERIC_WRITE")]
    GenericWrite = GenericAccessRights.GenericWrite,
    [SDKName("GENERIC_EXECUTE")]
    GenericExecute = GenericAccessRights.GenericExecute,
    [SDKName("GENERIC_ALL")]
    GenericAll = GenericAccessRights.GenericAll,
    [SDKName("DELETE")]
    Delete = GenericAccessRights.Delete,
    [SDKName("READ_CONTROL")]
    ReadControl = GenericAccessRights.ReadControl,
    [SDKName("WRITE_DAC")]
    WriteDac = GenericAccessRights.WriteDac,
    [SDKName("WRITE_OWNER")]
    WriteOwner = GenericAccessRights.WriteOwner,
    [SDKName("SYNCHRONIZE")]
    Synchronize = GenericAccessRights.Synchronize,
    [SDKName("MAXIMUM_ALLOWED")]
    MaximumAllowed = GenericAccessRights.MaximumAllowed,
    [SDKName("ACCESS_SYSTEM_SECURITY")]
    AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
}

public enum MemoryPartitionInformationClass
{
    SystemMemoryPartitionInformation,
    SystemMemoryPartitionMoveMemory,
    SystemMemoryPartitionAddPagefile,
    SystemMemoryPartitionCombineMemory,
    SystemMemoryPartitionInitialAddMemory,
    SystemMemoryPartitionGetMemoryEvents
}

public static partial class NtSystemCalls
{
    [DllImport("ntdll.dll")]
    public static extern NtStatus NtCreatePartition(
        SafeKernelObjectHandle ParentPartitionHandle,
        out SafeKernelObjectHandle PartitionHandle,
        AccessMask DesiredAccess,
        [In] ObjectAttributes ObjectAttributes,
        int PreferredNode
        );

    [DllImport("ntdll.dll")]
    public static extern NtStatus NtOpenPartition(
        out SafeKernelObjectHandle PartitionHandle,
        AccessMask DesiredAccess,
        [In] ObjectAttributes ObjectAttributes
    );

    [DllImport("ntdll.dll")]
    public static extern NtStatus NtManagePartition(
        MemoryPartitionInformationClass PartitionInformationClass,
        SafeBuffer PartitionInformation,
        int PartitionInformationLength
        );
}
#pragma warning restore 1591

