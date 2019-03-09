//  Copyright 2018 Google Inc. All Rights Reserved.
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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum MemoryPartitionAccessRights : uint
    {
        None = 0,
        Query = 1,
        Modify = 2,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
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
}
