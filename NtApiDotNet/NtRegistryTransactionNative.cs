//  Copyright 2019 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Utilities.Reflection;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum RegistryTransactionAccessRights : uint
    {
        [SDKName("TRANSACTION_QUERY_INFORMATION")]
        QueryInformation = 0x01,
        [SDKName("TRANSACTION_SET_INFORMATION")]
        SetInformation = 0x02,
        [SDKName("TRANSACTION_ENLIST")]
        Enlist = 0x04,
        [SDKName("TRANSACTION_COMMIT")]
        Commit = 0x08,
        [SDKName("TRANSACTION_ROLLBACK")]
        Rollback = 0x10,
        [SDKName("TRANSACTION_PROPAGATE")]
        Propagate = 0x20,
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

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateRegistryTransaction(out SafeKernelObjectHandle Handle, RegistryTransactionAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes, int Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenRegistryTransaction(out SafeKernelObjectHandle Handle, RegistryTransactionAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCommitRegistryTransaction(SafeKernelObjectHandle Handle, bool Wait);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRollbackRegistryTransaction(SafeKernelObjectHandle Handle, bool Wait);
    }
#pragma warning restore 1591
}
