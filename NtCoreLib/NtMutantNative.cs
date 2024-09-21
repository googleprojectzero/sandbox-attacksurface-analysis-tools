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
    public enum MutantAccessRights : uint
    {
        None = 0,
        [SDKName("MUTANT_MODIFY_STATE")]
        ModifyState = 1,
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

    public enum MutantInformationClass
    {
        MutantBasicInformation,
        MutantOwnerInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MutantBasicInformation
    {
        public int CurrentCount;
        public byte OwnedByCaller;
        public byte AbandonedState;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MutantOwnerInformation
    {
        public ClientIdStruct ClientId;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateMutant(out SafeKernelObjectHandle MutantHandle, MutantAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes, bool InitialOwner);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenMutant(out SafeKernelObjectHandle MutantHandle, MutantAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtReleaseMutant(SafeKernelObjectHandle MutantHandle, out int PreviousState);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryMutant(
            SafeKernelObjectHandle MutantHandle,
            MutantInformationClass MutantInformationClass,
            SafeBuffer MutantInformation,
            int MutantInformationLength,
            out int ResultLength);
    }
#pragma warning restore 1591
}
