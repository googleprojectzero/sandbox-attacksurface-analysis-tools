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
    /// <summary>
    /// Semaphore access rights.
    /// </summary>
    [Flags]
    public enum SemaphoreAccessRights : uint
    {
        None = 0,
        [SDKName("SEMAPHORE_QUERY_STATE")]
        QueryState = 1,
        [SDKName("SEMAPHORE_MODIFY_STATE")]
        ModifyState = 2,
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

    public enum SemaphoreInformationClass
    {
        SemaphoreBasicInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SemaphoreBasicInformation
    {
        public int CurrentCount;
        public int MaximumCount;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateSemaphore(out SafeKernelObjectHandle MutantHandle, SemaphoreAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes, int InitialCount, int MaximumCount);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenSemaphore(out SafeKernelObjectHandle MutantHandle, SemaphoreAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes);


        [DllImport("ntdll.dll")]
        public static extern NtStatus NtReleaseSemaphore(
           SafeKernelObjectHandle SemaphoreHandle,
           int ReleaseCount,
           out int PreviousCount
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQuerySemaphore(SafeKernelObjectHandle MutantHandle,
            SemaphoreInformationClass SemaphoreInformationClass,
            SafeBuffer SemaphoreInformation,
            int SemaphoreInformationLength,
            out int ResultLength);
    }
#pragma warning restore 1591
}
