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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum EnlistmentAccessRights : uint
    {
        None = 0,
        QueryInformation = 1,
        SetInformation = 2,
        Recover = 4,
        SubordinateRights = 8,
        SuperiorRights = 0x10,
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

    [Flags]
    public enum EnlistmentCreateOptions
    {
        None = 0,
        Superior = 1,
    }

    public enum EnlistmentInformationClass
    {
        EnlistmentBasicInformation,
        EnlistmentRecoveryInformation,
        EnlistmentCrmInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EnlistmentBasicInformation
    {
        public Guid EnlistmentId;
        public Guid TransactionId;
        public Guid ResourceManagerId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EnlistmentCrmInformation
    {
        public Guid CrmTransactionManagerId;
        public Guid CrmResourceManagerId;
        public Guid CrmEnlistmentId;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateEnlistment(
            out SafeKernelObjectHandle EnlistmentHandle,
            EnlistmentAccessRights DesiredAccess,
            SafeKernelObjectHandle ResourceManagerHandle,
            SafeKernelObjectHandle TransactionHandle,
            ObjectAttributes ObjectAttributes,
            EnlistmentCreateOptions CreateOptions,
            TransactionNotificationMask NotificationMask,
            IntPtr EnlistmentKey
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenEnlistment(
            out SafeKernelObjectHandle EnlistmentHandle,
            EnlistmentAccessRights DesiredAccess,
            SafeKernelObjectHandle ResourceManagerHandle,
            ref Guid EnlistmentGuid,
            ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCommitComplete(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCommitEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPrePrepareComplete(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPrePrepareEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPrepareComplete(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPrepareEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRollbackComplete(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRollbackEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtReadOnlyEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRecoverEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSinglePhaseReject(
            SafeKernelObjectHandle EnlistmentHandle,
            LargeInteger TmVirtualClock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            EnlistmentInformationClass EnlistmentInformationClass,
            SafeBuffer EnlistmentInformation,
            int EnlistmentInformationLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationEnlistment(
            SafeKernelObjectHandle EnlistmentHandle,
            EnlistmentInformationClass EnlistmentInformationClass,
            SafeBuffer EnlistmentInformation,
            int EnlistmentInformationLength
        );
    }

#pragma warning restore 1591
}
