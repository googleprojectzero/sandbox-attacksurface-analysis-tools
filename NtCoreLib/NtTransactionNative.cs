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

using NtApiDotNet.Utilities.Reflection;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum TransactionAccessRights : uint
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
        [SDKName("TRANSACTION_RIGHT_RESERVED1")]
        RightReserved1 = 0x40,
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

    [Flags]
    public enum TransactionCreateFlags
    {
        None = 0,
        DoNotPromote = 1,
    }

    [Flags]
    public enum TransactionIsolationFlags
    {
        None = 0,
    }

    public enum TransactionInformationClass
    {
        TransactionBasicInformation,
        TransactionPropertiesInformation,
        TransactionEnlistmentInformation,
        TransactionSuperiorEnlistmentInformation
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateTransaction(out SafeKernelObjectHandle TransactionHandle,
                TransactionAccessRights DesiredAccess, ObjectAttributes ObjectAttributes,
                OptionalGuid Uow, SafeKernelObjectHandle TmHandle,
                TransactionCreateFlags CreateOptions,
                int IsolationLevel,
                TransactionIsolationFlags IsolationFlags,
                LargeInteger Timeout,
                UnicodeString Description);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenTransaction(out SafeKernelObjectHandle TransactionHandle, TransactionAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes, ref Guid Uow, SafeKernelObjectHandle TmHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCommitTransaction(SafeKernelObjectHandle TransactionHandle, bool Wait);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRollbackTransaction(SafeKernelObjectHandle TransactionHandle, bool Wait);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationTransaction(
            SafeKernelObjectHandle TransactionHandle,
            TransactionInformationClass TransactionInformationClass,
            SafeBuffer TransactionInformation,
            int TransactionInformationLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationTransaction(
            SafeKernelObjectHandle TransactionHandle,
            TransactionInformationClass TransactionInformationClass,
            SafeBuffer TransactionInformation,
            int TransactionInformationLength
        );
    }

    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern bool RtlSetCurrentTransaction(SafeKernelObjectHandle TransactionHandle);

        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlGetCurrentTransaction();
    }

    public sealed class TransactionContext : IDisposable
    {
        internal TransactionContext(SafeKernelObjectHandle transaction)
        {
            NtRtl.RtlSetCurrentTransaction(transaction);
        }

        void IDisposable.Dispose()
        {
            NtRtl.RtlSetCurrentTransaction(SafeKernelObjectHandle.Null);
        }
    }

    public enum TransactionState
    {
        None = 0,
        Normal,
        Indoubt,
        CommittedNotify
    }

    public enum TransactionOutcome
    {
        None = 0,
        Undetermined,
        Committed,
        Aborted
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TransactionBasicInformation
    {
        public Guid TransactionId;
        public TransactionState State;
        public TransactionOutcome Outcome;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("Description", IncludeDataField = true)]
    public struct TransactionPropertiesInformation
    {
        public int IsolationLevel;
        public int IsolationFlags;
        public LargeIntegerStruct Timeout;
        public TransactionOutcome Outcome;
        public int DescriptionLength;
        public char Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TransactionEnlistmentPair
    {
        public Guid EnlistmentId;
        public Guid ResourceManagerId;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("EnlistmentPair")]
    public struct TransactionEnlistmentsInformation
    {
        public int NumberOfEnlistments;
        public TransactionEnlistmentPair EnlistmentPair;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TransactionSuperiorEnlistmentInformation
    {
        public TransactionEnlistmentPair SuperiorEnlistmentPair;
    }

#pragma warning restore 1591
}
