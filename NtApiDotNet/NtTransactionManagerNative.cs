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
    public enum TransactionManagerAccessRights : uint
    {
        [SDKName("TRANSACTIONMANAGER_QUERY_INFORMATION")]
        QueryInformation = 1,
        [SDKName("TRANSACTIONMANAGER_SET_INFORMATION")]
        SetInformation = 2,
        [SDKName("TRANSACTIONMANAGER_RECOVER")]
        Recover = 4,
        [SDKName("TRANSACTIONMANAGER_RENAME")]
        Rename = 8,
        [SDKName("TRANSACTIONMANAGER_CREATE_RM")]
        CreateRm = 0x10,
        [SDKName("TRANSACTIONMANAGER_BIND_TRANSACTION")]
        BindTransaction = 0x20,
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
    public enum TransactionManagerCreateOptions
    {
        CommitDefault = 0x00000000,
        Volatile = 0x00000001,
        CommitSystemVolume = 0x00000002,
        CommitSystemHives = 0x00000004,
        CommitLowest = 0x00000008,
        CorruptForRecovery = 0x00000010,
        CorruptForProgress = 0x00000020,
    }

    [Flags]
    public enum TransactionManagerOpenOptions
    {
        None = 0
    }

    public enum TransactionManagerInformationClass
    {
        TransactionManagerBasicInformation,
        TransactionManagerLogInformation,
        TransactionManagerLogPathInformation,
        TransactionManagerRecoveryInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TransactionManagerBasicInformation
    {
        public Guid TmIdentity;
        public LargeIntegerStruct VirtualClock;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TransactionManagerLogInformation
    {
        public Guid LogIdentity;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("LogPath")]
    public struct TransactionLogPathInformation
    {
        public int LogPathLength;
        public char LogPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TransactionManagerRecoveryInformation
    {
        public ulong LastRecoveredLsn;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateTransactionManager(
            out SafeKernelObjectHandle TmHandle,
            TransactionManagerAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes,
            UnicodeString LogFileName,
            TransactionManagerCreateOptions CreateOptions,
            int CommitStrength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenTransactionManager(
            out SafeKernelObjectHandle TmHandle,
            TransactionManagerAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes,
            UnicodeString LogFileName,
            OptionalGuid TmIdentity,
            TransactionManagerOpenOptions OpenOptions
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationTransactionManager(
          SafeKernelObjectHandle TmHandle,
          TransactionManagerInformationClass TransactionManagerInformationClass,
          SafeBuffer TransactionManagerInformation,
          int TransactionManagerInformationLength,
          out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationTransactionManager(
          SafeKernelObjectHandle TmHandle,
          TransactionManagerInformationClass TransactionManagerInformationClass,
          SafeBuffer TransactionManagerInformation,
          int TransactionManagerInformationLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRecoverTransactionManager(
            SafeKernelObjectHandle TmHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRenameTransactionManager(
            UnicodeString LogFileName,
            OptionalGuid ExistingTransactionManagerGuid
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRollforwardTransactionManager(
            SafeKernelObjectHandle TmHandle,
            LargeInteger TmVirtualClock
        );
    }

#pragma warning restore 1591
}
