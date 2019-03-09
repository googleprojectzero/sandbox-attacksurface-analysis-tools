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
    public enum TransactionManagerAccessRights : uint
    {
        QueryInformation = 1,
        SetInformation = 2,
        Recover = 4,
        Rename = 8,
        CreateRm = 0x10,
        BindTransaction = 0x20,
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
