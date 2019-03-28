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
    public enum ResourceManagerAccessRights : uint
    {
        QueryInformation = 1,
        SetInformation = 2,
        Recover = 4,
        Enlist = 8,
        GetNotification = 0x10,
        RegisterProtocol = 0x20,
        CompletePropagation = 0x40,
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

    public enum ResourceManagerCreateOptions
    {
        None = 0,
        Volatile = 1,
        Communication = 2,
    }

    [Flags]
    public enum TransactionNotificationMask : uint
    {
        PrePrepare = 0x00000001,
        Prepare = 0x00000002,
        Commit = 0x00000004,
        Rollback = 0x00000008,
        PrePrepareComplete = 0x00000010,
        PrepareComplete = 0x00000020,
        CommitComplete = 0x00000040,
        RollbackComplete = 0x00000080,
        Recover = 0x00000100,
        SinglePhaseCommit = 0x00000200,
        DelegateCommit = 0x00000400,
        RecoverQuery = 0x00000800,
        EnlistPrePrepare = 0x00001000,
        LastRecover = 0x00002000,
        InDoubt = 0x00004000,
        PropagatePull = 0x00008000,
        PropagatePush = 0x00010000,
        Marshal = 0x00020000,
        EnlistMask = 0x00040000,
        RmDisconnected = 0x01000000,
        TmOnline = 0x02000000,
        CommitRequest = 0x04000000,
        Promote = 0x08000000,
        PromoteNew = 0x10000000,
        RequestOutcome = 0x20000000,
    }

    [Flags]
    public enum RegisterProtocolCreateOptions
    {
        None = 0,
        ExplicitMarshalOnly = 1,
        DynamicMarshalInfo = 2,
    }

    [StructLayout(LayoutKind.Sequential), DataStart("ArgumentData")]
    public struct TransactionNotificationData
    {
        public IntPtr TransactionKey;
        public TransactionNotificationMask TransactionNotification;
        public LargeIntegerStruct TmVirtualClock;
        public int ArgumentLength;
        public byte ArgumentData;
    }

    public class TransactionNotification
    {
        public IntPtr Key { get; }
        public TransactionNotificationMask Mask { get; }
        public long VirtualClock { get; }
        public byte[] Argument { get; }

        internal TransactionNotification(SafeStructureInOutBuffer<TransactionNotificationData> buffer)
        {
            var result = buffer.Result;
            Key = result.TransactionKey;
            Mask = result.TransactionNotification;
            VirtualClock = result.TmVirtualClock.QuadPart;
            Argument = new byte[result.ArgumentLength];
            buffer.Data.ReadArray(0, Argument, 0, Argument.Length);
        }
    }

    public enum ResourceManagerInformationClass
    {
        ResourceManagerBasicInformation,
        ResourceManagerCompletionInformation
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode),
        DataStart("Description", IncludeDataField = true)]
    public struct ResourceManagerBasicInformation
    {
        public Guid ResourceManagerId;
        public int DescriptionLength;
        public char Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ResourceManagerCompletionInformation
    {
        public IntPtr IoCompletionPortHandle;
        public IntPtr CompletionKey;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateResourceManager(
            out SafeKernelObjectHandle ResourceManagerHandle,
            ResourceManagerAccessRights DesiredAccess,
            SafeKernelObjectHandle TmHandle,
            ref Guid RmGuid,
            ObjectAttributes ObjectAttributes,
            ResourceManagerCreateOptions CreateOptions,
            UnicodeString Description
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenResourceManager(
            out SafeKernelObjectHandle ResourceManagerHandle,
            ResourceManagerAccessRights DesiredAccess,
            SafeKernelObjectHandle TmHandle,
            ref Guid ResourceManagerGuid,
            ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationResourceManager(
            SafeKernelObjectHandle ResourceManagerHandle,
            ResourceManagerInformationClass ResourceManagerInformationClass,
            SafeBuffer ResourceManagerInformation,
            int ResourceManagerInformationLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationResourceManager(
            SafeKernelObjectHandle ResourceManagerHandle,
            ResourceManagerInformationClass ResourceManagerInformationClass,
            SafeBuffer ResourceManagerInformation,
            int ResourceManagerInformationLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRecoverResourceManager(
            SafeKernelObjectHandle ResourceManagerHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtGetNotificationResourceManager(
            SafeKernelObjectHandle ResourceManagerHandle,
            SafeBuffer TransactionNotification, // Allocated TransactionNotificationData
            int NotificationLength,
            LargeInteger Timeout,
            out int ReturnLength,
            int Asynchronous,
            IntPtr AsynchronousContext
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRegisterProtocolAddressInformation(
            SafeKernelObjectHandle ResourceManagerHandle,
            ref Guid ProtocolId,
            int ProtocolInformationSize,
            SafeBuffer ProtocolInformation,
            RegisterProtocolCreateOptions CreateOptions);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPropagationComplete(
            SafeKernelObjectHandle ResourceManagerHandle,
            uint RequestCookie,
            int BufferLength,
            SafeBuffer Buffer);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPropagationFailed(
            SafeKernelObjectHandle ResourceManagerHandle,
            uint RequestCookie,
            NtStatus PropStatus);
    }

    public static class NtResourceManagerKnownProtocolId
    {
        public static readonly Guid PromotingProtocolId = new Guid("AC06CC84-1465-428B-A398-0AAEEFB4599B");
        public static readonly Guid OleTxProtocolId = new Guid("88288CD9-A6D0-494B-8072-FF9BE190D691");
    }

#pragma warning restore 1591
}
