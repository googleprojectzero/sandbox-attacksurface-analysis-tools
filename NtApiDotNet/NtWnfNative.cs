﻿//  Copyright 2019 Google Inc. All Rights Reserved.
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
    public enum WnfStateNameLifetime
    {
        WellKnown,
        Permanent,
        Volatile,
        Temporary
    }

    public enum WnfStateNameInformation
    {
        NameExist,
        SubscribersPresent,
        IsQuiescent
    }

    public enum WnfDataScope
    {
        System,
        Session,
        User,
        Process,
        Machine,
        PhysicalMachine
    }

    [StructLayout(LayoutKind.Sequential)]
    public class WnfTypeId
    {
        public Guid TypeId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WnfDeliveryDescriptor
    {
        public ulong SubscriptionId;
        public ulong StateName;
        public uint ChangeStamp;
        public uint StateDataSize;
        public uint EventMask;
        public WnfTypeId TypeId;
        public uint StateDataOffset;
    }

    public class WnfStateData
    {
        public byte[] Data { get; }
        public int ChangeStamp { get; }
        public WnfStateData(byte[] data, int changestamp)
        {
            Data = data;
            ChangeStamp = changestamp;
        }
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateWnfStateName(
            out ulong StateName,
            WnfStateNameLifetime NameLifetime,
            WnfDataScope DataScope,
            bool PersistData,
            [In, Optional] WnfTypeId TypeId,
            int MaximumStateSize,
            SafeBuffer SecurityDescriptor
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryWnfStateData(
             in ulong StateName,
             [In, Optional] WnfTypeId TypeId,
             [Optional] IntPtr ExplicitScope,
             out int ChangeStamp,
             SafeBuffer Buffer,
             ref int BufferSize
         );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtUpdateWnfStateData(
            in ulong StateName,
            SafeBuffer Buffer,
            int Length,
            [In, Optional] WnfTypeId TypeId,
            [Optional] IntPtr ExplicitScope,
            int MatchingChangeStamp,
            [MarshalAs(UnmanagedType.Bool)] bool CheckChangeStamp
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDeleteWnfStateName(
            in ulong StateName
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryWnfStateNameInformation(
            in ulong StateName,
            WnfStateNameInformation NameInfoClass,
            IntPtr ExplicitScope,
            SafeBuffer InfoBuffer,
            int InfoBufferSize
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDeleteWnfStateData(
          in ulong StateName,
          IntPtr ExplicitScope);
    }

    public enum WnfAccessRights : uint
    {
        [SDKName("WNF_READ_DATA")]
        ReadData = 1,
        [SDKName("WNF_WRITE_DATA")]
        WriteData = 2,
        [SDKName("WNF_UNKNOWN_10")]
        Unknown10 = 0x10,
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

#pragma warning restore 1591
}
