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
    /// <summary>
    /// Access rights for Trace
    /// </summary>
    [Flags]
    public enum TraceAccessRights : uint
    {
        None = 0,
        Query = 0x0001,
        Set = 0x0002,
        Notification = 0x0004,
        ReadDescription = 0x0008,
        Execute = 0x0010,
        CreateRealtime = 0x0020,
        CreateOnDisk = 0x0040,
        GuidEnable = 0x0080,
        AccessKernelLogger = 0x0100,
        CreateInproc = 0x0200,
        AccessRealtime = 0x0400,
        RegisterGuids = 0x0800,
        JoinGroup = 0x1000,
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

    public static class TraceKnownGuids
    {
        /// <summary>
        /// The security trace provider GUID.
        /// </summary>
        public static readonly Guid SecurityProvider = new Guid("54849625-5478-4994-A5BA-3E3B0328C30D");
        /// <summary>
        /// The default security GUID.
        /// </summary>
        public static readonly Guid DefaultTraceSecurity = new Guid("0811C1AF-7A07-4A06-82ED-869455CDF713");
    }

    public enum TraceControlFunctionCode : uint
    {
        Start = 1,
        Stop = 2,
        Query = 3,
        Update = 4,
        Flush = 5,
        IncrementFile = 6,
        RealtimeConnect = 11,
        CreateActivityId = 12,
        DispatchControl = 13,
        RealtimeDisconnect = 14,
        RegisterGuid = 15,          // IN: Handle to registration block. OUT: Handle to result block.
        ReceiveNotification = 16,
        EnableOrNotify = 17,
        SendReply = 18,
        ReceiveReply = 19,
        UpdateSem = 20,
        GetGuidList = 21,
        GetGuidInfo = 22,
        EnumerateGuids = 23,
        RegisterSecurityProvider = 24,
        QueryReferenceTime = 25,
        TrackProviderBinary = 26,
        AddNotificationEvent = 27, // IN: HANDLE to NtEvent.
        UpdateDisallowList = 28,
        SetProviderTraits = 30,
        UseDescriptorType = 31,
        GetGroupList = 32,
        GetGroupInfo = 33,
        GetDisallowList = 34,
        SetCompressionSettings = 35,
        GetCompressionSettings = 36,
        UpdatePeriodicCaptureState = 37,
        GetPrivateSessionHandle = 38,
        RegisterPrivateSession = 39,
        QuerySessionDemuxObject = 40,
        SetTrackProviderBinary = 41,
        GetMaxLogger = 42,
        Wow64 = 0x80000000,
    }

    public enum TraceEventFlags : uint
    {
        None = 0,
        Header = 0x100,
        Message = 0x200,
        Event = 0x300,
        System = 0x400,
        Security = 0x500,
        Mark = 0x600,
        EventNoReg = 0x700,
        Instance = 0x800,
        Raw = 0x900,
        UseNativeHeader = 0x40000000,
        Wow64 = 0x80000000
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtTraceEvent(
            SafeHandle TraceHandle,
            TraceEventFlags Flags,
            int FieldSize,
            SafeBuffer Fields
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtTraceEvent(
            ref Guid TraceHandle,
            TraceEventFlags Flags,
            int FieldSize,
            SafeBuffer Fields
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtTraceControl(
            TraceControlFunctionCode FunctionCode,
            SafeBuffer InBuffer,
            int InBufferLen,
            SafeBuffer OutBuffer,
            int OutBufferLen,
            out int ReturnLength
        );
    }
#pragma warning restore 1591
}
