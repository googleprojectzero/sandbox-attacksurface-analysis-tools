//  Copyright 2016 Google Inc. All Rights Reserved.
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
    public enum EventAccessRights : uint
    {
        QueryState = 1,
        ModifyState = 2,
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
    public enum EventType
    {
        NotificationEvent,
        SynchronizationEvent
    }

    public enum EventInformationClass
    {
        EventBasicInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EventBasicInformation
    {
        public EventType EventType;
        public int EventState;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateEvent(
            out SafeKernelObjectHandle EventHandle,
            EventAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            EventType EventType,
            bool InitialState);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenEvent(
            out SafeKernelObjectHandle EventHandle,
            EventAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetEvent(
            SafeKernelObjectHandle EventHandle,
            out int PreviousState);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtClearEvent(
            SafeKernelObjectHandle EventHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPulseEvent(
            SafeKernelObjectHandle EventHandle,
            out int PreviousState);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryEvent(
            SafeKernelObjectHandle EventHandle,
            EventInformationClass EventInformationClass,
            SafeBuffer EventInformation,
            int EventInformationLength,
            out int ResultLength);
    }
#pragma warning restore 1591
}
