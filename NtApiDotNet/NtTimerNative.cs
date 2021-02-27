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
    public enum TimerAccessRights : uint
    {
        [SDKName("TIMER_QUERY_STATE")]
        Query = 0x0001,
        [SDKName("TIMER_SET_STATE")]
        Set = 0x0002,
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

    public enum TimerInformationClass
    {
        TimerBasicInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TimerBasicInformation
    {
        public LargeIntegerStruct RemainingTime;
        public bool TimerState;
    }

    /// <summary>
    /// Delegate for Timer APC callbacks.
    /// </summary>
    /// <param name="TimerContext">Context parameter.</param>
    /// <param name="TimerLowValue">Low value of timer.</param>
    /// <param name="TimerHighValue">High value of timer.</param>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void TimerApcCallback(IntPtr TimerContext, uint TimerLowValue, int TimerHighValue);

    public enum TimerSetInformationClass
    {
        TimerSetCoalescableTimer,
    }

    public enum TimerType
    {
        Notification,
        Synchronization
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TimerSetCoalescableTimerInfo
    {
        public LargeIntegerStruct DueTime;
        public IntPtr TimerApcRoutine;
        public IntPtr TimerContext;
        public IntPtr WakeContext; // _COUNTED_REASON_CONTEXT
        public int Period;
        public int TolerableDelay;
        public IntPtr PreviousState;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateTimer(
            out SafeKernelObjectHandle TimerHandle,
            TimerAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes,
            TimerType TimerType
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenTimer(
            out SafeKernelObjectHandle TimerHandle,
            TimerAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetTimer(
            SafeKernelObjectHandle TimerHandle,
            LargeInteger DueTime,
            IntPtr TimerApcRoutine,
            IntPtr TimerContext,
            bool ResumeTimer,
            int Period,
            out bool PreviousState
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetTimerEx(
            SafeKernelObjectHandle TimerHandle,
            TimerSetInformationClass TimerSetInformationClass,
            SafeBuffer TimerSetInformation,
            int TimerSetInformationLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCancelTimer(
            SafeKernelObjectHandle TimerHandle,
            out bool CurrentState
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryTimer(
            SafeKernelObjectHandle TimerHandle,
            TimerInformationClass TimerInformationClass,
            SafeBuffer TimerInformation,
            int TimerInformationLength,
            out int ReturnLength
        );
    }
#pragma warning restore 1591
}
