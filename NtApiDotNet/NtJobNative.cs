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
    public enum JobAccessRights : uint
    {
        None = 0,
        AssignProcess = 0x1,
        SetAttributes = 0x2,
        Query = 0x4,
        Terminate = 0x8,
        SetSecurityAttributes = 0x10,
        Impersonate = 0x20,
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

    public enum JobObjectInformationClass
    {
        JobObjectBasicAccountingInformation = 1,
        JobObjectBasicLimitInformation,
        JobObjectBasicProcessIdList,
        JobObjectBasicUIRestrictions,
        JobObjectSecurityLimitInformation,
        JobObjectEndOfJobTimeInformation,
        JobObjectAssociateCompletionPortInformation,
        JobObjectBasicAndIoAccountingInformation,
        JobObjectExtendedLimitInformation,
        JobObjectJobSetInformation,
        JobObjectGroupInformation,
        JobObjectNotificationLimitInformation,
        JobObjectLimitViolationInformation,
        JobObjectGroupInformationEx,
        JobObjectCpuRateControlInformation,
        JobObjectCompletionFilter,
        JobObjectCompletionCounter,
        JobObjectFreezeInformation,
        JobObjectExtendedAccountingInformation,
        JobObjectWakeInformation,
        JobObjectBackgroundInformation,
        JobObjectSchedulingRankBiasInformation,
        JobObjectTimerVirtualizationInformation,
        JobObjectCycleTimeNotification,
        JobObjectClearEvent,
        JobObjectInterferenceInformation,
        JobObjectClearPeakJobMemoryUsed,
        JobObjectMemoryUsageInformation,
        JobObjectSharedCommit,
        JobObjectContainerId,
        JobObjectIoRateControlInformation,
        JobObjectNetRateControlInformation,
        JobObjectNotificationLimitInformation2,
        JobObjectLimitViolationInformation2,
        JobObjectCreateSilo,
        JobObjectSiloBasicInformation,
        JobObjectSiloRootDirectory,
        JobObjectServerSiloBasicInformation,
        JobObjectServerSiloUserSharedData,
        JobObjectServerSiloInitialize,
        JobObjectServerSiloRunningState,
        JobObjectIoAttribution,
        JobObjectMemoryPartitionInformation,
        JobObjectContainerTelemetryId,
        JobObjectSiloSystemRoot,
        JobObjectEnergyTrackingState,
        JobObjectThreadImpersonationInformation,
    }

    public enum JobObjectCompletionPortMessages
    {
        EndOfJobTime = 1,
        EndOfProcessTime = 2,
        ActiveProcessLimit = 3,
        ActiveProcessZero = 4,
        Unknown5 = 5,
        NewProcess = 6,
        ExitProcess = 7,
        AbnormalExitProcess = 8,
        ProcessMemoryLimit = 9,
        JobMemoryLimit = 10,
        NotificationLimit = 11,
        JobCycleTimeLimit = 12,
        SiloTerminated = 13,
        MaxMessage = 14,
    }

    [Flags]
    public enum JobObjectCompletionPortMessageFilters
    {
        None = 0,
        EndOfJobTime = 1 << JobObjectCompletionPortMessages.EndOfJobTime,
        EndOfProcessTime = 1 << JobObjectCompletionPortMessages.EndOfProcessTime,
        ActiveProcessLimit = 1 << JobObjectCompletionPortMessages.ActiveProcessLimit,
        ActiveProcessZero = 1 << JobObjectCompletionPortMessages.ActiveProcessZero,
        Unknown5 = 1 << JobObjectCompletionPortMessages.Unknown5,
        NewProcess = 1 << JobObjectCompletionPortMessages.NewProcess,
        ExitProcess = 1 << JobObjectCompletionPortMessages.ExitProcess,
        AbnormalExitProcess = 1 << JobObjectCompletionPortMessages.AbnormalExitProcess,
        ProcessMemoryLimit = 1 << JobObjectCompletionPortMessages.ProcessMemoryLimit,
        JobMemoryLimit = 1 << JobObjectCompletionPortMessages.JobMemoryLimit,
        NotificationLimit = 1 << JobObjectCompletionPortMessages.NotificationLimit,
        JobCycleTimeLimit = 1 << JobObjectCompletionPortMessages.JobCycleTimeLimit,
        SiloTerminated = 1 << JobObjectCompletionPortMessages.SiloTerminated,
        MaxMessage = 1 << JobObjectCompletionPortMessages.MaxMessage
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectAssociateCompletionPort
    {
        public IntPtr CompletionKey;
        public IntPtr CompletionPort;
    }

    [Flags]
    public enum JobObjectLimitFlags
    {
        None = 0,
        WorkingSet = 0x00000001,
        ProcessTime = 0x00000002,
        JobTime = 0x00000004,
        ActiveProcess = 0x00000008,
        Affinity = 0x00000010,
        PriorityClass = 0x00000020,
        PreserveJobTime = 0x00000040,
        SchedulingClass = 0x00000080,
        ProcessMemory = 0x00000100,
        JobMemory = 0x00000200,
        DieOnUnhandledException = 0x00000400,
        BreakawayOk = 0x00000800,
        SilentBreakawayOk = 0x00001000,
        KillOnJobClose = 0x00002000,
        SubsetAffinity = 0x00004000,
        JobMemoryLow = 0x00008000,
        Application = 0x00400000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectBasicLimitInformation
    {
        public LargeIntegerStruct PerProcessUserTimeLimit;
        public LargeIntegerStruct PerJobUserTimeLimit;
        public JobObjectLimitFlags LimitFlags;
        public IntPtr MinimumWorkingSetSize;
        public IntPtr MaximumWorkingSetSize;
        public int ActiveProcessLimit;
        public IntPtr Affinity;
        public int PriorityClass;
        public int SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public IntPtr ProcessMemoryLimit;
        public IntPtr JobMemoryLimit;
        public IntPtr PeakProcessMemoryUsed;
        public IntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectExtendedLimitInformationV2
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public IntPtr ProcessMemoryLimit;
        public IntPtr JobMemoryLimit;
        public IntPtr PeakProcessMemoryUsed;
        public IntPtr PeakJobMemoryUsed;
        public IntPtr JobTotalMemoryLimit;
    }

    [Flags]
    public enum JobObjectNetRateControlFlags
    {
        None = 0,
        Enable = 0x1,
        MaxBandwidth = 0x2,
        DscpTag = 0x4,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectNetRateControlInformation
    {
        public ulong MaxBandwidth;
        public JobObjectNetRateControlFlags ControlFlags;
        public byte DscpTag;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("ProcessIdList")]
    public struct JobObjectBasicProcessIdList
    {
        public int NumberOfAssignedProcesses;
        public int NumberOfProcessIdsInList;
        public IntPtr ProcessIdList;
    }

    [Flags]
    public enum JobObjectUiLimitFlags
    {
        None = 0,
        Handles = 1,
        ReadClipboard = 2,
        WriteClipboard = 4,
        SystemParameters = 8,
        DisplaySettings = 0x10,
        GlobalAtoms = 0x20,
        Desktop = 0x40,
        ExitWindows = 0x80
    }

    [Flags]
    public enum JobObjectFreezeFlags
    {
        None = 0,
        FreezeOperation = 1,
        FilterOperation = 2,
        SwapOperation = 4,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectFreezeInformation
    {
        public JobObjectFreezeFlags Flags;
        [MarshalAs(UnmanagedType.U1)] public bool Freeze;
        [MarshalAs(UnmanagedType.U1)] public bool Swap;
        public uint HighEdgeFilter;
        public uint LowEdgeFilter;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectContainerIdentifierV2
    {
        public Guid ContainerId;
        public Guid ContainerTelemetryId;
        public int JobId;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateJobObject(out SafeKernelObjectHandle JobHandle, JobAccessRights DesiredAccess, [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenJobObject(out SafeKernelObjectHandle JobHandle, JobAccessRights DesiredAccess, [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAssignProcessToJobObject(SafeKernelObjectHandle JobHandle, SafeKernelObjectHandle ProcessHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtTerminateJobObject(SafeKernelObjectHandle JobHandle, NtStatus ExitStatus);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationJobObject(SafeKernelObjectHandle JobHandle, JobObjectInformationClass JobInfoClass,
            SafeBuffer JobInformation, int JobInformationLength, out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationJobObject(SafeKernelObjectHandle JobHandle, JobObjectInformationClass JobInfoClass,
            SafeBuffer JobInformation, int JobInformationLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtIsProcessInJob(
            SafeKernelObjectHandle ProcessHandle,
            SafeKernelObjectHandle JobHandle
        );
    }
#pragma warning restore 1591
}
