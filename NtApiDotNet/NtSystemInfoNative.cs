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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591

    public enum SystemEnvironmentValueInformationClass
    {
        NamesOnly = 1,
        NamesAndValues = 2,
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQuerySystemInformation(
          SystemInformationClass SystemInformationClass,
          SafeBuffer SystemInformation,
          int SystemInformationLength,
          out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQuerySystemInformationEx(
            SystemInformationClass SystemInformationClass,
            SafeBuffer InputBuffer,
            int InputBufferLength,
            SafeBuffer SystemInformation,
            int SystemInformationLength,
            out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetSystemInformation(
          SystemInformationClass SystemInformationClass,
          SafeBuffer SystemInformation,
          int SystemInformationLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSystemDebugControl(
            SystemDebugCommand ControlCode,
            SafeBuffer InputBuffer,
            int InputBufferLength,
            SafeBuffer OutputBuffer,
            int OutputBufferLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtEnumerateSystemEnvironmentValuesEx(
            SystemEnvironmentValueInformationClass SystemEnvironmentValueInformationClass,
            SafeBuffer Buffer, ref int BufferLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQuerySystemEnvironmentValueEx([In] UnicodeString ValueName,
            ref Guid VendorGuid, [Out] byte[] Value, ref int ValueLength, OptionalInt32 Attributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetSystemEnvironmentValueEx([In] UnicodeString VariableName,
            ref Guid VendorGuid, [In] byte[] Value, int ValueLength, int Attributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAllocateLocallyUniqueId(out Luid Luid);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDrawText([In] UnicodeString Text);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDisplayString([In] UnicodeString Text);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtLoadDriver(
            [In] UnicodeString DriverServiceName
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtUnloadDriver(
            [In] UnicodeString DriverServiceName
        );
    }

    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlGetNativeSystemInformation(
          SystemInformationClass SystemInformationClass,
          SafeBuffer SystemInformation,
          int SystemInformationLength,
          out int ReturnLength
        );
    }

    [Flags]
    public enum SystemEnvironmentValueAttribute
    {
        None = 0x0000,
        NonVolatile = 0x0001,
        BootServiceAccess = 0x0002,
        RuntimeAccess = 0x0004,
        ErrorRecord = 0x0008,
        WriteAccess = 0x0010,
        TimeBasedAuthenticatedWriteAccess = 0x0020,
        AppendWrite = 0x0040,
    }

    public sealed class SystemEnvironmentValue
    {
        public string Name { get; }
        public Guid VendorGuid { get; }
        public byte[] Value { get; }
        public SystemEnvironmentValueAttribute Attributes { get; }

        internal SystemEnvironmentValue(SafeStructureInOutBuffer<SystemEnvironmentValueNameAndValue> buffer)
        {
            SystemEnvironmentValueNameAndValue value = buffer.Result;
            Name = buffer.Data.ReadNulTerminatedUnicodeString();
            Value = buffer.ReadBytes((ulong)value.ValueOffset, value.ValueLength);
            Attributes = value.Attributes;
            VendorGuid = value.VendorGuid;
        }

        internal SystemEnvironmentValue(string name, byte[] value, OptionalInt32 attributes, OptionalGuid vendor_guid)
        {
            Name = name;
            Value = value;
            Attributes = (SystemEnvironmentValueAttribute)attributes.Value;
            VendorGuid = vendor_guid.Value;
        }
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Name")]
    public struct SystemEnvironmentValueName
    {
        public int NextEntryOffset;
        public Guid VendorGuid;
        public char Name;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Name")]
    public struct SystemEnvironmentValueNameAndValue
    {
        public int NextEntryOffset;
        public int ValueOffset;
        public int ValueLength;
        public SystemEnvironmentValueAttribute Attributes;
        public Guid VendorGuid;
        public char Name;
        //UCHAR Value[ANYSIZE_ARRAY];
    }

    public enum SystemDebugCommand
    {
        SysDbgQueryModuleInformation = 0,
        SysDbgQueryTraceInformation = 1,
        SysDbgSetTracepoint = 2,
        SysDbgSetSpecialCall = 3,
        SysDbgClearSpecialCalls = 4,
        SysDbgQuerySpecialCalls = 5,
        SysDbgBreakPoint = 6,
        SysDbgQueryVersion = 7,
        SysDbgReadVirtual = 8,
        SysDbgWriteVirtual = 9,
        SysDbgReadPhysical = 10,
        SysDbgWritePhysical = 11,
        SysDbgReadControlSpace = 12,
        SysDbgWriteControlSpace = 13,
        SysDbgReadIoSpace = 14,
        SysDbgWriteIoSpace = 15,
        SysDbgReadMsr = 16,
        SysDbgWriteMsr = 17,
        SysDbgReadBusData = 18,
        SysDbgWriteBusData = 19,
        SysDbgCheckLowMemory = 20,
        SysDbgEnableKernelDebugger = 21,
        SysDbgDisableKernelDebugger = 22,
        SysDbgGetAutoKdEnable = 23,
        SysDbgSetAutoKdEnable = 24,
        SysDbgGetPrintBufferSize = 25,
        SysDbgSetPrintBufferSize = 26,
        SysDbgGetKdUmExceptionEnable = 27,
        SysDbgSetKdUmExceptionEnable = 28,
        SysDbgGetTriageDump = 29,
        SysDbgGetKdBlockEnable = 30,
        SysDbgSetKdBlockEnable = 31,
        SysDbgRegisterForUmBreakInfo = 32,
        SysDbgGetUmBreakPid = 33,
        SysDbgClearUmBreakPid = 34,
        SysDbgGetUmAttachPid = 35,
        SysDbgClearUmAttachPid = 36,
        SysDbgGetLiveKernelDump = 37,
    }

    [Flags]
    public enum SystemDebugKernelDumpControlFlags
    {
        None = 0,
        UseDumpStorageStack = 1,
        CompressMemoryPagesData = 2,
        IncludeUserSpaceMemoryPages = 4,
        AbortIfMemoryPressure = 8,
    }

    [Flags]
    public enum SystemDebugKernelDumpPageControlFlags
    {
        None = 0,
        HypervisorPages = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemDebugKernelDumpConfig
    {
        public int Version;
        public int BugCheckCode;
        public IntPtr BugCheckParam1;
        public IntPtr BugCheckParam2;
        public IntPtr BugCheckParam3;
        public IntPtr BugCheckParam4;
        public IntPtr FileHandle;
        public IntPtr EventHandle;
        public SystemDebugKernelDumpControlFlags Flags;
        public SystemDebugKernelDumpPageControlFlags PageFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemHandleTableInfoEntry
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public UIntPtr Object;
        public uint GrantedAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemHandleTableInfoEntryEx
    {
        public UIntPtr Object;
        public IntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public AccessMask GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Handles")]
    public struct SystemHandleInformationEx
    {
        public IntPtr NumberOfHandles;
        public IntPtr Reserved;
        public SystemHandleTableInfoEntryEx Handles;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemThreadInformation
    {
        public LargeIntegerStruct KernelTime;
        public LargeIntegerStruct UserTime;
        public LargeIntegerStruct CreateTime;
        public uint WaitTime;
        public IntPtr StartAddress;
        public ClientIdStruct ClientId;
        public int Priority;
        public int BasePriority;
        public uint ContextSwitches;
        public uint ThreadState;
        public int WaitReason;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemExtendedThreadInformation
    {
        public SystemThreadInformation ThreadInfo;
        public IntPtr StackBase;
        public IntPtr StackLimit;
        public IntPtr Win32StartAddress;
        public IntPtr TebBase;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr Reserved4;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Threads")]
    public struct SystemProcessInformation
    {
        public int NextEntryOffset;
        public int NumberOfThreads;
        public LargeIntegerStruct WorkingSetPrivateSize; // since VISTA
        public uint HardFaultCount; // since WIN7
        public uint NumberOfThreadsHighWatermark; // since WIN7
        public ulong CycleTime; // since WIN7
        public LargeIntegerStruct CreateTime;
        public LargeIntegerStruct UserTime;
        public LargeIntegerStruct KernelTime;
        public UnicodeStringOut ImageName;
        public int BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
        public int HandleCount;
        public int SessionId;
        public IntPtr UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
        public IntPtr PeakVirtualSize;
        public IntPtr VirtualSize;
        public uint PageFaultCount;
        public IntPtr PeakWorkingSetSize;
        public IntPtr WorkingSetSize;
        public IntPtr QuotaPeakPagedPoolUsage;
        public IntPtr QuotaPagedPoolUsage;
        public IntPtr QuotaPeakNonPagedPoolUsage;
        public IntPtr QuotaNonPagedPoolUsage;
        public IntPtr PagefileUsage;
        public IntPtr PeakPagefileUsage;
        public IntPtr PrivatePageCount;
        public LargeIntegerStruct ReadOperationCount;
        public LargeIntegerStruct WriteOperationCount;
        public LargeIntegerStruct OtherOperationCount;
        public LargeIntegerStruct ReadTransferCount;
        public LargeIntegerStruct WriteTransferCount;
        public LargeIntegerStruct OtherTransferCount;
        public SystemThreadInformation Threads;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemPageFileInformation
    {
        public int NextEntryOffset;
        public int TotalSize;
        public int TotalInUse;
        public int PeekUsage;
        public UnicodeStringOut PageFileName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemKernelDebuggerInformation
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool KernelDebuggerEnabled;
        [MarshalAs(UnmanagedType.U1)]
        public bool KernelDebuggerNotPresent;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemKernelDebuggerInformationEx
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool KernelDebuggerAllowed;
        [MarshalAs(UnmanagedType.U1)]
        public bool KernelDebuggerEnabled;
        [MarshalAs(UnmanagedType.U1)]
        public bool KernelDebuggerNotPresent;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemSecurebootInformation
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool SecureBootEnabled;
        [MarshalAs(UnmanagedType.U1)]
        public bool SecureBootCapable;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemSecurebootPolicyInformation
    {
        public Guid PolicyPublisher;
        public int PolicyVersion;
        public int PolicyOptions;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Policy")]
    public struct SystemSecurebootPolicyFullInformation
    {
        public SystemSecurebootPolicyInformation PolicyInformation;
        public int PolicySize;
        public byte Policy;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("SiloIdList")]
    public struct SystemRootSiloInformation
    {
        public int NumberOfSilos;
        public int SiloIdList;
    }

    public class SecureBootPolicy
    {
        public Guid PolicyPublisher { get; }
        public int PolicyVersion { get; }
        public int PolicyOptions { get; }
        public byte[] Policy { get; }

        internal SecureBootPolicy(SafeStructureInOutBuffer<SystemSecurebootPolicyFullInformation> policy)
        {
            SystemSecurebootPolicyFullInformation policy_struct = policy.Result;
            PolicyPublisher = policy_struct.PolicyInformation.PolicyPublisher;
            PolicyVersion = policy_struct.PolicyInformation.PolicyVersion;
            PolicyOptions = policy_struct.PolicyInformation.PolicyOptions;
            Policy = policy.Data.ReadBytes(policy_struct.PolicySize);
        }
    }

    [Flags]
    public enum CodeIntegrityOptions
    {
        None = 0,
        Enabled = 0x01,
        TestSign = 0x02,
        UmciEnabled = 0x04,
        UmciAuditModeEnabled = 0x08,
        UmciExclusionPathsEnabled = 0x10,
        TestBuild = 0x20,
        PreProductionBuild = 0x40,
        DebugModeEnabled = 0x80,
        FlightBuild = 0x100,
        FlightingEnabled = 0x200,
        HvciKmciEnabled = 0x400,
        HvciKmciAuditModeEnabled = 0x800,
        HvciKmciStrictModeEnabled = 0x1000,
        HvciIumEnabled = 0x2000,
        WhqlEnforcementEnabled = 0x4000,
        WhqlAuditModeEnabled = 0x8000,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemCodeIntegrityInformation
    {
        public int Length;
        public CodeIntegrityOptions CodeIntegrityOptions;
    }

    public class CodeIntegrityPolicy
    {
        public int PolicyType { get; }
        public byte[] Policy { get; }

        internal CodeIntegrityPolicy(BinaryReader reader)
        {
            int header_length = reader.ReadInt32();
            int policy_length = reader.ReadInt32();
            PolicyType = reader.ReadInt32();
            reader.ReadBytes(header_length - 12);
            Policy = reader.ReadBytes(policy_length);
        }

        internal CodeIntegrityPolicy(byte[] policy)
        {
            Policy = policy;
        }
    }

    [Flags]
    public enum SystemCodeIntegrityPolicyOptions : uint
    {
        None = 0,
        Enabled = 1,
        Audit = 2,
        RequireWHQL = 4,
        DisabledFlightSigning = 8,
        EnabledUMCI = 0x10,
        EnabledUpdatePolicyNoReboot = 0x20,
        EnabledSecureSettingPolicy = 0x40,
        EnabledUnsignedSystemIntegrityPolicy = 0x80,
        DynamicCodePolicyEnabled = 0x100,
        Flag200 = 0x200,
        Flag400 = 0x400,
        Flag800 = 0x800,
        Flag1000 = 0x1000,
        Flag2000 = 0x2000,
        Flag4000 = 0x4000,
        Flag8000 = 0x8000,
        Flag10000 = 0x10000,
        Flag20000 = 0x20000,
        Flag40000 = 0x40000,
        Flag80000 = 0x80000,
        Flag100000 = 0x100000,
        Flag200000 = 0x200000,
        Flag400000 = 0x400000,
        Flag800000 = 0x800000,
        Flag1000000 = 0x1000000,
        Flag2000000 = 0x2000000,
        Flag4000000 = 0x4000000,
        Flag8000000 = 0x8000000,
        Flag10000000 = 0x10000000,
        ConditionalLockdown = 0x20000000,
        NoLockdown = 0x40000000,
        Lockdown = 0x80000000
    }

    [Flags]
    public enum SystemCodeIntegrityPolicyHVCIOptions : uint
    {
        None = 0,
        Enabled = 1,
        Strict = 2,
        Debug = 4
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemCodeIntegrityPolicy
    {
        public SystemCodeIntegrityPolicyOptions Options;
        public SystemCodeIntegrityPolicyHVCIOptions HVCIOptions;
        public ushort VersionRevision;
        public ushort VersionBuild;
        public ushort VersionMinor;
        public ushort VersionMajor;
        public Guid PolicyGuid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemCodeIntegrityVerificationInformation
    {
        public IntPtr FileHandle;
        public int ImageSize;
        public IntPtr Image;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemBasicInformation
    {
        public int Reserved;
        public int TimerResolution;
        public int PageSize;
        public int NumberOfPhysicalPages;
        public int LowestPhysicalPageNumber;
        public int HighestPhysicalPageNumber;
        public int AllocationGranularity;
        public UIntPtr MinimumUserModeAddress;
        public UIntPtr MaximumUserModeAddress;
        public UIntPtr ActiveProcessorsAffinityMask;
        public sbyte NumberOfProcessors;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemElamCertificateInformation
    {
        public IntPtr ElamDriverFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemCodeIntegrityCertificateInformation
    {
        public IntPtr ImageFile;
        public int Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemProcessIdInformation
    {
        public IntPtr ProcessId;
        public UnicodeStringOut ImageName;
    };

    public enum ProcessorAchitecture : ushort
    {
        Intel = 0,
        MIPS = 1,
        Alpha = 2,
        PPC = 3,
        SHX = 4,
        ARM = 5,
        IA64 = 6,
        Alpha64 = 7,
        MSIL = 8,
        AMD64 = 9,
        IA32OnWin64 = 10,
        Neutral = 11,
        ARM64 = 12,
        ARM32OnWin64 = 13,
        IA32OnARM64 = 14,
        Unknonw = 0xFFFF,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemProcessorInformation
    {
        public ProcessorAchitecture ProcessorArchitecture;
        public ushort ProcessorLevel;
        public ushort ProcessorRevision;
        public ushort MaximumProcessors;
        public uint ProcessorFeatureBits;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Modules")]
    public struct RtlProcessModules
    {
        public int NumberOfModules;
        public RtlProcessModuleInformation Modules;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct RtlProcessModuleInformation
    {
        public UIntPtr Section;
        public UIntPtr MappedBase;
        public UIntPtr ImageBase;
        public int ImageSize;
        public int Flags;
        public ushort LoadOrderIndex;
        public ushort InitOrderIndex;
        public ushort LoadCount;
        public ushort OffsetToFileName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] FullPathName;
    }

    public enum SystemInformationClass
    {
        SystemBasicInformation = 0,
        SystemProcessorInformation = 1,
        SystemPerformanceInformation = 2,
        SystemTimeOfDayInformation = 3,
        SystemPathInformation = 4,
        SystemProcessInformation = 5,
        SystemCallCountInformation = 6,
        SystemDeviceInformation = 7,
        SystemProcessorPerformanceInformation = 8,
        SystemFlagsInformation = 9,
        SystemCallTimeInformation = 10,
        SystemModuleInformation = 11,
        SystemLocksInformation = 12,
        SystemStackTraceInformation = 13,
        SystemPagedPoolInformation = 14,
        SystemNonPagedPoolInformation = 15,
        SystemHandleInformation = 16,
        SystemObjectInformation = 17,
        SystemPageFileInformation = 18,
        SystemVdmInstemulInformation = 19,
        SystemVdmBopInformation = 20,
        SystemFileCacheInformation = 21,
        SystemPoolTagInformation = 22,
        SystemInterruptInformation = 23,
        SystemDpcBehaviorInformation = 24,
        SystemFullMemoryInformation = 25,
        SystemLoadGdiDriverInformation = 26,
        SystemUnloadGdiDriverInformation = 27,
        SystemTimeAdjustmentInformation = 28,
        SystemSummaryMemoryInformation = 29,
        SystemMirrorMemoryInformation = 30,
        SystemPerformanceTraceInformation = 31,
        SystemObsolete0 = 32,
        SystemExceptionInformation = 33,
        SystemCrashDumpStateInformation = 34,
        SystemKernelDebuggerInformation = 35,
        SystemContextSwitchInformation = 36,
        SystemRegistryQuotaInformation = 37,
        SystemExtendServiceTableInformation = 38,
        SystemPrioritySeperation = 39,
        SystemVerifierAddDriverInformation = 40,
        SystemVerifierRemoveDriverInformation = 41,
        SystemProcessorIdleInformation = 42,
        SystemLegacyDriverInformation = 43,
        SystemCurrentTimeZoneInformation = 44,
        SystemLookasideInformation = 45,
        SystemTimeSlipNotification = 46,
        SystemSessionCreate = 47,
        SystemSessionDetach = 48,
        SystemSessionInformation = 49,
        SystemRangeStartInformation = 50,
        SystemVerifierInformation = 51,
        SystemVerifierThunkExtend = 52,
        SystemSessionProcessInformation = 53,
        SystemLoadGdiDriverInSystemSpace = 54,
        SystemNumaProcessorMap = 55,
        SystemPrefetcherInformation = 56,
        SystemExtendedProcessInformation = 57,
        SystemRecommendedSharedDataAlignment = 58,
        SystemComPlusPackage = 59,
        SystemNumaAvailableMemory = 60,
        SystemProcessorPowerInformation = 61,
        SystemEmulationBasicInformation = 62,
        SystemEmulationProcessorInformation = 63,
        SystemExtendedHandleInformation = 64,
        SystemLostDelayedWriteInformation = 65,
        SystemBigPoolInformation = 66,
        SystemSessionPoolTagInformation = 67,
        SystemSessionMappedViewInformation = 68,
        SystemHotpatchInformation = 69,
        SystemObjectSecurityMode = 70,
        SystemWatchdogTimerHandler = 71,
        SystemWatchdogTimerInformation = 72,
        SystemLogicalProcessorInformation = 73,
        SystemWow64SharedInformationObsolete = 74,
        SystemRegisterFirmwareTableInformationHandler = 75,
        SystemFirmwareTableInformation = 76,
        SystemModuleInformationEx = 77,
        SystemVerifierTriageInformation = 78,
        SystemSuperfetchInformation = 79,
        SystemMemoryListInformation = 80,
        SystemFileCacheInformationEx = 81,
        SystemThreadPriorityClientIdInformation = 82,
        SystemProcessorIdleCycleTimeInformation = 83,
        SystemVerifierCancellationInformation = 84,
        SystemProcessorPowerInformationEx = 85,
        SystemRefTraceInformation = 86,
        SystemSpecialPoolInformation = 87,
        SystemProcessIdInformation = 88,
        SystemErrorPortInformation = 89,
        SystemBootEnvironmentInformation = 90,
        SystemHypervisorInformation = 91,
        SystemVerifierInformationEx = 92,
        SystemTimeZoneInformation = 93,
        SystemImageFileExecutionOptionsInformation = 94,
        SystemCoverageInformation = 95,
        SystemPrefetchPatchInformation = 96,
        SystemVerifierFaultsInformation = 97,
        SystemSystemPartitionInformation = 98,
        SystemSystemDiskInformation = 99,
        SystemProcessorPerformanceDistribution = 100,
        SystemNumaProximityNodeInformation = 101,
        SystemDynamicTimeZoneInformation = 102,
        SystemCodeIntegrityInformation = 103,
        SystemProcessorMicrocodeUpdateInformation = 104,
        SystemProcessorBrandString = 105,
        SystemVirtualAddressInformation = 106,
        SystemLogicalProcessorAndGroupInformation = 107,
        SystemProcessorCycleTimeInformation = 108,
        SystemStoreInformation = 109,
        SystemRegistryAppendString = 110,
        SystemAitSamplingValue = 111,
        SystemVhdBootInformation = 112,
        SystemCpuQuotaInformation = 113,
        SystemNativeBasicInformation = 114,
        SystemErrorPortTimeouts = 115,
        SystemLowPriorityIoInformation = 116,
        SystemBootEntropyInformation = 117,
        SystemVerifierCountersInformation = 118,
        SystemPagedPoolInformationEx = 119,
        SystemSystemPtesInformationEx = 120,
        SystemNodeDistanceInformation = 121,
        SystemAcpiAuditInformation = 122,
        SystemBasicPerformanceInformation = 123,
        SystemQueryPerformanceCounterInformation = 124,
        SystemSessionBigPoolInformation = 125,
        SystemBootGraphicsInformation = 126,
        SystemScrubPhysicalMemoryInformation = 127,
        SystemBadPageInformation = 128,
        SystemProcessorProfileControlArea = 129,
        SystemCombinePhysicalMemoryInformation = 130,
        SystemEntropyInterruptTimingInformation = 131,
        SystemConsoleInformation = 132,
        SystemPlatformBinaryInformation = 133,
        SystemPolicyInformation = 134,
        SystemHypervisorProcessorCountInformation = 135,
        SystemDeviceDataInformation = 136,
        SystemDeviceDataEnumerationInformation = 137,
        SystemMemoryTopologyInformation = 138,
        SystemMemoryChannelInformation = 139,
        SystemBootLogoInformation = 140,
        SystemProcessorPerformanceInformationEx = 141,
        SystemCriticalProcessErrorLogInformation = 142,
        SystemSecureBootPolicyInformation = 143,
        SystemPageFileInformationEx = 144,
        SystemSecureBootInformation = 145,
        SystemEntropyInterruptTimingRawInformation = 146,
        SystemPortableWorkspaceEfiLauncherInformation = 147,
        SystemFullProcessInformation = 148,
        SystemKernelDebuggerInformationEx = 149,
        SystemBootMetadataInformation = 150,
        SystemSoftRebootInformation = 151,
        SystemElamCertificateInformation = 152,
        SystemOfflineDumpConfigInformation = 153,
        SystemProcessorFeaturesInformation = 154,
        SystemRegistryReconciliationInformation = 155,
        SystemEdidInformation = 156,
        SystemManufacturingInformation = 157,
        SystemEnergyEstimationConfigInformation = 158,
        SystemHypervisorDetailInformation = 159,
        SystemProcessorCycleStatsInformation = 160,
        SystemVmGenerationCountInformation = 161,
        SystemTrustedPlatformModuleInformation = 162,
        SystemKernelDebuggerFlags = 163,
        SystemCodeIntegrityPolicyInformation = 164,
        SystemIsolatedUserModeInformation = 165,
        SystemHardwareSecurityTestInterfaceResultsInformation = 166,
        SystemSingleModuleInformation = 167,
        SystemAllowedCpuSetsInformation = 168,
        SystemVsmProtectionInformation = 169,
        SystemInterruptCpuSetsInformation = 170,
        SystemSecureBootPolicyFullInformation = 171,
        SystemCodeIntegrityPolicyFullInformation = 172,
        SystemAffinitizedInterruptProcessorInformation = 173,
        SystemRootSiloInformation = 174,
        SystemCpuSetInformation = 175,
        SystemCpuSetTagInformation = 176,
        SystemWin32WerStartCallout = 177,
        SystemSecureKernelProfileInformation = 178,
        SystemCodeIntegrityPlatformManifestInformation = 179,
        SystemInterruptSteeringInformation = 180,
        SystemSupportedProcessorArchitectures = 181,
        SystemMemoryUsageInformation = 182,
        SystemCodeIntegrityCertificateInformation = 183,
        SystemPhysicalMemoryInformation = 184,
        SystemControlFlowTransition = 185,
        SystemKernelDebuggingAllowed = 186,
        SystemActivityModerationExeState = 187,
        SystemActivityModerationUserSettings = 188,
        SystemCodeIntegrityPoliciesFullInformation = 189,
        SystemCodeIntegrityUnlockInformation = 190,
        SystemIntegrityQuotaInformation = 191,
        SystemFlushInformation = 192,
        SystemProcessorIdleMaskInformation = 193,
        SystemSecureDumpEncryptionInformation = 194,
        SystemWriteConstraintInformation = 195,
        SystemKernelVaShadowInformation = 196,
        SystemHypervisorSharedPageInformation = 197,
        SystemFirmwareBootPerformanceInformation = 198,
        SystemCodeIntegrityVerificationInformation = 199,
        SystemFirmwarePartitionInformation = 200,
        SystemSpeculationControlInformation = 201,
        SystemDmaGuardPolicyInformation = 202,
        SystemEnclaveLaunchControlInformation = 203,
        SystemWorkloadAllowedCpuSetsInformation = 204,
        SystemCodeIntegrityUnlockModeInformation = 205,
        SystemLeapSecondInformation = 206,
        SystemFlags2Information = 207,
    }

    public enum ThreadWaitReason
    {
        Executive = 0,
        FreePage = 1,
        PageIn = 2,
        PoolAllocation = 3,
        ExecutionDelay = 4,
        FreePage2 = 5,
        PageIn2 = 6,
        Executive2 = 7,
        FreePage3 = 8,
        PageIn3 = 9,
        PoolAllocation2 = 10,
        ExecutionDelay2 = 11,
        FreePage4 = 12,
        PageIn4 = 13,
        EventPairHigh = 14,
        EventPairLow = 15,
        LPCReceive = 16,
        LPCReply = 17,
        VirtualMemory = 18,
        PageOut = 19,
        Unknown = 20,
    }

    public enum ThreadState
    {
        Initialized = 0,
        Ready = 1,
        Running = 2,
        Standby = 3,
        Terminated = 4,
        Waiting = 5,
        Transition = 6,
        Unknown = 7
    }

    public class NtThreadInformation
    {
        public int ThreadId { get; }
        public int ProcessId { get; }
        public string ProcessName { get; }
        public long StartAddress { get; }
        public ThreadState ThreadState { get; }
        public ThreadWaitReason WaitReason { get; }
        public long KernelTime { get; }
        public long UserTime { get; }
        public long CreateTime { get; }
        public uint WaitTime { get; }
        public int Priority { get; }
        public int BasePriority { get; }
        public uint ContextSwitches { get; }

        internal NtThreadInformation(string name, SystemThreadInformation thread_info)
        {
            ProcessName = name;
            ThreadId = thread_info.ClientId.UniqueThread.ToInt32();
            ProcessId = thread_info.ClientId.UniqueProcess.ToInt32();
            StartAddress = thread_info.StartAddress.ToInt64();
            ThreadState = (ThreadState)thread_info.ThreadState;
            WaitReason = (ThreadWaitReason)thread_info.WaitReason;
            KernelTime = thread_info.KernelTime.QuadPart;
            UserTime = thread_info.UserTime.QuadPart;
            CreateTime = thread_info.CreateTime.QuadPart;
            WaitTime = thread_info.WaitTime;
            Priority = thread_info.Priority;
            BasePriority = thread_info.BasePriority;
            ContextSwitches = thread_info.ContextSwitches;
        }

        public override string ToString()
        {
            return ThreadId.ToString();
        }
    }

    public class NtThreadInformationExtended : NtThreadInformation
    {
        public long StackBase { get; }
        public long StackLimit { get; }
        public long Win32StartAddress { get; }
        public long TebBase { get; }
        
        internal NtThreadInformationExtended(string name, SystemExtendedThreadInformation thread_info) 
            : base(name, thread_info.ThreadInfo)
        {
            StackBase = thread_info.StackBase.ToInt64();
            StackLimit = thread_info.StackLimit.ToInt64();
            Win32StartAddress = thread_info.Win32StartAddress.ToInt64();
            TebBase = thread_info.TebBase.ToInt64();
        }

        public override string ToString()
        {
            return ThreadId.ToString();
        }
    }

    public class NtProcessInformation
    {
        public int ProcessId { get; }
        public int ParentProcessId { get; }
        public IEnumerable<NtThreadInformation> Threads { get; }
        public string ImageName { get; }
        public string ImagePath { get; }
        public int SessionId { get; }
        public long WorkingSetPrivateSize { get; }
        public uint HardFaultCount { get; }
        public uint NumberOfThreadsHighWatermark { get; }
        public ulong CycleTime { get; }
        public long CreateTime { get; }
        public long UserTime { get; }
        public long KernelTime { get; }
        public int BasePriority { get; }
        public int HandleCount { get; }
        public long UniqueProcessKey { get; }
        public long PeakVirtualSize { get; }
        public long VirtualSize { get; }
        public uint PageFaultCount { get; }
        public long PeakWorkingSetSize { get; }
        public long WorkingSetSize { get; }
        public long QuotaPeakPagedPoolUsage { get; }
        public long QuotaPagedPoolUsage { get; }
        public long QuotaPeakNonPagedPoolUsage { get; }
        public long QuotaNonPagedPoolUsage { get; }
        public long PagefileUsage { get; }
        public long PeakPagefileUsage { get; }
        public long PrivatePageCount { get; }
        public long ReadOperationCount { get; }
        public long WriteOperationCount { get; }
        public long OtherOperationCount { get; }
        public long ReadTransferCount { get; }
        public long WriteTransferCount { get; }
        public long OtherTransferCount { get; }

        internal NtProcessInformation(SystemProcessInformation process_info, IEnumerable<NtThreadInformation> threads, bool full_information)
        {
            ProcessId = process_info.UniqueProcessId.ToInt32();
            if (full_information)
            {
                ImagePath = process_info.ImageName.ToString();
                ImageName = ProcessId == 0 ? "Idle" : Path.GetFileName(ImagePath);
            }
            else
            {
                ImagePath = NtSystemInfo.GetProcessIdImagePath(ProcessId, false).GetResultOrDefault(string.Empty);
                ImageName = ProcessId == 0 ? "Idle" : process_info.ImageName.ToString();
            }

            ParentProcessId = process_info.InheritedFromUniqueProcessId.ToInt32();
            SessionId = process_info.SessionId;
            Threads = threads.ToArray();
            WorkingSetPrivateSize = process_info.WorkingSetPrivateSize.QuadPart;
            HardFaultCount = process_info.HardFaultCount;
            NumberOfThreadsHighWatermark = process_info.NumberOfThreadsHighWatermark;
            CycleTime = process_info.CycleTime;
            CreateTime = process_info.CreateTime.QuadPart;
            UserTime = process_info.UserTime.QuadPart;
            KernelTime = process_info.KernelTime.QuadPart;
            BasePriority = process_info.BasePriority;
            HandleCount = process_info.HandleCount;
            UniqueProcessKey = process_info.UniqueProcessKey.ToInt64();
            PeakVirtualSize = process_info.PeakVirtualSize.ToInt64();
            VirtualSize = process_info.VirtualSize.ToInt64();
            PageFaultCount = process_info.PageFaultCount;
            PeakWorkingSetSize = process_info.PeakWorkingSetSize.ToInt64();
            WorkingSetSize = process_info.WorkingSetSize.ToInt64();
            QuotaPeakPagedPoolUsage = process_info.QuotaPeakPagedPoolUsage.ToInt64();
            QuotaPagedPoolUsage = process_info.QuotaPagedPoolUsage.ToInt64();
            QuotaPeakNonPagedPoolUsage = process_info.QuotaPeakNonPagedPoolUsage.ToInt64();
            QuotaNonPagedPoolUsage = process_info.QuotaNonPagedPoolUsage.ToInt64();
            PagefileUsage = process_info.PagefileUsage.ToInt64();
            PeakPagefileUsage = process_info.PeakPagefileUsage.ToInt64();
            PrivatePageCount = process_info.PrivatePageCount.ToInt64();
            ReadOperationCount = process_info.ReadOperationCount.QuadPart;
            WriteOperationCount = process_info.WriteOperationCount.QuadPart;
            OtherOperationCount = process_info.OtherOperationCount.QuadPart;
            ReadTransferCount = process_info.ReadTransferCount.QuadPart;
            WriteTransferCount = process_info.WriteTransferCount.QuadPart;
            OtherTransferCount = process_info.OtherTransferCount.QuadPart;
        }

        public override string ToString()
        {
            return ImageName;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SysDbgTriageDump
    {
        public int Flags;
        public int BugCheckCode;
        public ulong BugCheckParam1;
        public ulong BugCheckParam2;
        public ulong BugCheckParam3;
        public ulong BugCheckParam4;
        public int ProcessHandles;
        public int ThreadHandles;
        public IntPtr Handles; // PHANDLE
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemDeviceInformation
    {
        public int NumberOfDisks;
        public int NumberOfFloppies;
        public int NumberOfCdRoms;
        public int NumberOfTapes;
        public int NumberOfSerialPorts;
        public int NumberOfParallelPorts;
    }

    [Flags]
    public enum SystemIsolatedUserModeInformationFlags
    {
        None = 0,
        SecureKernelRunning = 1,
        HvciEnabled = 2,
        HvciStrictMode = 4,
        DebugEnabled = 8,
        FirmwarePageProtection = 0x10,
        EncryptionKeyAvailable = 0x20,
        TrustletRunning = 0x100,
        HvciDisableAllowed = 0x200,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemIsolatedUserModeInformation
    {
        public SystemIsolatedUserModeInformationFlags Flags;
        public int Spare0;
        public long Spare1;
    }

#pragma warning restore 1591
}
