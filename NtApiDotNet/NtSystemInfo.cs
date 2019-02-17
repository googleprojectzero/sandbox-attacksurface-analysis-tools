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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

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
        public static extern NtStatus NtSetSystemInformation(
          SystemInformationClass SystemInformationClass,
          SafeBuffer SystemInformation,
          int SystemInformationLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSystemDebugControl(
            SystemDebugControlCode ControlCode,
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
        public string Name { get; private set; }
        public Guid VendorGuid { get; private set; }
        public byte[] Value { get; private set; }
        public SystemEnvironmentValueAttribute Attributes { get; private set; }

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
            Attributes = (SystemEnvironmentValueAttribute) attributes.Value;
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
   
    public enum SystemDebugControlCode
    {
        KernelCrashDump = 37,
    }

    [Flags]
    public enum SystemDebugKernelDumpControlFlags
    {
        None = 0,
        UseDumpStorageStack = 1,
        CompressMemoryPagesData = 2,
        IncludeUserSpaceMemoryPages = 4,
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
        public Guid PolicyPublisher { get; private set; }
        public int PolicyVersion { get; private set; }
        public int PolicyOptions { get; private set; }
        public byte[] Policy { get; private set; }

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
        public int PolicyType { get; private set; }
        public byte[] Policy { get; private set; }

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

    public class NtThreadInformation
    {
        public int ThreadId { get; }
        public int ProcessId { get; }
        public string ProcessName { get; }
        public long StartAddress { get; }
        public uint ThreadState { get; }
        public int WaitReason { get; }
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
            ThreadState = thread_info.ThreadState;
            WaitReason = thread_info.WaitReason;
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

    public class NtProcessInformation
    {
        public int ProcessId { get; }
        public int ParentProcessId { get; }
        public IEnumerable<NtThreadInformation> Threads { get; }
        public string ImageName { get; }
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

        internal NtProcessInformation(SystemProcessInformation process_info, IEnumerable<NtThreadInformation> threads)
        {
            ImageName = process_info.ImageName.ToString();
            ProcessId = process_info.UniqueProcessId.ToInt32();
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
    }

#pragma warning restore 1591

    /// <summary>
    /// Class to represent a system handle
    /// </summary>
    public class NtHandle
    {
        /// <summary>
        /// The ID of the process holding the handle
        /// </summary>
        public int ProcessId { get; private set; }

        /// <summary>
        /// The object type index
        /// </summary>
        public int ObjectTypeIndex { get; private set; }

        /// <summary>
        /// The object type name
        /// </summary>
        public string ObjectType
        {
            get
            {
                if (NtType == null)
                {
                    return $"Unknown Type: {ObjectTypeIndex}";
                }
                return NtType.Name;
            }
        }

        /// <summary>
        /// The object type
        /// </summary>
        public NtType NtType { get; private set; }

        /// <summary>
        /// The handle attribute flags.
        /// </summary>
        public AttributeFlags Attributes { get; private set; }

        /// <summary>
        /// The handle value
        /// </summary>
        public int Handle { get; private set; }

        /// <summary>
        /// The address of the object.
        /// </summary>
        public ulong Object { get; private set; }

        /// <summary>
        /// The granted access mask
        /// </summary>
        public AccessMask GrantedAccess { get; private set; }

        /// <summary>
        /// The name of the object (needs to have set query access in constructor)
        /// </summary>
        public string Name
        {
            get
            {
                QueryValues();
                return _name ?? String.Empty;
            }
        }

        /// <summary>
        /// The security of the object  (needs to have set query access in constructor)
        /// </summary>
        public SecurityDescriptor SecurityDescriptor
        {
            get
            {
                QueryValues();
                return _sd;
            }
        }

        private void QueryValues()
        {
            if (_allow_query)
            {
                _allow_query = false;
                NtToken.EnableDebugPrivilege();
                using (var obj = NtGeneric.DuplicateFrom(ProcessId, 
                    new IntPtr(Handle), 0, DuplicateObjectOptions.SameAccess, false))
                {
                    if (!obj.IsSuccess)
                    {
                        return;
                    }

                    NtType = obj.Result.NtType;
                    _name = GetName(obj.Result);
                    _sd = GetSecurityDescriptor(obj.Result);
                }
            }
        }

        internal NtHandle(SystemHandleTableInfoEntryEx entry, bool allow_query)
        {
            ProcessId = entry.UniqueProcessId.ToInt32();
            NtType info = NtType.GetTypeByIndex(entry.ObjectTypeIndex);
            if (info != null)
            {
                NtType = info;
            }
            
            Attributes = (AttributeFlags)entry.HandleAttributes;
            Handle = entry.HandleValue.ToInt32();
            Object = entry.Object.ToUInt64();
            GrantedAccess = entry.GrantedAccess.ToGenericAccess();
            _allow_query = allow_query;
        }

        /// <summary>
        /// Get handle into the current process
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The handle to the object</returns>
        public NtResult<NtObject> GetObject(bool throw_on_error)
        {
            NtToken.EnableDebugPrivilege();
            using (var result = NtGeneric.DuplicateFrom(ProcessId, new IntPtr(Handle), 0,
                DuplicateObjectOptions.SameAccess | DuplicateObjectOptions.SameAttributes, throw_on_error))
            {
                if (!result.IsSuccess)
                {
                    return result.Cast<NtObject>();
                }

                NtGeneric generic = result.Result;

                // Ensure that we get the actual type from the handle.
                NtType = generic.NtType;
                return generic.ToTypedObject(throw_on_error).Cast<NtObject>();
            }
        }

        /// <summary>
        /// Get handle into the current process
        /// </summary>
        /// <returns>The handle to the object</returns>
        public NtObject GetObject()
        {
            return GetObject(true).Result;
        }

        private string GetName(NtGeneric obj)
        {
            if (obj == null)
            {
                return string.Empty;
            }
            return obj.FullPath;
        }

        private SecurityDescriptor GetSecurityDescriptor(NtGeneric obj)
        {
            if (obj != null)
            {
                using (var dup = obj.Duplicate(GenericAccessRights.ReadControl, false))
                {
                    if (!dup.IsSuccess)
                    {
                        return null;
                    }
                    var sd = dup.Result.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
                    if (!sd.IsSuccess)
                    {
                        return null;
                    }
                    return sd.Result;
                }
            }
            return null;
        }

        private string _name;
        private SecurityDescriptor _sd;
        private bool _allow_query;
    }


    /// <summary>
    /// Class to access some NT system information
    /// </summary>
    public static class NtSystemInfo
    {
        #region Private Members

        // A dummy system info object to repurpose the query/set methods.
        private class NtSystemInfoObject : NtObjectWithDuplicateAndInfo<NtGeneric, GenericAccessRights, SystemInformationClass, SystemInformationClass>
        {
            public NtSystemInfoObject() : base(SafeKernelObjectHandle.Null)
            {
            }

            protected override int GetMaximumBruteForceLength(SystemInformationClass info_class)
            {
                return 16 * 1024 * 1024;
            }

            protected override bool GetTrustReturnLength(SystemInformationClass info_class)
            {
                return false;
            }

            public override NtStatus QueryInformation(SystemInformationClass info_class, SafeBuffer buffer, out int return_length)
            {
                return NtSystemCalls.NtQuerySystemInformation(info_class, buffer, buffer.GetLength(), out return_length);
            }

            public override NtStatus SetInformation(SystemInformationClass info_class, SafeBuffer buffer)
            {
                return NtSystemCalls.NtSetSystemInformation(info_class, buffer, buffer.GetLength());
            }
        }

        private static readonly Lazy<SystemBasicInformation> _basic_info = new Lazy<SystemBasicInformation>(GetBasicInformation);
        private static readonly NtSystemInfoObject _system_info_object = new NtSystemInfoObject();

        private static SystemKernelDebuggerInformation GetKernelDebuggerInformation()
        {
            return Query<SystemKernelDebuggerInformation>(SystemInformationClass.SystemKernelDebuggerInformation);
        }

        private static SafeHGlobalBuffer EnumEnvironmentValues(SystemEnvironmentValueInformationClass info_class)
        {
            int ret_length = 0;
            NtStatus status = NtSystemCalls.NtEnumerateSystemEnvironmentValuesEx(info_class, SafeHGlobalBuffer.Null, ref ret_length);
            if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
            {
                throw new NtException(status);
            }
            var buffer = new SafeHGlobalBuffer(ret_length);
            try
            {
                ret_length = buffer.Length;
                NtSystemCalls.NtEnumerateSystemEnvironmentValuesEx(info_class,
                    buffer, ref ret_length).ToNtException();
                return buffer;
            }
            catch
            {
                buffer.Dispose();
                throw;
            }
        }

        private static SystemBasicInformation GetBasicInformation()
        {
            return Query<SystemBasicInformation>(SystemInformationClass.SystemBasicInformation);
        }

        #endregion

        #region Static Methods

        /// <summary>
        /// Get a list of handles
        /// </summary>
        /// <param name="pid">A process ID to filter on. If -1 will get all handles</param>
        /// <param name="allow_query">True to allow the handles returned to query for certain properties</param>
        /// <returns>The list of handles</returns>
        public static IEnumerable<NtHandle> GetHandles(int pid, bool allow_query)
        {
            using (var buffer = QueryBuffer<SystemHandleInformationEx>(SystemInformationClass.SystemExtendedHandleInformation))
            {
                var handle_info = buffer.Result;
                int handle_count = handle_info.NumberOfHandles.ToInt32();
                SystemHandleTableInfoEntryEx[] handles = new SystemHandleTableInfoEntryEx[handle_count];
                buffer.Data.ReadArray(0, handles, 0, handle_count);
                return handles.Where(h => pid == -1 || h.UniqueProcessId.ToInt32() == pid).Select(h => new NtHandle(h, allow_query));
            }
        }

        /// <summary>
        /// Get a list of all handles
        /// </summary>
        /// <returns>The list of handles</returns>
        public static IEnumerable<NtHandle> GetHandles()
        {
            return GetHandles(-1, true);
        }

        /// <summary>
        /// Get a list of threads for a specific process.
        /// </summary>
        /// <param name="process_id">The process ID to list.</param>
        /// <returns>The list of thread information.</returns>
        public static IEnumerable<NtThreadInformation> GetThreadInformation(int process_id)
        {
            foreach (NtProcessInformation process in GetProcessInformation())
            {
                if (process.ProcessId == process_id)
                {
                    foreach (NtThreadInformation thread in process.Threads)
                    {
                        yield return thread;
                    }
                    break;
                }
            }
        }

        /// <summary>
        /// Get a list of all threads.
        /// </summary>
        /// <returns>The list of thread information.</returns>
        public static IEnumerable<NtThreadInformation> GetThreadInformation()
        {
            return GetProcessInformation().SelectMany(p => p.Threads);
        }

        /// <summary>
        /// Get all process information for the system.
        /// </summary>
        /// <returns>The list of process information.</returns>
        public static IEnumerable<NtProcessInformation> GetProcessInformation()
        {
            using (var process_info = QueryBuffer<SystemProcessInformation>(SystemInformationClass.SystemProcessInformation))
            {
                int offset = 0;
                while (true)
                {
                    var process_buffer = process_info.GetStructAtOffset<SystemProcessInformation>(offset);
                    var process_entry = process_buffer.Result;
                    SystemThreadInformation[] thread_info = new SystemThreadInformation[process_entry.NumberOfThreads];
                    process_buffer.Data.ReadArray(0, thread_info, 0, thread_info.Length);

                    yield return new NtProcessInformation(process_entry, thread_info.Select(t => new NtThreadInformation(process_entry.ImageName.ToString(), t)));

                    if (process_entry.NextEntryOffset == 0)
                    {
                        break;
                    }

                    offset += process_entry.NextEntryOffset;
                }
            }
        }

        /// <summary>
        /// Get list of page filenames.
        /// </summary>
        /// <returns>The list of page file names.</returns>
        public static IEnumerable<string> GetPageFileNames()
        {
            using (var buffer = QueryBuffer<SystemPageFileInformation>(SystemInformationClass.SystemPageFileInformation))
            {
                int offset = 0;
                while (true)
                {
                    var pagefile_info = buffer.GetStructAtOffset<SystemPageFileInformation>(offset).Result;
                    yield return pagefile_info.PageFileName.ToString();
                    if (pagefile_info.NextEntryOffset == 0)
                    {
                        break;
                    }
                    offset += pagefile_info.NextEntryOffset;
                }
            }
        }

        /// <summary>
        /// Create a kernel dump for current system.
        /// </summary>
        /// <param name="path">The path to the output file.</param>
        /// <param name="flags">Flags</param>
        /// <param name="page_flags">Page flags</param>
        public static void CreateKernelDump(string path, SystemDebugKernelDumpControlFlags flags, SystemDebugKernelDumpPageControlFlags page_flags)
        {
            NtToken.EnableDebugPrivilege();
            using (NtFile file = NtFile.Create(path, FileAccessRights.Synchronize | FileAccessRights.GenericWrite | FileAccessRights.GenericRead,
                    FileShareMode.Read, FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.WriteThrough | FileOpenOptions.NoIntermediateBuffering, FileDisposition.OverwriteIf,
                    null))
            {
                using (var buffer = new SystemDebugKernelDumpConfig()
                {
                    FileHandle = file.Handle.DangerousGetHandle(),
                    Flags = flags,
                    PageFlags = page_flags
                }.ToBuffer())
                {
                    NtSystemCalls.NtSystemDebugControl(SystemDebugControlCode.KernelCrashDump, buffer, buffer.Length,
                        SafeHGlobalBuffer.Null, 0, out int ret_length).ToNtException();
                }
            }
        }

        /// <summary>
        /// Query all system environment value names.
        /// </summary>
        /// <returns>A list of names of environment values</returns>
        public static IEnumerable<string> QuerySystemEnvironmentValueNames()
        {
            using (var buffer = EnumEnvironmentValues(SystemEnvironmentValueInformationClass.NamesOnly))
            {
                int offset = 0;
                int size_struct = Marshal.SizeOf(typeof(SystemEnvironmentValueName));
                while (offset <= buffer.Length - size_struct)
                {
                    var struct_buffer = buffer.GetStructAtOffset<SystemEnvironmentValueName>(offset);
                    SystemEnvironmentValueName name = struct_buffer.Result;
                    yield return struct_buffer.Data.ReadNulTerminatedUnicodeString();
                    if (name.NextEntryOffset == 0)
                    {
                        break;
                    }
                    offset = offset + name.NextEntryOffset;
                }
            }
        }

        /// <summary>
        /// Query all system environment value names and values.
        /// </summary>
        /// <returns>A list of names of environment values</returns>
        public static IEnumerable<SystemEnvironmentValue> QuerySystemEnvironmentValueNamesAndValues()
        {
            using (var buffer = EnumEnvironmentValues(SystemEnvironmentValueInformationClass.NamesAndValues))
            {
                int offset = 0;
                int size_struct = Marshal.SizeOf(typeof(SystemEnvironmentValueNameAndValue));
                while (offset <= buffer.Length - size_struct)
                {
                    var struct_buffer = buffer.GetStructAtOffset<SystemEnvironmentValueNameAndValue>(offset);
                    SystemEnvironmentValueNameAndValue name = struct_buffer.Result;
                    yield return new SystemEnvironmentValue(struct_buffer);
                    if (name.NextEntryOffset == 0)
                    {
                        break;
                    }
                    offset = offset + name.NextEntryOffset;
                }
            }
        }

        /// <summary>
        /// Query a single system environment value.
        /// </summary>
        /// <param name="name">The name of the value.</param>
        /// <param name="vendor_guid">The associated vendor guid</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The system environment value.</returns>
        public static NtResult<SystemEnvironmentValue> QuerySystemEnvironmentValue(string name, Guid vendor_guid, bool throw_on_error)
        {
            UnicodeString name_string = new UnicodeString(name);
            int value_length = 0;
            NtStatus status = NtSystemCalls.NtQuerySystemEnvironmentValueEx(name_string, ref vendor_guid, null, ref value_length, 0);
            if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
            {
                return status.CreateResultFromError<SystemEnvironmentValue>(throw_on_error);
            }

            byte[] value = new byte[value_length];
            OptionalInt32 attributes = new OptionalInt32();
            return NtSystemCalls.NtQuerySystemEnvironmentValueEx(name_string, ref vendor_guid, value, ref value_length, attributes)
                .CreateResult(throw_on_error, () => new SystemEnvironmentValue(name, value, attributes, vendor_guid));
        }

        /// <summary>
        /// Query a single system environment value.
        /// </summary>
        /// <param name="name">The name of the value.</param>
        /// <param name="vendor_guid">The associated vendor guid</param>
        /// <returns>The system environment value.</returns>
        public static SystemEnvironmentValue QuerySystemEnvironmentValue(string name, Guid vendor_guid)
        {
            return QuerySystemEnvironmentValue(name, vendor_guid, true).Result;
        }

        /// <summary>
        /// Set a system environment variable.
        /// </summary>
        /// <param name="name">The name of the variable.</param>
        /// <param name="vendor_guid">The vendor GUID</param>
        /// <param name="value">The value to set</param>
        /// <param name="attributes">Attributes of the value</param>
        public static void SetSystemEnvironmentValue(string name, Guid vendor_guid, byte[] value, int attributes)
        {
            NtSystemCalls.NtSetSystemEnvironmentValueEx(new UnicodeString(name), ref vendor_guid, value, value.Length, attributes).ToNtException();
        }

        /// <summary>
        /// Set a system environment variable.
        /// </summary>
        /// <param name="name">The name of the variable.</param>
        /// <param name="vendor_guid">The vendor GUID</param>
        /// <param name="value">The value to set</param>
        /// <param name="attributes">Attributes of the value</param>
        public static void SetSystemEnvironmentValue(string name, Guid vendor_guid, byte[] value, SystemEnvironmentValueAttribute attributes)
        {
            SetSystemEnvironmentValue(name, vendor_guid, value, (int)attributes);
        }

        /// <summary>
        /// Set a system environment variable.
        /// </summary>
        /// <param name="name">The name of the variable.</param>
        /// <param name="vendor_guid">The vendor GUID</param>
        /// <param name="value">The value to set</param>
        /// <param name="attributes">Attributes of the value</param>
        public static void SetSystemEnvironmentValue(string name, Guid vendor_guid, string value, int attributes)
        {
            SetSystemEnvironmentValue(name, vendor_guid, Encoding.Unicode.GetBytes(value), attributes);
        }

        /// <summary>
        /// Set a system environment variable.
        /// </summary>
        /// <param name="name">The name of the variable.</param>
        /// <param name="vendor_guid">The vendor GUID</param>
        /// <param name="value">The value to set</param>
        /// <param name="attributes">Attributes of the value</param>
        public static void SetSystemEnvironmentValue(string name, Guid vendor_guid, string value, SystemEnvironmentValueAttribute attributes)
        {
            SetSystemEnvironmentValue(name, vendor_guid, value, (int)attributes);
        }

        /// <summary>
        /// Allocate a LUID.
        /// </summary>
        /// <returns>The allocated LUID.</returns>
        public static Luid AllocateLocallyUniqueId()
        {
            NtSystemCalls.NtAllocateLocallyUniqueId(out Luid luid).ToNtException();
            return luid;
        }

        /// <summary>
        /// Get the addresses of a list of objects from the handle table and initialize the Address property.
        /// </summary>
        /// <param name="objects">The list of objects to initialize.</param>
        public static void ResolveObjectAddress(IEnumerable<NtObject> objects)
        {
            var handles = GetHandles(NtProcess.Current.ProcessId, false).ToDictionary(h => h.Handle, h => h.Object);
            foreach (var obj in objects)
            {
                int obj_handle = obj.Handle.DangerousGetHandle().ToInt32();
                if (handles.ContainsKey(obj_handle))
                {
                    obj.Address = handles[obj_handle];
                }
            }
        }

        /// <summary>
        /// Get the address of an object in kernel memory from the handle table and initialize the Address property.
        /// </summary>
        /// <param name="obj">The object.</param>
        public static void ResolveObjectAddress(NtObject obj)
        {
            ResolveObjectAddress(new[] { obj });
        }

        /// <summary>
        /// Query whether a file is trusted for dynamic code.
        /// </summary>
        /// <param name="handle">The handle to a file to query.</param>
        /// <param name="image">Pointer to a memory buffer containing the image.</param>
        /// <param name="image_size">The size of the in-memory buffer.</param>
        /// <returns>True if the file is trusted.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS4)]
        public static NtStatus QueryDynamicCodeTrust(SafeKernelObjectHandle handle, IntPtr image, int image_size)
        {
            SystemCodeIntegrityVerificationInformation info = new SystemCodeIntegrityVerificationInformation()
            {
                FileHandle = handle.DangerousGetHandle(),
                Image = image,
                ImageSize = image_size
            };

            return Query(SystemInformationClass.SystemCodeIntegrityVerificationInformation, info, false).Status;
        }

        /// <summary>
        /// Query whether a file is trusted for dynamic code.
        /// </summary>
        /// <param name="image">Pointer to a memory buffer containing the image.</param>
        /// <returns>The status code from the operation. Returns STATUS_SUCCESS is valid.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS4)]
        public static NtStatus QueryDynamicCodeTrust(byte[] image)
        {
            using (var buffer = image.ToBuffer())
            {
                return QueryDynamicCodeTrust(SafeKernelObjectHandle.Null, 
                    buffer.DangerousGetHandle(), buffer.Length);
            }
        }

        /// <summary>
        /// Query whether a file is trusted for dynamic code.
        /// </summary>
        /// <param name="handle">The handle to a file to query.</param>
        /// <returns>The status code from the operation. Returns STATUS_SUCCESS is valid.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS4)]
        public static NtStatus QueryDynamicCodeTrust(SafeKernelObjectHandle handle)
        {
            return QueryDynamicCodeTrust(handle, IntPtr.Zero, 0);
        }

        /// <summary>
        /// Set a file is trusted for dynamic code.
        /// </summary>
        /// <param name="handle">The handle to a file to set.</param>
        /// <returns>The status code from the operation.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS4)]
        public static NtStatus SetDynamicCodeTrust(SafeKernelObjectHandle handle)
        {
            SystemCodeIntegrityVerificationInformation info = new SystemCodeIntegrityVerificationInformation()
            {
                FileHandle = handle.DangerousGetHandle()
            };

            return Set(SystemInformationClass.SystemCodeIntegrityVerificationInformation, info, false);
        }

        /// <summary>
        /// Get list of root silos.
        /// </summary>
        /// <returns>The list of root silos.</returns>
        public static IReadOnlyCollection<int> GetRootSilos()
        {
            using (var buffer = QueryBuffer<SystemRootSiloInformation>(SystemInformationClass.SystemRootSiloInformation))
            {
                var result = buffer.Result;
                int[] silos = new int[result.NumberOfSilos];
                buffer.Data.ReadArray(0, silos, 0, silos.Length);
                return silos.ToList().AsReadOnly();
            }
        }

        /// <summary>
        /// Set the ELAM certificate information.
        /// </summary>
        /// <param name="image_file">The signed file containing an ELAM certificate resource.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetElamCertificate(NtFile image_file)
        {
            SystemElamCertificateInformation info = new SystemElamCertificateInformation()
            { ElamDriverFile = image_file.Handle.DangerousGetHandle() };
            return Set(SystemInformationClass.SystemElamCertificateInformation, info, false);
        }

        /// <summary>
        /// Query code integrity certificate information.
        /// </summary>
        /// <param name="image_file">The image file.</param>
        /// <param name="type">The type of check to make.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus QueryCodeIntegrityCertificateInfo(NtFile image_file, int type)
        {
            SystemCodeIntegrityCertificateInformation info = new SystemCodeIntegrityCertificateInformation()
            {
                ImageFile = image_file.Handle.DangerousGetHandle(),
                Type = type
            };

            return Query(SystemInformationClass.SystemCodeIntegrityCertificateInformation, info, false).Status;
        }

        /// <summary>
        /// Query a fixed structure from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<T> Query<T>(SystemInformationClass info_class, T default_value, bool throw_on_error) where T : new()
        {
            return _system_info_object.Query(info_class, default_value, throw_on_error);
        }

        /// <summary>
        /// Query a fixed structure from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static T Query<T>(SystemInformationClass info_class, T default_value) where T : new()
        {
            return _system_info_object.Query(info_class, default_value);
        }

        /// <summary>
        /// Query a fixed structure from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static T Query<T>(SystemInformationClass info_class) where T : new()
        {
            return _system_info_object.Query<T>(info_class);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<SafeStructureInOutBuffer<T>> QueryBuffer<T>(SystemInformationClass info_class, T default_value, bool throw_on_error) where T : new()
        {
            return _system_info_object.QueryBuffer(info_class, default_value, throw_on_error);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="init_buffer">A buffer to initialize the initial query. Can be null.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<SafeHGlobalBuffer> QueryRawBuffer(SystemInformationClass info_class, byte[] init_buffer, bool throw_on_error)
        {
            return _system_info_object.QueryRawBuffer(info_class, init_buffer, throw_on_error);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="init_buffer">A buffer to initialize the initial query. Can be null.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static SafeHGlobalBuffer QueryRawBuffer(SystemInformationClass info_class, byte[] init_buffer)
        {
            return _system_info_object.QueryRawBuffer(info_class, init_buffer);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static SafeHGlobalBuffer QueryRawBuffer(SystemInformationClass info_class)
        {
            return _system_info_object.QueryRawBuffer(info_class);
        }

        /// <summary>
        /// Query a variable buffer from the object and return as bytes.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="init_buffer">A buffer to initialize the initial query. Can be null.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<byte[]> QueryRawBytes(SystemInformationClass info_class, byte[] init_buffer, bool throw_on_error)
        {
            return _system_info_object.QueryRawBytes(info_class, init_buffer, throw_on_error);
        }

        /// <summary>
        /// Query a variable buffer from the object and return as bytes.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="init_buffer">A buffer to initialize the initial query. Can be null.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static byte[] QueryRawBytes(SystemInformationClass info_class, byte[] init_buffer)
        {
            return _system_info_object.QueryRawBytes(info_class, init_buffer);
        }

        /// <summary>
        /// Query a variable buffer from the object and return as bytes.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static byte[] QueryRawBytes(SystemInformationClass info_class)
        {
            return _system_info_object.QueryRawBytes(info_class);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static SafeStructureInOutBuffer<T> QueryBuffer<T>(SystemInformationClass info_class, T default_value) where T : new()
        {
            return _system_info_object.QueryBuffer(info_class, default_value);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static SafeStructureInOutBuffer<T> QueryBuffer<T>(SystemInformationClass info_class) where T : new()
        {
            return _system_info_object.QueryBuffer<T>(info_class);
        }

        /// <summary>
        /// Set a value to the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to set.</typeparam>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="value">The value to set. If you specify a SafeBuffer then it'll be passed directly.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtStatus Set<T>(SystemInformationClass info_class, T value, bool throw_on_error) where T : struct
        {
            return _system_info_object.Set(info_class, value, throw_on_error);
        }

        /// <summary>
        /// Set a value to the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to set.</typeparam>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="value">The value to set.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static void Set<T>(SystemInformationClass info_class, T value) where T : struct
        {
            _system_info_object.Set(info_class, value);
        }

        /// <summary>
        /// Set a value to the object from a buffer.
        /// </summary>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="buffer">The value to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtStatus SetBuffer(SystemInformationClass info_class, SafeBuffer buffer, bool throw_on_error)
        {
            return _system_info_object.SetBuffer(info_class, buffer, throw_on_error);
        }

        /// <summary>
        /// Set a value to the object from a buffer..
        /// </summary>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="buffer">The value to set.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static void SetBuffer(SystemInformationClass info_class, SafeBuffer buffer)
        {
            _system_info_object.SetBuffer(info_class, buffer);
        }

        /// <summary>
        /// Set a raw value to the object.
        /// </summary>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="value">The raw value to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtStatus SetBytes(SystemInformationClass info_class, byte[] value, bool throw_on_error)
        {
            return _system_info_object.SetBytes(info_class, value, throw_on_error);
        }

        /// <summary>
        /// Set a raw value to the object.
        /// </summary>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="value">The raw value to set.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static void SetBytes(SystemInformationClass info_class, byte[] value)
        {
            _system_info_object.SetBytes(info_class, value);
        }

        #endregion

        #region Static Properties
        /// <summary>
        /// Get whether the kernel debugger is enabled.
        /// </summary>
        public static bool KernelDebuggerEnabled
        {
            get
            {
                return GetKernelDebuggerInformation().KernelDebuggerEnabled;
            }
        }

        /// <summary>
        /// Get whether the kernel debugger is not present.
        /// </summary>
        public static bool KernelDebuggerNotPresent
        {
            get
            {
                return GetKernelDebuggerInformation().KernelDebuggerNotPresent;
            }
        }

        /// <summary>
        /// Get current code integrity option settings.
        /// </summary>
        public static CodeIntegrityOptions CodeIntegrityOptions
        {
            get
            {
                return Query(SystemInformationClass.SystemCodeIntegrityInformation, 
                    new SystemCodeIntegrityInformation() { Length = Marshal.SizeOf(typeof(SystemCodeIntegrityInformation)) }).CodeIntegrityOptions;
            }
        }

        /// <summary>
        /// Get code integrity policy.
        /// </summary>
        public static SystemCodeIntegrityPolicy CodeIntegrityPolicy
        {
            get
            {
                return Query<SystemCodeIntegrityPolicy>(SystemInformationClass.SystemCodeIntegrityPolicyInformation);
            }
        }

        /// <summary>
        /// Get code integrity unlock information.
        /// </summary>
        public static int CodeIntegrityUnlock
        {
            get
            {
                return Query<int>(SystemInformationClass.SystemCodeIntegrityUnlockInformation);
            }
        }

        /// <summary>
        /// Get all code integrity policies.
        /// </summary>
        public static IEnumerable<CodeIntegrityPolicy> CodeIntegrityFullPolicy
        {
            get
            {
                List<CodeIntegrityPolicy> policies = new List<CodeIntegrityPolicy>();
                try
                {
                    MemoryStream stm = new MemoryStream(QueryRawBytes(SystemInformationClass.SystemCodeIntegrityPoliciesFullInformation));
                    if (stm.Length > 0)
                    {
                        BinaryReader reader = new BinaryReader(stm);
                        int header_size = reader.ReadInt32();
                        int total_policies = reader.ReadInt32();
                        reader.ReadBytes(8 - header_size);
                        for (int i = 0; i < total_policies; ++i)
                        {
                            policies.Add(new CodeIntegrityPolicy(reader));
                        }
                    }
                }
                catch (NtException)
                {
                    byte[] policy = QueryRawBytes(SystemInformationClass.SystemCodeIntegrityPolicyFullInformation);
                    if (policy.Length > 0)
                    {
                        policies.Add(new CodeIntegrityPolicy(policy));
                    }
                }

                return policies.AsReadOnly();
            }
        }

        /// <summary>
        /// Get whether secure boot is enabled.
        /// </summary>
        public static bool SecureBootEnabled
        {
            get
            {
                return Query<SystemSecurebootInformation>(SystemInformationClass.SystemSecureBootInformation).SecureBootEnabled;
            }
        }

        /// <summary>
        /// Get whether system supports secure boot.
        /// </summary>
        public static bool SecureBootCapable
        {
            get
            {
                return Query<SystemSecurebootInformation>(SystemInformationClass.SystemSecureBootInformation).SecureBootCapable;
            }
        }

        /// <summary>
        /// Extract the secure boot policy.
        /// </summary>
        public static SecureBootPolicy SecureBootPolicy
        {
            get
            {
                using (var buffer = QueryBuffer<SystemSecurebootPolicyFullInformation>(SystemInformationClass.SystemSecureBootPolicyFullInformation))
                {
                    return new SecureBootPolicy(buffer);
                }
            }
        }
        /// <summary>
        /// Get system timer resolution.
        /// </summary>
        public static int TimerResolution => _basic_info.Value.TimerResolution;
        /// <summary>
        /// Get system page size.
        /// </summary>
        public static int PageSize => _basic_info.Value.PageSize;
        /// <summary>
        /// Get number of physical pages.
        /// </summary>
        public static int NumberOfPhysicalPages => _basic_info.Value.NumberOfPhysicalPages;
        /// <summary>
        /// Get lowest page number.
        /// </summary>
        public static int LowestPhysicalPageNumber => _basic_info.Value.LowestPhysicalPageNumber;
        /// <summary>
        /// Get highest page number.
        /// </summary>
        public static int HighestPhysicalPageNumber => _basic_info.Value.HighestPhysicalPageNumber;
        /// <summary>
        /// Get allocation granularity.
        /// </summary>
        public static int AllocationGranularity => _basic_info.Value.AllocationGranularity;
        /// <summary>
        /// Get minimum user mode address.
        /// </summary>
        public static ulong MinimumUserModeAddress => _basic_info.Value.MinimumUserModeAddress.ToUInt64();
        /// <summary>
        /// Get maximum user mode address.
        /// </summary>
        public static ulong MaximumUserModeAddress => _basic_info.Value.MaximumUserModeAddress.ToUInt64();
        /// <summary>
        /// Get active processor affinity mask.
        /// </summary>
        public static ulong ActiveProcessorsAffinityMask => _basic_info.Value.ActiveProcessorsAffinityMask.ToUInt64();
        /// <summary>
        /// Get number of processors.
        /// </summary>
        public static int NumberOfProcessors => _basic_info.Value.NumberOfProcessors;

        #endregion
    }
}
