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
    }

    public class SystemEnvironmentValue
    {
        public string Name { get; private set; }
        public Guid VendorGuid { get; private set; }
        public byte[] Value { get; private set; }
        public int Attributes { get; private set; }

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
            Attributes = attributes.Value;
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
        public int Attributes;
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

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemCodeIntegrityPolicy
    {
        // 2 enabled auditing (at least in WLDP). 0x10 enables UMCI
        public int Options;
        public int HVCIOptions;
        public ushort VersionRevision;
        public ushort VersionBuild;
        public ushort VersionMinor;
        public ushort VersionMajor;
        public Guid PolicyGuid;
    }
    
    public enum SystemInformationClass
    {
        SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
        SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
        SystemPathInformation, // not implemented
        SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
        SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
        SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
        SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
        SystemCallTimeInformation, // 10, not implemented
        SystemModuleInformation, // q: RTL_PROCESS_MODULES
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation, // not implemented
        SystemNonPagedPoolInformation, // not implemented
        SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
        SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
        SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
        SystemVdmInstemulInformation, // q
        SystemVdmBopInformation, // 20, not implemented
        SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
        SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
        SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
        SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
        SystemFullMemoryInformation, // not implemented
        SystemLoadGdiDriverInformation, // s (kernel-mode only)
        SystemUnloadGdiDriverInformation, // s (kernel-mode only)
        SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
        SystemSummaryMemoryInformation, // not implemented
        SystemMirrorMemoryInformation, // 30, s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege)
        SystemPerformanceTraceInformation, // s
        SystemObsolete0, // not implemented
        SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
        SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
        SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
        SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
        SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
        SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
        SystemPrioritySeperation, // s (requires SeTcbPrivilege)
        SystemVerifierAddDriverInformation, // 40, s (requires SeDebugPrivilege)
        SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
        SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
        SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
        SystemCurrentTimeZoneInformation, // q
        SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
        SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
        SystemSessionCreate, // not implemented
        SystemSessionDetach, // not implemented
        SystemSessionInformation, // not implemented
        SystemRangeStartInformation, // 50, q
        SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
        SystemVerifierThunkExtend, // s (kernel-mode only)
        SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
        SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
        SystemNumaProcessorMap, // q
        SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
        SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemRecommendedSharedDataAlignment, // q
        SystemComPlusPackage, // q; s
        SystemNumaAvailableMemory, // 60
        SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
        SystemEmulationBasicInformation, // q
        SystemEmulationProcessorInformation,
        SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
        SystemLostDelayedWriteInformation, // q: ULONG
        SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
        SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
        SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
        SystemHotpatchInformation, // q; s
        SystemObjectSecurityMode, // 70, q
        SystemWatchdogTimerHandler, // s (kernel-mode only)
        SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
        SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
        SystemWow64SharedInformationObsolete, // not implemented
        SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
        SystemFirmwareTableInformation, // not implemented
        SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
        SystemVerifierTriageInformation, // not implemented
        SystemSuperfetchInformation, // q: SUPERFETCH_INFORMATION; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
        SystemMemoryListInformation, // 80, q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege)
        SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
        SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
        SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
        SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
        SystemProcessorPowerInformationEx, // not implemented
        SystemRefTraceInformation, // q; s // ObQueryRefTraceInformation
        SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
        SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
        SystemErrorPortInformation, // s (requires SeTcbPrivilege)
        SystemBootEnvironmentInformation, // 90, q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION
        SystemHypervisorInformation, // q; s (kernel-mode only)
        SystemVerifierInformationEx, // q; s
        SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
        SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
        SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
        SystemPrefetchPatchInformation, // not implemented
        SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
        SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
        SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
        SystemProcessorPerformanceDistribution, // 100, q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION
        SystemNumaProximityNodeInformation, // q
        SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
        SystemCodeIntegrityInformation, // q // SeCodeIntegrityQueryInformation
        SystemProcessorMicrocodeUpdateInformation, // s
        SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
        SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
        SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
        SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
        SystemStoreInformation, // q; s // SmQueryStoreInformation
        SystemRegistryAppendString, // 110, s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS
        SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
        SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
        SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
        SystemNativeBasicInformation, // not implemented
        SystemSpare1, // not implemented
        SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
        SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
        SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
        SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
        SystemSystemPtesInformationEx, // 120, q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes)
        SystemNodeDistanceInformation, // q
        SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
        SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
        SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
        SystemSessionBigPoolInformation, // since WIN8
        SystemBootGraphicsInformation,
        SystemScrubPhysicalMemoryInformation,
        SystemBadPageInformation,
        SystemProcessorProfileControlArea,
        SystemCombinePhysicalMemoryInformation, // 130
        SystemEntropyInterruptTimingCallback,
        SystemConsoleInformation,
        SystemPlatformBinaryInformation,
        SystemThrottleNotificationInformation,
        SystemHypervisorProcessorCountInformation,
        SystemDeviceDataInformation,
        SystemDeviceDataEnumerationInformation,
        SystemMemoryTopologyInformation,
        SystemMemoryChannelInformation,
        SystemBootLogoInformation, // 140
        SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
        SystemSpare0,
        SystemSecureBootPolicyInformation,
        SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
        SystemSecureBootInformation,
        SystemEntropyInterruptTimingRawInformation,
        SystemPortableWorkspaceEfiLauncherInformation,
        SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
        SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
        SystemBootMetadataInformation, // 150
        SystemSoftRebootInformation,
        SystemElamCertificateInformation,
        SystemOfflineDumpConfigInformation,
        SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
        SystemRegistryReconciliationInformation,
        SystemEdidInformation,
        SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
        SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
        SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
        SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
        SystemVmGenerationCountInformation,
        SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
        SystemKernelDebuggerFlags,
        SystemCodeIntegrityPolicyInformation,
        SystemIsolatedUserModeInformation,
        SystemHardwareSecurityTestInterfaceResultsInformation,
        SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
        SystemAllowedCpuSetsInformation,
        SystemDmaProtectionInformation,
        SystemInterruptCpuSetsInformation,
        SystemSecureBootPolicyFullInformation,
        SystemCodeIntegrityPolicyFullInformation,
        SystemAffinitizedInterruptProcessorInformation,
        SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
        SystemCodeIntegrityAllPoliciesInformation = 189,
        SystemCodeIntegrityUnlockInformation = 190,
        MaxSystemInfoClass
    }

    public class NtThreadInformation
    {
        public int ThreadId { get; private set; }
        public int ProcessId { get; private set; }
        public string ProcessName { get; private set; }
        public IntPtr StartAddress { get; private set; }
        public uint ThreadState { get; private set; }
        public int WaitReason { get; private set; }

        internal NtThreadInformation(string name, SystemThreadInformation thread_info)
        {
            ProcessName = name;
            ThreadId = thread_info.ClientId.UniqueThread.ToInt32();
            ProcessId = thread_info.ClientId.UniqueProcess.ToInt32();
            StartAddress = thread_info.StartAddress;
            ThreadState = thread_info.ThreadState;
            WaitReason = thread_info.WaitReason;
        }

        public override string ToString()
        {
            return ThreadId.ToString();
        }
    }

    public class NtProcessInformation
    {
        public int ProcessId { get; private set; }
        public int ParentProcessId { get; private set; }
        public IEnumerable<NtThreadInformation> Threads { get; private set; }
        public string ImageName { get; private set; }
        public int SessionId { get; private set; }

        internal NtProcessInformation(SystemProcessInformation process_info, IEnumerable<NtThreadInformation> threads)
        {
            ImageName = process_info.ImageName.ToString();
            ProcessId = process_info.UniqueProcessId.ToInt32();
            ParentProcessId = process_info.InheritedFromUniqueProcessId.ToInt32();
            SessionId = process_info.SessionId;
            Threads = threads.ToArray();
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
                    return String.Format("Unknown Type: {0}", ObjectTypeIndex);
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

        internal NtHandle(SystemHandleTableInfoEntry entry, bool allow_query)
        {
            ProcessId = entry.UniqueProcessId;
            NtType info = NtType.GetTypeByIndex(entry.ObjectTypeIndex);
            if (info != null)
            {
                NtType = info;
            }
            
            Attributes = (AttributeFlags)entry.HandleAttributes;
            Handle = entry.HandleValue;
            Object = entry.Object.ToUInt64();
            GrantedAccess = (GenericAccessRights)entry.GrantedAccess;
            _allow_query = allow_query;
        }

        /// <summary>
        /// Get handle into the current process
        /// </summary>
        /// <returns>The handle to the object</returns>
        public NtObject GetObject()
        {
            NtToken.EnableDebugPrivilege();
            try
            {
                using (NtGeneric generic = NtGeneric.DuplicateFrom(ProcessId, new IntPtr(Handle)))
                {
                    // Ensure that we get the actual type from the handle.
                    NtType = generic.NtType;
                    return generic.ToTypedObject();
                }
            }
            catch
            {
            }
            return null;
        }

        private string GetName(NtGeneric obj)
        {
            if (obj == null)
            {
                return String.Empty;
            }
            return obj.FullPath;
        }

        private SecurityDescriptor GetSecurityDescriptor(NtGeneric obj)
        {
            try
            {
                if (obj != null)
                {
                    using (NtGeneric dup = obj.Duplicate(GenericAccessRights.ReadControl))
                    {
                        return dup.SecurityDescriptor;
                    }
                }
            }
            catch
            {
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
        private static void AllocateSafeBuffer(SafeHGlobalBuffer buffer, SystemInformationClass info_class)
        {
            NtStatus status = 0;
            int return_length = 0;
            while ((status = NtSystemCalls.NtQuerySystemInformation(info_class,
                                                     buffer,
                                                     buffer.Length,
                                                     out return_length)) == NtStatus.STATUS_INFO_LENGTH_MISMATCH)
            {
                int length = buffer.Length * 2;
                buffer.Resize(length);
            }
            status.ToNtException();
        }

        /// <summary>
        /// Get a list of handles
        /// </summary>
        /// <param name="pid">A process ID to filter on. If -1 will get all handles</param>
        /// <param name="allow_query">True to allow the handles returned to query for certain properties</param>
        /// <returns>The list of handles</returns>
        public static IEnumerable<NtHandle> GetHandles(int pid, bool allow_query)
        {
            using (SafeHGlobalBuffer handle_info = new SafeHGlobalBuffer(0x10000))
            {
                AllocateSafeBuffer(handle_info, SystemInformationClass.SystemHandleInformation);
                int handle_count = handle_info.Read<Int32>(0);
                SystemHandleTableInfoEntry[] handles = new SystemHandleTableInfoEntry[handle_count];
                handle_info.ReadArray((ulong)IntPtr.Size, handles, 0, handle_count);

                return handles.Where(h => pid == -1 || h.UniqueProcessId == pid).Select(h => new NtHandle(h, allow_query));
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
        /// Get all process information for the system.
        /// </summary>
        /// <returns>The list of process information.</returns>
        public static IEnumerable<NtProcessInformation> GetProcessInformation()
        {
            using (SafeHGlobalBuffer process_info = new SafeHGlobalBuffer(0x10000))
            {
                AllocateSafeBuffer(process_info, SystemInformationClass.SystemProcessInformation);
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
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(0x10000))
            {
                AllocateSafeBuffer(buffer, SystemInformationClass.SystemPageFileInformation);
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

        private static SystemKernelDebuggerInformation GetKernelDebuggerInformation()
        {
            using (var info = new SafeStructureInOutBuffer<SystemKernelDebuggerInformation>())
            {
                int return_length;
                NtSystemCalls.NtQuerySystemInformation(SystemInformationClass.SystemKernelDebuggerInformation,
                    info, info.Length, out return_length).ToNtException();
                return info.Result;
            }
        }

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

        private static T QuerySystemInfo<T>(T data, SystemInformationClass info_class) where T : struct
        {
            using (var buffer = data.ToBuffer())
            {
                int ret_length;
                NtSystemCalls.NtQuerySystemInformation(info_class, buffer,
                    buffer.Length, out ret_length).ToNtException();
                return buffer.Result;
            }
        }

        private static T QuerySystemInfo<T>(SystemInformationClass info_class) where T : struct
        {
            return QuerySystemInfo<T>(new T(), info_class);
        }

        /// <summary>
        /// Get current code integrity option settings.
        /// </summary>
        public static CodeIntegrityOptions CodeIntegrityOptions
        {
            get
            {
                return QuerySystemInfo(new SystemCodeIntegrityInformation() { Length = Marshal.SizeOf(typeof(SystemCodeIntegrityInformation)) },
                    SystemInformationClass.SystemCodeIntegrityInformation).CodeIntegrityOptions;
            }
        }

        private static byte[] QueryBlob(SystemInformationClass info_class)
        {
            int ret_length;
            NtStatus status = NtSystemCalls.NtQuerySystemInformation(info_class, SafeHGlobalBuffer.Null, 0, out ret_length);
            if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
            {
                if (status.IsSuccess())
                {
                    return new byte[0];
                }
                throw new NtException(status);
            }
            using (var buffer = new SafeHGlobalBuffer(ret_length))
            {
                NtSystemCalls.NtQuerySystemInformation(info_class, buffer, buffer.Length, out ret_length).ToNtException();
                return buffer.ToArray();
            }
        }

        /// <summary>
        /// Get code integrity policy.
        /// </summary>
        public static SystemCodeIntegrityPolicy CodeIntegrityPolicy
        {
            get
            {
                using (var buffer = new SafeStructureInOutBuffer<SystemCodeIntegrityPolicy>())
                {
                    int ret_length;
                    NtSystemCalls.NtQuerySystemInformation(SystemInformationClass.SystemCodeIntegrityPolicyInformation,
                        buffer, buffer.Length, out ret_length).ToNtException();
                    return buffer.Result;
                }
            }
        }

        /// <summary>
        /// Get code integrity unlock information.
        /// </summary>
        public static int CodeIntegrityUnlock
        {
            get
            {
                using (var buffer = new SafeStructureInOutBuffer<int>())
                {
                    int ret_length;
                    NtSystemCalls.NtQuerySystemInformation(SystemInformationClass.SystemCodeIntegrityUnlockInformation,
                        buffer, buffer.Length, out ret_length).ToNtException();
                    return buffer.Result;
                }
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
                    MemoryStream stm = new MemoryStream(QueryBlob(SystemInformationClass.SystemCodeIntegrityAllPoliciesInformation));
                    BinaryReader reader = new BinaryReader(stm);
                    int header_size = reader.ReadInt32();
                    int total_policies = reader.ReadInt32();
                    reader.ReadBytes(8 - header_size);
                    for (int i = 0; i < total_policies; ++i)
                    {
                        policies.Add(new CodeIntegrityPolicy(reader));
                    }
                }
                catch (NtException)
                {
                    byte[] policy = QueryBlob(SystemInformationClass.SystemCodeIntegrityPolicyFullInformation);
                    if (policy.Length > 0)
                    {
                        policies.Add(new CodeIntegrityPolicy(policy));
                    }
                }

                return policies.AsReadOnly();
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
                    int ret_length;
                    NtSystemCalls.NtSystemDebugControl(SystemDebugControlCode.KernelCrashDump, buffer, buffer.Length,
                        SafeHGlobalBuffer.Null, 0, out ret_length).ToNtException();
                }
            }
        }

        /// <summary>
        /// Get whether secure boot is enabled.
        /// </summary>
        public static bool SecureBootEnabled
        {
            get
            {
                return QuerySystemInfo<SystemSecurebootInformation>(SystemInformationClass.SystemSecureBootInformation).SecureBootEnabled;
            }
        }

        /// <summary>
        /// Get whether system supports secure boot.
        /// </summary>
        public static bool SecureBootCapable
        {
            get
            {
                return QuerySystemInfo<SystemSecurebootInformation>(SystemInformationClass.SystemSecureBootInformation).SecureBootCapable;
            }
        }

        /// <summary>
        /// Extract the secure boot policy.
        /// </summary>
        public static SecureBootPolicy SecureBootPolicy
        {
            get
            {
                int ret_length;
                NtStatus status = NtSystemCalls.NtQuerySystemInformation(SystemInformationClass.SystemSecureBootPolicyFullInformation,
                    SafeHGlobalBuffer.Null, 0, out ret_length);
                if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                {
                    throw new NtException(status);
                }

                using (var buffer = new SafeStructureInOutBuffer<SystemSecurebootPolicyFullInformation>(ret_length, true))
                {
                    NtSystemCalls.NtQuerySystemInformation(SystemInformationClass.SystemSecureBootPolicyFullInformation,
                        buffer, buffer.Length, out ret_length).ToNtException();
                    return new SecureBootPolicy(buffer);
                }
            }
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
        public static void SetSystemEnvironmentValue(string name, Guid vendor_guid, string value, int attributes)
        {
            SetSystemEnvironmentValue(name, vendor_guid, Encoding.Unicode.GetBytes(value), attributes);
        }
    }
}
