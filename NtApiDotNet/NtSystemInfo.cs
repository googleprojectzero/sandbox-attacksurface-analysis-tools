using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQuerySystemInformation(
          SystemInformationClass SystemInformationClass,
          IntPtr SystemInformation,
          int SystemInformationLength,
          out int ReturnLength
        );
    }

    [StructLayout(LayoutKind.Sequential)]
    public class SystemHandleTableInfoEntry
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public IntPtr Object;
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
    public class SystemProcessInformation
    {
        public uint NextEntryOffset;
        public uint NumberOfThreads;
        public LargeIntegerStruct WorkingSetPrivateSize; // since VISTA
        public uint HardFaultCount; // since WIN7
        public uint NumberOfThreadsHighWatermark; // since WIN7
        public ulong CycleTime; // since WIN7
        public LargeIntegerStruct CreateTime;
        public LargeIntegerStruct UserTime;
        public LargeIntegerStruct KernelTime;
        public UnicodeStringOut ImageName;
        public uint BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
        public uint HandleCount;
        public uint SessionId;
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

    public class HandleEntry
    {
        public int Pid { get; private set; }
        public string ObjectType { get; private set; }
        public AttributeFlags Attributes { get; private set; }
        public int Handle { get; private set; }
        public ulong Object { get; private set; }
        public uint GrantedAccess { get; private set; }
        public string Name
        {
            get
            {
                QueryValues();
                return _name;
            }
        }

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
                try
                {
                    using (NtGeneric obj = NtGeneric.DuplicateFrom(Pid, new IntPtr(Handle)))
                    {
                        // Ensure we get the real type, in case it changed _or_ it was wrong to begin with.
                        ObjectType = obj.GetTypeName();
                        _name = GetName(obj);
                        _sd = GetSecurityDescriptor(obj);
                    }
                }
                catch (NtException)
                {
                }
            }
        }

        internal HandleEntry(SystemHandleTableInfoEntry entry, bool allow_query)
        {
            Pid = entry.UniqueProcessId;
            ObjectTypeInfo info = ObjectTypeInfo.GetTypeByIndex(entry.ObjectTypeIndex);
            if (info != null)
            {
                ObjectType = info.Name;
            }
            else
            {
                ObjectType = String.Format("Unknown {0}", entry.ObjectTypeIndex);
            }
            Attributes = (AttributeFlags)entry.HandleAttributes;
            Handle = entry.HandleValue;
            Object = (ulong)entry.Object.ToInt64();
            GrantedAccess = entry.GrantedAccess;
            _allow_query = allow_query;
        }

        public NtObject GetObject()
        {
            NtToken.EnableDebugPrivilege();
            try
            {
                using (NtGeneric generic = NtGeneric.DuplicateFrom(Pid, new IntPtr(Handle)))
                {
                    // Ensure that we get the actual type from the handle.
                    ObjectType = generic.GetTypeName();
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
            return obj.GetName();
        }

        private SecurityDescriptor GetSecurityDescriptor(NtGeneric obj)
        {
            try
            {
                if (obj != null)
                {
                    using (NtGeneric dup = obj.Duplicate(GenericAccessRights.ReadControl))
                    {
                        return dup.GetSecurityDescriptor();
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
        MaxSystemInfoClass
    }

    public class NtSystemInfo
    {
        public static IEnumerable<HandleEntry> GetHandles(int pid, bool allow_query)
        {
            SafeHGlobalBuffer handleInfo = new SafeHGlobalBuffer(0x10000);
            try
            {
                NtStatus status = 0;
                int return_length = 0;
                while ((status = NtSystemCalls.NtQuerySystemInformation(SystemInformationClass.SystemHandleInformation,
                                                         handleInfo.DangerousGetHandle(),
                                                         handleInfo.Length,
                                                         out return_length)) == NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                {
                    int length = handleInfo.Length * 2;
                    handleInfo.Close();
                    handleInfo = new SafeHGlobalBuffer(length);
                }
                NtObject.StatusToNtException(status);

                IntPtr handleInfoBuf = handleInfo.DangerousGetHandle();
                int handle_count = Marshal.ReadInt32(handleInfoBuf);
                List<HandleEntry> ret = new List<HandleEntry>();
                handleInfoBuf += IntPtr.Size;
                for (int i = 0; i < handle_count; ++i)
                {
                    SystemHandleTableInfoEntry entry = (SystemHandleTableInfoEntry)Marshal.PtrToStructure(handleInfoBuf, typeof(SystemHandleTableInfoEntry));

                    if (pid == -1 || entry.UniqueProcessId == pid)
                    {
                        ret.Add(new HandleEntry(entry, allow_query));
                    }
                    handleInfoBuf += Marshal.SizeOf(typeof(SystemHandleTableInfoEntry));
                }
                return ret;
            }
            finally
            {
                handleInfo.Close();
            }
        }

        public static IEnumerable<HandleEntry> GetHandles()
        {
            return GetHandles(-1, true);
        }
    }
}
