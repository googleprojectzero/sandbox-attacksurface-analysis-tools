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

using NtApiDotNet.Ndr;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum ProcessAccessRights : uint
    {
        None = 0,
        Terminate = 0x0001,
        CreateThread = 0x0002,
        SetSessionId = 0x0004,
        VmOperation = 0x0008,
        VmRead = 0x0010,
        VmWrite = 0x0020,
        DupHandle = 0x0040,
        CreateProcess = 0x0080,
        SetQuota = 0x0100,
        SetInformation = 0x0200,
        QueryInformation = 0x0400,
        SuspendResume = 0x0800,
        QueryLimitedInformation = 0x1000,
        SetLimitedInformation = 0x2000,
        AllAccess = 0x1FFFFF,
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
    };

    public enum ProcessCreateState
    {
        InitialState,
        FailOnFileOpen,
        FailOnSectionCreate,
        FailExeFormat,
        FailMachineMismatch,
        FailExeName,
        Success,
    };

    public enum ProcessCreateStateSuccessOutputFlags : uint
    {
        None = 0,
        ProtectedProcess = 1,
        AddressSpaceOverride = 2,
        DevOverrideEnabled = 4,
        ManifestDetected = 8,
        ProtectedProcessLight = 16,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessCreateStateSuccessData
    {
        public ProcessCreateStateSuccessOutputFlags OutputFlags;
        public IntPtr FileHandle;
        public IntPtr SectionHandle;
        public ulong UserProcessParametersNative;
        public uint UserProcessParametersWow64;
        public uint CurrentParameterFlags;
        public ulong PebAddressNative;
        public uint PebAddressWow64;
        public ulong ManifestAddress;
        public uint ManifestSize;
    }

    [Flags]
    public enum ProcessCreateInitFlag : ushort
    {
        None = 0,
        WriteOutputOnExit = 1,
        DetectManifest = 2,
        IFEOSkipDebugger = 4,
        IFEODoNotPropagateKeyState = 8,
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ProcessCreateInfoData
    {
        // InitialState
        [FieldOffset(0)]
        public ProcessCreateInitFlag InitFlags;
        [FieldOffset(2)]
        public ImageCharacteristics ProhibitedImageCharacteristics;
        [FieldOffset(4)]
        public FileAccessRights AdditionalFileAccess;
        // FailOnSectionCreate
        [FieldOffset(0)]
        public IntPtr FileHandle;
        // FailExeFormat
        [FieldOffset(0)]
        public ushort DllCharacteristics;
        // FailExeName
        [FieldOffset(0)]
        public IntPtr IFEOKey;
        // Success
        [FieldOffset(0)]
        public ProcessCreateStateSuccessData Success;
    }

    [StructLayout(LayoutKind.Sequential)]
    public sealed class ProcessCreateInfo : IDisposable
    {
        IntPtr Size;
        public ProcessCreateState State;
        public ProcessCreateInfoData Data;

        public ProcessCreateInfo()
        {
            Size = new IntPtr(Marshal.SizeOf(this));
            State = ProcessCreateState.InitialState;
        }

        void IDisposable.Dispose()
        {
            // Close handles which come from errors
            switch (State)
            {
                case ProcessCreateState.FailOnSectionCreate:
                    NtObject.CloseHandle(Data.FileHandle);
                    break;
                case ProcessCreateState.FailExeName:
                    NtObject.CloseHandle(Data.IFEOKey);
                    break;
                case ProcessCreateState.Success:
                    NtObject.CloseHandle(Data.Success.FileHandle);
                    NtObject.CloseHandle(Data.Success.SectionHandle);
                    break;
            }
        }
    }

    public enum PsProtectedType
    {
        None,
        ProtectedLight,
        Protected,
    }

    public enum PsProtectedSigner
    {
        None,
        Authenticode,
        CodeGen,
        Antimalware,
        Lsa,
        Windows,
        WinTcb,
        System,
        App
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PsProtection
    {
        private readonly byte level;

        public PsProtection(PsProtectedType type, PsProtectedSigner signer, bool audit)
        {
            level = (byte)((int)type | (audit ? 0x8 : 0) | ((int)signer << 4));
        }

        public PsProtection(PsProtectedType type, PsProtectedSigner signer)
            : this(type, signer, false)
        {
        }

        public PsProtectedType Type { get { return (PsProtectedType)(level & 0x7); } }
        public bool Audit { get { return (level & 0x8) == 0x8; } }
        public PsProtectedSigner Signer { get { return (PsProtectedSigner)(level >> 4); } }
        public byte Level { get { return level; } }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessAttributeNative
    {
        public uint Attribute;
        public IntPtr Size;
        public IntPtr ValuePtr;
        public IntPtr ReturnLength;

        public ProcessAttributeNative(uint attribute, IntPtr valueptr, IntPtr size, IntPtr return_length)
        {
            Attribute = attribute;
            ValuePtr = valueptr;
            Size = size;
            ReturnLength = return_length;
        }
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Attributes")]
    public struct PsAttributeList
    {
        public IntPtr TotalLength;
        public ProcessAttributeNative Attributes;
    }

    public enum ProcessAttributeNum
    {
        ParentProcess, // in HANDLE
        DebugPort, // in HANDLE
        Token, // in HANDLE
        ClientId, // out PCLIENT_ID
        TebAddress, // out PTEB *
        ImageName, // in PWSTR
        ImageInfo, // out PSECTION_IMAGE_INFORMATION
        MemoryReserve, // in PPS_MEMORY_RESERVE
        PriorityClass, // in UCHAR
        ErrorMode, // in ULONG
        StdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
        HandleList, // in PHANDLE
        GroupAffinity, // in PGROUP_AFFINITY
        PreferredNode, // in PUSHORT
        IdealProcessor, // in PPROCESSOR_NUMBER
        UmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
        MitigationOptions, // in UCHAR
        ProtectionLevel,
        SecureProcess,
        JobList,
        ChildProcess, // since THRESHOLD
        AllApplicationPackages, // since REDSTONE
        Win32kFilter,
        SafeOpenPromptOriginClaim,
        BnoIsolation, // PS_BNO_ISOLATION_PARAMETERS
        DesktopAppPolicy, // in ULONG
    }

    [Flags]
    public enum ProcessCreateFlags
    {
        None = 0,
        BreakawayJob = 0x00000001,    // Only allowed if job allows breakaway
        NoDebugInherit = 0x00000002,
        InheritHandles = 0x00000004,
        OverrideAddressSpace = 0x00000008,
        LargePages = 0x00000010,
        LargePagesSystemDll = 0x00000020,
        ProtectedProcess = 0x00000040,
        CreateSession = 0x00000080,
        InheritFromParent = 0x00000100,
        TerminateOnAbnormalExit = 0x200,
        ForceBreakawayJob = 0x400,     // Needs TCB
                                       // This is same as ForceBreakawayJob prior to Anniversary Edition
        MinimalProcess = 0x800,        // Needs Kernel Privileges
        IgnoreSectionObject = 0x1000,
        MinimalProcessFlag1 = 0x2000,
        MinimalProcessFlag2 = 0x4000,
        AuxiliaryProcess = 0x8000,     // Needs TCB
    }

    [Flags]
    public enum ThreadCreateFlags
    {
        None = 0,
        Suspended = 0x00000001,
        SkipThreadAttach = 0x00000002,
        HideFromDebugger = 0x00000004,
        HasSecurityDescriptor = 0x00000010,
        AccessCheckInTarget = 0x00000020,
        InitialThread = 0x00000080,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessBasicInformation
    {
        public int ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public int BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [Flags]
    public enum ProcessExtendedBasicInformationFlags
    {
        None = 0,
        IsProtectedProcess = 0x00000001,
        IsWow64Process = 0x00000002,
        IsProcessDeleting = 0x00000004,
        IsCrossSessionCreate = 0x00000008,
        IsFrozen = 0x00000010,
        IsBackground = 0x00000020,
        IsStronglyNamed = 0x00000040,
        IsSecureProcess = 0x00000080,
        IsSubsystemProcess = 0x00000100,
    }

    [StructLayout(LayoutKind.Sequential)]
    public class ProcessExtendedBasicInformation
    {
        public IntPtr Size;
        public ProcessBasicInformation BasicInfo;
        public ProcessExtendedBasicInformationFlags Flags;

        public ProcessExtendedBasicInformation()
        {
            Size = new IntPtr(Marshal.SizeOf(this));
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessSessionInformation
    {
        public int SessionId;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("WindowTitle")]
    public struct ProcessWindowInformation
    {
        public uint WindowFlags;
        public ushort WindowTitleLength;
        public char WindowTitle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessChildProcessRestricted
    {
        public byte ProhibitChildProcesses;
        public byte AlwaysAllowSecureChildProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessChildProcessRestricted1709
    {
        public byte ProhibitChildProcesses;
        public byte AlwaysAllowSecureChildProcess;
        public byte AuditProhibitChildProcesses;
    }

    public enum ProcessSubsystemInformationType
    {
        Win32 = 0,
        WSL = 1,
    }

    public enum ProcessFaultFlags
    {
        None = 0,
        SetCrashed = 1,
        IncrementHangCount = 2,
        IncrementGhostCound = 4,
        PrefilterException = 8,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessFaultInformation
    {
        public ProcessFaultFlags FaultFlags;
        public int AdditionalInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessExceptionPort
    {
        public IntPtr ExceptionPortHandle;
        public int StateFlags;
    }

    [Flags]
    public enum ProcessDebugFlags
    {
        None = 0,
        DebugInherit = 1,
    }

    [Flags]
    public enum ProcessExecuteFlags
    {
        None = 0,
        ExecuteDisable = 0x01,
        ExecuteEnable = 0x02,
        DisableThunkEmulation = 0x04,
        Permanent = 0x08,
        ExecuteDispatchEnable = 0x10,
        ImageDispatchEnable = 0x20,
        DisableExceptionChainValidation = 0x40,
        Spare = 0x80
    }

    [Flags]
    public enum ProcessLoggingFlags
    {
        ReadVm = 1,
        WriteVm = 2,
        ProcessSuspendResume = 4,
        ThreadSuspendResume = 8,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessSecurityDomainInformation
    {
        public long SecurityDomain;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessCombineSecurityDomainInformation
    {
        public IntPtr ProcessHandle;
    }

    public enum ProcessInformationClass
    {
        ProcessBasicInformation, 
        ProcessQuotaLimits, 
        ProcessIoCounters, 
        ProcessVmCounters, 
        ProcessTimes, 
        ProcessBasePriority, 
        ProcessRaisePriority, 
        ProcessDebugPort, 
        ProcessExceptionPort, 
        ProcessAccessToken, 
        ProcessLdtInformation, 
        ProcessLdtSize, 
        ProcessDefaultHardErrorMode, 
        ProcessIoPortHandlers, 
        ProcessPooledUsageAndLimits, 
        ProcessWorkingSetWatch, 
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup, 
        ProcessPriorityClass, 
        ProcessWx86Information,
        ProcessHandleCount, 
        ProcessAffinityMask, 
        ProcessPriorityBoost, 
        ProcessDeviceMap, 
        ProcessSessionInformation, 
        ProcessForegroundInformation, 
        ProcessWow64Information, 
        ProcessImageFileName, 
        ProcessLUIDDeviceMapsEnabled, 
        ProcessBreakOnTermination, 
        ProcessDebugObjectHandle, 
        ProcessDebugFlags, 
        ProcessHandleTracing, 
        ProcessIoPriority, 
        ProcessExecuteFlags, 
        ProcessResourceManagement,
        ProcessCookie, 
        ProcessImageInformation, 
        ProcessCycleTime, 
        ProcessPagePriority, 
        ProcessInstrumentationCallback, 
        ProcessThreadStackAllocation, 
        ProcessWorkingSetWatchEx, 
        ProcessImageFileNameWin32, 
        ProcessImageFileMapping, 
        ProcessAffinityUpdateMode, 
        ProcessMemoryAllocationMode, 
        ProcessGroupInformation, 
        ProcessTokenVirtualizationEnabled, 
        ProcessConsoleHostProcess, 
        ProcessWindowInformation, 
        ProcessHandleInformation, 
        ProcessMitigationPolicy, 
        ProcessDynamicFunctionTableInformation,
        ProcessHandleCheckingMode,
        ProcessKeepAliveCount, 
        ProcessRevokeFileHandles, 
        ProcessWorkingSetControl, 
        ProcessHandleTable, 
        ProcessCheckStackExtentsMode,
        ProcessCommandLineInformation, 
        ProcessProtectionInformation, 
        ProcessMemoryExhaustion, 
        ProcessFaultInformation, 
        ProcessTelemetryIdInformation, 
        ProcessCommitReleaseInformation, 
        ProcessDefaultCpuSetsInformation,
        ProcessAllowedCpuSetsInformation,
        ProcessSubsystemProcess,
        ProcessJobMemoryInformation, 
        ProcessInPrivate, 
        ProcessRaiseUMExceptionOnInvalidHandleClose,
        ProcessIumChallengeResponse,
        ProcessChildProcessInformation, 
        ProcessHighGraphicsPriorityInformation,
        ProcessSubsystemInformation, 
        ProcessEnergyValues, 
        ProcessActivityThrottleState, 
        ProcessActivityThrottlePolicy, 
        ProcessWin32kSyscallFilterInformation,
        ProcessDisableSystemAllowedCpuSets,
        ProcessWakeInformation, 
        ProcessEnergyTrackingState, 
        ProcessManageWritesToExecutableMemory, 
        ProcessCaptureTrustletLiveDump,
        ProcessTelemetryCoverage,
        ProcessEnclaveInformation,
        ProcessEnableReadWriteVmLogging, 
        ProcessUptimeInformation, 
        ProcessImageSection,
        ProcessDebugAuthInformation,
        ProcessSystemResourceManagement,
        ProcessSequenceNumber,
        ProcessLoaderDetour,
        ProcessSecurityDomainInformation,
        ProcessCombineSecurityDomainsInformation,
        ProcessEnableLogging,
        ProcessLeapSecondInformation,
        ProcessFiberShadowStackAllocation,
        ProcessFreeFiberShadowStackAllocation
    }

    public enum ProcessMitigationPolicy
    {
        DEP, // Comes from ProcessExecuteFlags, we don't use.
        ASLR,
        DynamicCode,
        StrictHandleCheck,
        SystemCallDisable,
        MitigationOptionsMask, // Unused
        ExtensionPointDisable,
        ControlFlowGuard,
        Signature,
        FontDisable,
        ImageLoad,
        SystemCallFilter,
        PayloadRestriction,
        ChildProcess,
        SideChannelIsolation
    }

    public struct MitigationPolicy
    {
        public ProcessMitigationPolicy Policy;
        public int Result;
    }

    public struct ProcessDepStatus
    {
        public bool Permanent;
        public bool Enabled;
        public bool DisableAtlThunkEmulation;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class ClientId
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;

        public ClientId()
        {
        }

        public ClientId(int pid, int tid)
        {
            UniqueProcess = new IntPtr(pid);
            UniqueThread = new IntPtr(tid);
        }

        public ClientId(ClientIdStruct cid)
        {
            UniqueProcess = cid.UniqueProcess;
            UniqueThread = cid.UniqueThread;
        }

        public override string ToString()
        {
            return $"PID: {UniqueProcess.ToInt32()} - TID: {UniqueThread.ToInt32()}";
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ClientIdStruct
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessDeviceMapInformationSet
    {
        public IntPtr DirectoryHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessDeviceMapInformationQuery
    {
        public uint DriveMap;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] DriveType;
    }

    public enum ProcessDeviceMapQueryFlags
    {
        LuidDosDevicesOnly = 0x00000001
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessDeviceMapInformationQueryEx
    {
        public uint DriveMap;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] DriveType;
        public ProcessDeviceMapQueryFlags Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessAccessToken
    {
        public IntPtr AccessToken;
        public IntPtr InitialThread;
    }

    [Flags]
    public enum ChildProcessMitigationFlags
    {
        None = 0,
        Restricted = 1,
        Override = 2,
        RestrictedUnlessSecure = 4,
    }

    [Flags]
    public enum CreateProcessParametersFlags
    {
        None = 0,
        Normalize = 1,
    }

    [Flags]
    public enum GetNextProcessFlags
    {
        None = 0,
        PreviousProcess = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessHandleTableEntryInfo
    {
        public IntPtr HandleValue;
        public IntPtr HandleCount;
        public IntPtr PointerCount;
        public AccessMask GrantedAccess;
        public int ObjectTypeIndex;
        public AttributeFlags HandleAttributes;
        public int Reserved;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Handles")]
    public struct ProcessHandleSnapshotInformation
    {
        public IntPtr NumberOfHandles;
        public IntPtr Reserved;
        public ProcessHandleTableEntryInfo Handles;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationProcess(
            SafeKernelObjectHandle ProcessHandle,
            ProcessInformationClass ProcessInformationClass,
            SafeBuffer ProcessInformation,
            int ProcessInformationLength,
            out int ReturnLength
         );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationProcess(
            SafeKernelObjectHandle ProcessHandle,
            ProcessInformationClass ProcessInformationClass,
            SafeBuffer ProcessInformation,
            int ProcessInformationLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtGetNextProcess(
          SafeKernelObjectHandle ProcessHandle,
          ProcessAccessRights DesiredAccess,
          AttributeFlags HandleAttributes,
          GetNextProcessFlags Flags,
          out SafeKernelObjectHandle NewProcessHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateUserProcess(
          out SafeKernelObjectHandle ProcessHandle,
          out SafeKernelObjectHandle ThreadHandle,
          ProcessAccessRights ProcessDesiredAccess,
          ThreadAccessRights ThreadDesiredAccess,
          ObjectAttributes ProcessObjectAttributes,
          ObjectAttributes ThreadObjectAttributes,
          ProcessCreateFlags ProcessFlags,
          ThreadCreateFlags ThreadFlags,
          IntPtr ProcessParameters,
          [In, Out] ProcessCreateInfo CreateInfo,
          [In, Out] ProcessAttributeList AttributeList
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtTerminateProcess(SafeKernelObjectHandle ProcessHandle, NtStatus ExitCode);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateProcess(out SafeKernelObjectHandle ProcessHandle, ProcessAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes, IntPtr InheritFromProcessHandle, [MarshalAs(UnmanagedType.U1)] bool InheritHandles,
            IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateProcessEx(out SafeKernelObjectHandle ProcessHandle, ProcessAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes, SafeHandle InheritFromProcessHandle, ProcessCreateFlags Flags, SafeHandle SectionHandle,
            SafeHandle DebugPort, SafeHandle ExceptionPort, int Unused);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenProcess(
          out SafeKernelObjectHandle ProcessHandle,
          ProcessAccessRights DesiredAccess,
          [In] ObjectAttributes ObjectAttributes,
          [In] ClientId ClientId
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSuspendProcess(SafeKernelObjectHandle ProcessHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtResumeProcess(SafeKernelObjectHandle ProcessHandle);
    }

    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlCreateProcessParametersEx(
            [Out] out IntPtr pProcessParameters,
            [In] UnicodeString ImagePathName,
            [In] UnicodeString DllPath,
            [In] UnicodeString CurrentDirectory,
            [In] UnicodeString CommandLine,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] Environment,
            [In] UnicodeString WindowTitle,
            [In] UnicodeString DesktopInfo,
            [In] UnicodeString ShellInfo,
            [In] UnicodeString RuntimeData,
            CreateProcessParametersFlags Flags);

        [DllImport("ntdll.dll")]
        public static extern void RtlDestroyProcessParameters(IntPtr pProcessParameters);
    }

    [Flags]
    public enum PebFlags : byte
    {
        None = 0,
        ImageUsesLargePages = 0x01,
        IsProtectedProcess = 0x02,
        IsImageDynamicallyRelocated = 0x04,
        SkipPatchingUser32Forwarders = 0x08,
        IsPackagedProcess = 0x10,
        IsAppContainer = 0x20,
        IsProtectedProcessLight = 0x40,
        IsLongPathAwareProcess = 0x80,
    }

    public interface IPeb
    {
        PebFlags GetPebFlags();
        IntPtr GetImageBaseAddress();
        IntPtr GetProcessHeap();
        IntPtr GetProcessParameters();
    }

    /// <summary>
    /// Partial definition of the PEB
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct PartialPeb : IPeb
    {
        public byte InheritedAddressSpace;
        public byte ReadImageFileExecOptions;
        public byte BeingDebugged;
        public PebFlags PebFlags;
        public IntPtr Mutant;
        public IntPtr ImageBaseAddress;
        public IntPtr Ldr; // PPEB_LDR_DATA
        public IntPtr ProcessParameters; // PRTL_USER_PROCESS_PARAMETERS
        public IntPtr SubSystemData;
        public IntPtr ProcessHeap;

        IntPtr IPeb.GetProcessParameters()
        {
            return ProcessParameters;
        }

        IntPtr IPeb.GetImageBaseAddress()
        {
            return ImageBaseAddress;
        }

        PebFlags IPeb.GetPebFlags()
        {
            return PebFlags;
        }

        IntPtr IPeb.GetProcessHeap()
        {
            return ProcessHeap;
        }
    }

    /// <summary>
    /// Partial definition of the PEB
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct PartialPeb32 : IPeb
    {
        public byte InheritedAddressSpace;
        public byte ReadImageFileExecOptions;
        public byte BeingDebugged;
        public PebFlags PebFlags;
        public int Mutant;
        public int ImageBaseAddress;
        public int Ldr; // PPEB_LDR_DATA
        public int ProcessParameters; // PRTL_USER_PROCESS_PARAMETERS
        public int SubSystemData;
        public int ProcessHeap;

        IntPtr IPeb.GetImageBaseAddress()
        {
            return new IntPtr(ImageBaseAddress);
        }

        PebFlags IPeb.GetPebFlags()
        {
            return PebFlags;
        }

        IntPtr IPeb.GetProcessHeap()
        {
            return new IntPtr(ProcessHeap);
        }

        IntPtr IPeb.GetProcessParameters()
        {
            return new IntPtr(ProcessParameters);
        }
    }

#pragma warning restore 1591
}
