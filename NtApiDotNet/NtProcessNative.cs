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
using System.Linq;
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
    public class ProcessCreateInfo
    {
        IntPtr Size;
        public ProcessCreateState State;
        public ProcessCreateInfoData Data;

        public ProcessCreateInfo()
        {
            Size = new IntPtr(Marshal.SizeOf(this));
            State = ProcessCreateState.InitialState;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RtlDriveLetterCurDir
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public UnicodeStringOut DosPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class RtlUserProcessParameters
    {
        public uint MaximumLength;
        public uint Length;
        public uint Flags;
        public uint DebugFlags;
        public IntPtr ConsoleHandle;
        public uint ConsoleFlags;
        public IntPtr StdInputHandle;
        public IntPtr StdOutputHandle;
        public IntPtr StdErrorHandle;
        public UnicodeStringOut CurrentDirectoryPath;
        public IntPtr CurrentDirectoryHandle;
        public UnicodeStringOut DllPath;
        public UnicodeStringOut ImagePathName;
        public UnicodeStringOut CommandLine;
        public IntPtr Environment;
        public uint StartingPositionLeft;
        public uint StartingPositionTop;
        public uint Width;
        public uint Height;
        public uint CharWidth;
        public uint CharHeight;
        public uint ConsoleTextAttributes;
        public uint WindowFlags;
        public uint ShowWindowFlags;
        public UnicodeStringOut WindowTitle;
        public UnicodeStringOut DesktopName;
        public UnicodeStringOut ShellInfo;
        public UnicodeStringOut RuntimeData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
        public RtlDriveLetterCurDir[] DLCurrentDirectory;
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
        public byte IsNoChildProcessRestricted;
        public byte EnableAutomaticOverride;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessChildProcessRestricted1709
    {
        public byte IsNoChildProcessRestricted;
        public byte EnableAutomaticOverride;
        public byte Unknown2;
    }

    public enum ProcessSubsystemInformationType
    {
        Win32 = 0,
        WSL = 1,
    }

    public enum ProcessInformationClass
    {
        ProcessBasicInformation, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
        ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
        ProcessIoCounters, // q: IO_COUNTERS
        ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
        ProcessTimes, // q: KERNEL_USER_TIMES
        ProcessBasePriority, // s: KPRIORITY
        ProcessRaisePriority, // s: ULONG
        ProcessDebugPort, // q: HANDLE
        ProcessExceptionPort, // s: HANDLE
        ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
        ProcessLdtInformation, // 10, qs: PROCESS_LDT_INFORMATION
        ProcessLdtSize, // s: PROCESS_LDT_SIZE
        ProcessDefaultHardErrorMode, // qs: ULONG
        ProcessIoPortHandlers, // (kernel-mode only)
        ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
        ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
        ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
        ProcessWx86Information,
        ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
        ProcessAffinityMask, // s: KAFFINITY
        ProcessPriorityBoost, // qs: ULONG
        ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
        ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
        ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
        ProcessWow64Information, // q: ULONG_PTR
        ProcessImageFileName, // q: UNICODE_STRING
        ProcessLUIDDeviceMapsEnabled, // q: ULONG
        ProcessBreakOnTermination, // qs: ULONG
        ProcessDebugObjectHandle, // 30, q: HANDLE
        ProcessDebugFlags, // qs: ULONG
        ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
        ProcessIoPriority, // qs: ULONG
        ProcessExecuteFlags, // qs: ULONG
        ProcessResourceManagement,
        ProcessCookie, // q: ULONG
        ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
        ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
        ProcessPagePriority, // q: ULONG
        ProcessInstrumentationCallback, // 40
        ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
        ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
        ProcessImageFileNameWin32, // q: UNICODE_STRING
        ProcessImageFileMapping, // q: HANDLE (input)
        ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
        ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
        ProcessGroupInformation, // q: USHORT[]
        ProcessTokenVirtualizationEnabled, // s: ULONG
        ProcessConsoleHostProcess, // q: ULONG_PTR
        ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
        ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
        ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
        ProcessDynamicFunctionTableInformation,
        ProcessHandleCheckingMode,
        ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
        ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
        ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
        ProcessHandleTable, // since WINBLUE
        ProcessCheckStackExtentsMode,
        ProcessCommandLineInformation, // 60, q: UNICODE_STRING
        ProcessProtectionInformation, // q: PS_PROTECTION
        ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
        ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
        ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
        ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
        ProcessDefaultCpuSetsInformation,
        ProcessAllowedCpuSetsInformation,
        ProcessSubsystemProcess,
        ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
        ProcessInPrivate, // since THRESHOLD2 // 70
        ProcessRaiseUMExceptionOnInvalidHandleClose,
        ProcessIumChallengeResponse,
        ProcessChildProcessInformation, // PROCESS_CHILD_PROCESS_INFORMATION
        ProcessHighGraphicsPriorityInformation,
        ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
        ProcessEnergyValues, // PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
        ProcessActivityThrottleState, // PROCESS_ACTIVITY_THROTTLE_STATE
        ProcessActivityThrottlePolicy, // PROCESS_ACTIVITY_THROTTLE_POLICY
        ProcessWin32kSyscallFilterInformation,
        ProcessDisableSystemAllowedCpuSets,
        ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
        ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
        ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
        ProcessCaptureTrustletLiveDump,
        ProcessTelemetryCoverage,
        ProcessEnclaveInformation,
        ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
        ProcessUptimeInformation, // PROCESS_UPTIME_INFORMATION
        ProcessImageSection,
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
          int Flags,
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
            uint Flags);

        [DllImport("ntdll.dll")]
        public static extern void RtlDestroyProcessParameters(IntPtr pProcessParameters);
    }

    public class ProcessAttribute : IDisposable
    {
        const uint NumberMask = 0x0000FFFF;
        const uint ThreadOnly = 0x00010000; // Attribute may be used with thread creation
        const uint InputOnly = 0x00020000; // Attribute is input only
        const uint Additive = 0x00040000; // Attribute may be "accumulated," e.g. bitmasks, counters, etc

        SafeHandle _handle;
        ProcessAttributeNum _attribute_num;
        bool _thread;
        bool _input;
        bool _additive;
        IntPtr _valueptr;
        IntPtr _size;
        IntPtr _return_length;

        private ProcessAttribute(ProcessAttributeNum num, bool thread, bool input, bool additive, IntPtr valueptr, int size, IntPtr return_length)
        {
            _attribute_num = num;
            _thread = thread;
            _input = input;
            _additive = additive;
            _valueptr = valueptr;
            _size = new IntPtr(size);
            _return_length = return_length;
        }

        private ProcessAttribute(ProcessAttributeNum num, bool thread, bool input, bool additive, SafeHandle handle, int size, IntPtr return_length) :
           this(num, thread, input, additive, handle.DangerousGetHandle(), size, return_length)
        {
            _handle = handle;
        }

        private ProcessAttribute(ProcessAttributeNum num, bool thread, bool input, bool additive, SafeHGlobalBuffer handle) :
          this(num, thread, input, additive, handle, handle.Length, IntPtr.Zero)
        {
        }

        private ProcessAttribute(ProcessAttributeNum num, bool thread, bool input, bool additive, SafeKernelObjectHandle handle) :
            this(num, thread, input, additive, handle, IntPtr.Size, IntPtr.Zero)
        {
        }

        public ProcessAttributeNative GetNativeAttribute()
        {
            IntPtr valueptr = _handle != null ? _handle.DangerousGetHandle() : _valueptr;
            return new ProcessAttributeNative(((uint)_attribute_num & NumberMask)
              | (_thread ? ThreadOnly : 0) | (_input ? InputOnly : 0) | (_additive ? Additive : 0), valueptr, _size, _return_length);
        }

        public static ProcessAttribute ImageName(string image_name)
        {
            SafeHGlobalBuffer name = new SafeHGlobalBuffer(Marshal.StringToHGlobalUni(image_name), image_name.Length * 2, true);
            return new ProcessAttribute(ProcessAttributeNum.ImageName, false, true, false,
                  name);
        }

        public static ProcessAttribute ParentProcess(SafeKernelObjectHandle parent_process)
        {
            return new ProcessAttribute(ProcessAttributeNum.ParentProcess,
              false, true, true, NtObject.DuplicateHandle(parent_process));
        }

        public static ProcessAttribute Token(SafeKernelObjectHandle token)
        {
            return new ProcessAttribute(ProcessAttributeNum.Token,
              false, true, true, NtObject.DuplicateHandle(token));
        }

        public static ProcessAttribute ImageInfo(SafeStructureInOutBuffer<SectionImageInformation> image_information)
        {
            return new ProcessAttribute(ProcessAttributeNum.ImageInfo, false, false, false, image_information);
        }

        public static ProcessAttribute ClientId(SafeStructureInOutBuffer<ClientId> client_id)
        {
            return new ProcessAttribute(ProcessAttributeNum.ClientId, true, false, false, client_id);
        }

        public static ProcessAttribute ChildProcess(bool child_process_restricted, bool child_process_override)
        {
            int value = child_process_restricted ? 1 : 0;
            if (child_process_override)
            {
                value |= 2;
            }
            return new ProcessAttribute(ProcessAttributeNum.ChildProcess, false, true, false, value.ToBuffer());
        }

        public static ProcessAttribute ProtectionLevel(PsProtectedType type, PsProtectedSigner signer, bool audit)
        {
            PsProtection protection = new PsProtection(type, signer, audit);

            return new ProcessAttribute(ProcessAttributeNum.ProtectionLevel, false, true, true, new IntPtr(protection.Level), 1, IntPtr.Zero);
        }

        public static ProcessAttribute HandleList(IEnumerable<SafeHandle> handles)
        {
            return new ProcessAttribute(ProcessAttributeNum.HandleList, false, true, false,
              new SafeHandleListHandle(handles.Select(h => NtObject.DuplicateHandle(h.ToSafeKernelHandle()))));
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (_handle != null)
                {
                    _handle.Close();
                    _handle = null;
                }

                disposedValue = true;
            }
        }

        ~ProcessAttribute()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion

    };

    [StructLayout(LayoutKind.Sequential)]
    public sealed class ProcessAttributeList
    {
        IntPtr TotalLength;
        // Allocate upto 64 entries.
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        ProcessAttributeNative[] Attributes;

        public ProcessAttributeList(IEnumerable<ProcessAttribute> attributes)
        {
            ProcessAttributeNative[] attrs = attributes.Select(a => a.GetNativeAttribute()).ToArray();
            Attributes = new ProcessAttributeNative[64];
            Array.Copy(attrs, Attributes, attrs.Length);
            TotalLength = new IntPtr(IntPtr.Size + Marshal.SizeOf(typeof(ProcessAttributeNative)) * attrs.Length);
        }
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
    }

#pragma warning restore 1591
}
