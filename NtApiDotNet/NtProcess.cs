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
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum ProcessAccessRights : uint
    {
        None = 0,
        CreateProcess = 0x0080,
        CreateThread = 0x0002,
        DupHandle = 0x0040,
        QueryInformation = 0x0400,
        QueryLimitedInformation = 0x1000,
        SetInformation = 0x0200,
        SetQuota = 0x0100,
        SuspendResume = 0x0800,
        Terminate = 0x0001,
        VmOperation = 0x0008,
        VmRead = 0x0010,
        VmWrite = 0x0020,
        All = 0x1FFFFF,
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
        ushort Flags;
        ushort Length;
        uint TimeStamp;
        UnicodeStringOut DosPath;
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


    [Flags]
    public enum SectionImageFlags : byte
    {
        ComPlusNativeReady = 1,
        ComPlusILOnly = 2,
        ImageDynamicallyRelocated = 4,
        ImageMappedFlat = 8,
        BaseBelow4gb = 16
    }

    [StructLayout(LayoutKind.Sequential)]
    public class SectionImageInformation
    {
        public IntPtr TransferAddress;
        public uint ZeroBits;
        public IntPtr MaximumStackSize;
        public IntPtr CommittedStackSize;
        public uint SubSystemType;
        public ushort SubSystemMinorVersion;
        public ushort SubSystemMajorVersion;
        public uint GpValue;
        public ushort ImageCharacteristics;
        public ushort DllCharacteristics;
        public ushort Machine;
        [MarshalAs(UnmanagedType.U1)]
        public bool ImageContainsCode;
        [MarshalAs(UnmanagedType.U1)]
        public SectionImageFlags ImageFlags;
        public uint LoaderFlags;
        public uint ImageFileSize;
        public uint CheckSum;
    };

    public enum PsProtectedType
    {
        PsProtectedTypeNone,
        PsProtectedTypeProtectedLight,
        PsProtectedTypeProtected,
        PsProtectedTypeMax
    }

    public enum PsProtectedSigner
    {
        PsProtectedSignerNone,
        PsProtectedSignerAuthenticode,
        PsProtectedSignerCodeGen,
        PsProtectedSignerAntimalware,
        PsProtectedSignerLsa,
        PsProtectedSignerWindows,
        PsProtectedSignerWinTcb,
        PsProtectedSignerMax
    }

    [StructLayout(LayoutKind.Sequential)]
    public class PsProtection
    {
        private byte level;

        public PsProtection(PsProtectedType type, PsProtectedSigner signer, bool audit)
        {
            level = (byte)((int)type | (audit ? 0x8 : 0) | ((int)signer << 4));
        }

        public PsProtection()
        {
        }
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
        ChildProcess, // since THRESHOLD
        JobList,
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
    public class ProcessBasicInformation
    {
        public int ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public int BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class ProcessSessionInformation
    {
        public int SessionId;
    }

    public enum ProcessInfoClass
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
        ProcessReserved1Information,
        ProcessReserved2Information,
        ProcessSubsystemProcess, // 70
        ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
    }

    public enum ProcessMitigationPolicy
    {
        ProcessDEPPolicy, // Comes from ProcessExecuteFlags, we don't use.
        ProcessASLRPolicy,
        ProcessDynamicCodePolicy,
        ProcessStrictHandleCheckPolicy,
        ProcessSystemCallDisablePolicy,
        ProcessMitigationOptionsMask, // Unused
        ProcessExtensionPointDisablePolicy,
        ProcessReserved1Policy, // Unused
        ProcessSignaturePolicy,
        ProcessFontDisablePolicy,
        ProcessImageLoadPolicy,
        ProcessReturnFlowGuardPolicy,
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
    
    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationProcess(SafeKernelObjectHandle ProcessHandle,
          ProcessInfoClass ProcessInformationClass,
          SafeHGlobalBuffer ProcessInformation,
          int ProcessInformationLength,
          [Out] out int ReturnLength
          );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationProcess(SafeKernelObjectHandle ProcessHandle,
            ProcessInfoClass ProcessInformationClass,
            SafeHGlobalBuffer ProcessInformation,
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
            return new ProcessAttribute(ProcessAttributeNum.ChildProcess, false, true, false, new IntPtr(value), IntPtr.Size, IntPtr.Zero);
        }

        public static ProcessAttribute ProtectionLevel(PsProtectedType type, PsProtectedSigner signer, bool audit)
        {
            return new ProcessAttribute(ProcessAttributeNum.ProtectionLevel, false, true, true, new PsProtection(type, signer, audit).ToBuffer());
        }

        public static ProcessAttribute HandleList(IEnumerable<SafeHandle> handles)
        {
            return new ProcessAttribute(ProcessAttributeNum.HandleList, false, true, false,
              new SafeHandleListHandle(handles.Select(h => NtObject.DuplicateHandle(h))));
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
#pragma warning restore 1591

    /// <summary>
    /// Class representing a NT Process object.
    /// </summary>
    public class NtProcess : NtObjectWithDuplicate<NtProcess, ProcessAccessRights>
    {
        private int? _pid;
        private int? _ppid;
        private IntPtr? _peb;

        private void PopulateBasicInformation()
        {
            using (SafeStructureInOutBuffer<ProcessBasicInformation> basic_info = new SafeStructureInOutBuffer<ProcessBasicInformation>())
            {
                int return_length = 0;
                NtSystemCalls.NtQueryInformationProcess(Handle, ProcessInfoClass.ProcessBasicInformation,
                  basic_info, basic_info.Length, out return_length).ToNtException();
                ProcessBasicInformation result = basic_info.Result;
                _pid = result.UniqueProcessId.ToInt32();
                _ppid = result.InheritedFromUniqueProcessId.ToInt32();
                _peb = result.PebBaseAddress;
            }
        }

        private SafeStructureInOutBuffer<T> Query<T>(ProcessInfoClass info_class) where T : new()
        {
            int return_length = 0;
            NtStatus status = NtSystemCalls.NtQueryInformationProcess(Handle, info_class, SafeHGlobalBuffer.Null, 0, out return_length);
            if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH && status != NtStatus.STATUS_BUFFER_TOO_SMALL)
            {
                throw new NtException(status);
            }

            SafeStructureInOutBuffer<T> buffer = new SafeStructureInOutBuffer<T>(return_length, false);
            try
            {
                NtSystemCalls.NtQueryInformationProcess(Handle, info_class, buffer, buffer.Length, out return_length).ToNtException();
                return buffer;
            }
            catch
            {
                buffer.Close();
                throw;
            }
        }


        internal NtProcess(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        /// <summary>
        /// Gets all accessible processes on the system.
        /// </summary>
        /// <param name="desired_access">The access desired for each process.</param>
        /// <returns>The list of accessible processes.</returns>
        public static IEnumerable<NtProcess> GetProcesses(ProcessAccessRights desired_access)
        {
            List<NtProcess> processes = new List<NtProcess>();
            NtProcess process = NtProcess.GetFirstProcess(desired_access);
            while (process != null)
            {
                processes.Add(process);
                process = process.GetNextProcess(desired_access);
            }
            return processes.AsReadOnly();
        }

        /// <summary>
        /// Get first accessible process (used in combination with GetNextProcess)
        /// </summary>
        /// <param name="desired_access">The access required for the process.</param>
        /// <returns>The accessible process, or null if one couldn't be opened.</returns>
        public static NtProcess GetFirstProcess(ProcessAccessRights desired_access)
        {
            SafeKernelObjectHandle new_handle;
            NtStatus status = NtSystemCalls.NtGetNextProcess(SafeKernelObjectHandle.Null, desired_access,
                AttributeFlags.None, 0, out new_handle);
            if (status == NtStatus.STATUS_SUCCESS)
            {
                return new NtProcess(new_handle);
            }
            return null;
        }

        /// <summary>
        /// Get next accessible process (used in combination with GetFirstProcess)
        /// </summary>
        /// <param name="desired_access">The access required for the process.</param>
        /// <returns>The accessible process, or null if one couldn't be opened.</returns>
        public NtProcess GetNextProcess(ProcessAccessRights desired_access)
        {
            SafeKernelObjectHandle new_handle;
            NtStatus status = NtSystemCalls.NtGetNextProcess(Handle, desired_access, AttributeFlags.None, 0, out new_handle);
            if (status == NtStatus.STATUS_SUCCESS)
            {
                return new NtProcess(new_handle);
            }
            return null;
        }

        /// <summary>
        /// Get accessible threads for a process.
        /// </summary>
        /// <param name="desired_access">The desired access for the threads</param>
        /// <returns>The list of threads</returns>
        public IEnumerable<NtThread> GetThreads(ThreadAccessRights desired_access)
        {
            List<NtThread> handles = new List<NtThread>();
            SafeKernelObjectHandle current_handle = new SafeKernelObjectHandle(IntPtr.Zero, false);
            NtStatus status = NtSystemCalls.NtGetNextThread(Handle, current_handle, desired_access, AttributeFlags.None, 0, out current_handle);
            while (status == NtStatus.STATUS_SUCCESS)
            {
                handles.Add(new NtThread(current_handle));
                status = NtSystemCalls.NtGetNextThread(Handle, current_handle, desired_access, AttributeFlags.None, 0, out current_handle);
            }
            return handles;
        }

        /// <summary>
        /// Get accessible threads for a process.
        /// </summary>
        /// <returns>The list of threads</returns>
        public IEnumerable<NtThread> GetThreads()
        {
            return GetThreads(ThreadAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Get the process' session ID
        /// </summary>
        public int SessionId
        {
            get
            {
                using (SafeStructureInOutBuffer<ProcessSessionInformation> session_info = new SafeStructureInOutBuffer<ProcessSessionInformation>())
                {
                    int return_length = 0;
                    NtSystemCalls.NtQueryInformationProcess(Handle, ProcessInfoClass.ProcessSessionInformation,
                      session_info, session_info.Length, out return_length).ToNtException();
                    return session_info.Result.SessionId;
                }
            }
        }

        /// <summary>
        /// Get the process' ID
        /// </summary>
        public int ProcessId
        {
            get
            {
                if (!_pid.HasValue)
                    PopulateBasicInformation();
                return _pid.Value;
            }
        }

        /// <summary>
        /// Get the process' parent process ID
        /// </summary>
        public int ParentProcessId
        {
            get
            {
                if (!_ppid.HasValue)
                    PopulateBasicInformation();
                return _ppid.Value;
            }
        }

        /// <summary>
        /// Get the memory address of the PEB
        /// </summary>
        public IntPtr PebAddress
        {
            get
            {
                if (!_peb.HasValue)
                    PopulateBasicInformation();
                return _peb.Value;
            }
        }

        /// <summary>
        /// Get the process' exit status.
        /// </summary>
        public int ExitStatus
        {
            get
            {
                using (SafeStructureInOutBuffer<ProcessBasicInformation> basic_info = new SafeStructureInOutBuffer<ProcessBasicInformation>())
                {
                    int return_length = 0;
                    NtSystemCalls.NtQueryInformationProcess(Handle, ProcessInfoClass.ProcessBasicInformation,
                      basic_info, basic_info.Length, out return_length).ToNtException();
                    return basic_info.Result.ExitStatus;
                }
            }
        }

        /// <summary>
        /// Get the process' command line
        /// </summary>
        public string CommandLine
        {
            get
            {
                using (var buffer = Query<UnicodeStringOut>(ProcessInfoClass.ProcessCommandLineInformation))
                {
                    return buffer.Result.ToString();
                }
            }
        }

        /// <summary>
        /// Open a process
        /// </summary>
        /// <param name="pid">The process ID to open</param>
        /// <param name="desired_access">The desired access for the handle</param>
        /// <returns>The opened process</returns>
        public static NtProcess Open(int pid, ProcessAccessRights desired_access)
        {
            SafeKernelObjectHandle process;
            ClientId client_id = new ClientId();
            client_id.UniqueProcess = new IntPtr(pid);
            NtSystemCalls.NtOpenProcess(out process, desired_access, new ObjectAttributes(), client_id).ToNtException();
            return new NtProcess(process) { _pid = pid };
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="ParentProcess">The parent process</param>
        /// <param name="Flags">Creation flags</param>
        /// <param name="SectionHandle">Handle to the executable image section</param>
        /// <returns>The created process</returns>
        public static NtProcess CreateProcessEx(NtProcess ParentProcess, ProcessCreateFlags Flags, NtSection SectionHandle)
        {
            SafeKernelObjectHandle process;
            SafeHandle parent_process = ParentProcess != null ? ParentProcess.Handle : Current.Handle;
            SafeHandle section = SectionHandle != null ? SectionHandle.Handle : null;
            NtSystemCalls.NtCreateProcessEx(out process, ProcessAccessRights.MaximumAllowed,
                new ObjectAttributes(), parent_process, Flags, section, null, null, 0).ToNtException();
            return new NtProcess(process);
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="Flags">Creation flags</param>
        /// <param name="SectionHandle">Handle to the executable image section</param>
        /// <returns>The created process</returns>
        public NtProcess CreateProcessEx(ProcessCreateFlags Flags, NtSection SectionHandle)
        {
            return CreateProcessEx(this, Flags, SectionHandle);
        }

        /// <summary>
        /// Create a new process
        /// </summary>
        /// <param name="SectionHandle">Handle to the executable image section</param>
        /// <returns>The created process</returns>
        public static NtProcess CreateProcessEx(NtSection SectionHandle)
        {
            return CreateProcessEx(null, ProcessCreateFlags.None, SectionHandle);
        }

        /// <summary>
        /// Terminate the process
        /// </summary>
        /// <param name="exitcode">The exit code for the termination</param>
        public void Terminate(NtStatus exitcode)
        {
            NtSystemCalls.NtTerminateProcess(Handle, exitcode).ToNtException();
        }

        /// <summary>
        /// Get process image file path
        /// </summary>
        /// <param name="native">True to return the native image path, false for a Win32 style path</param>
        /// <returns>The process image file path</returns>
        public string GetImageFilePath(bool native)
        {
            ProcessInfoClass info_class = native ? ProcessInfoClass.ProcessImageFileName : ProcessInfoClass.ProcessImageFileNameWin32;
            int return_length = 0;
            NtStatus status = NtSystemCalls.NtQueryInformationProcess(Handle, info_class, SafeHGlobalBuffer.Null, 0, out return_length);
            if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                status.ToNtException();
            using (SafeStructureInOutBuffer<UnicodeStringOut> buf = new SafeStructureInOutBuffer<UnicodeStringOut>(return_length, false))
            {
                NtSystemCalls.NtQueryInformationProcess(Handle, info_class, buf, buf.Length, out return_length).ToNtException();
                return buf.Result.ToString();
            }
        }

        /// <summary>
        /// Get full image path name in native format
        /// </summary>
        public override string FullPath
        {
            get
            {
                try
                {
                    return GetImageFilePath(true);
                }
                catch (NtException)
                {
                    if (IsAccessGranted(ProcessAccessRights.QueryLimitedInformation))
                    {
                        return String.Format("process:{0}", ProcessId);
                    }
                    else
                    {
                        return String.Empty;
                    }
                }
            }
        }

        /// <summary>
        /// Get a mitigation policy raw value
        /// </summary>
        /// <param name="policy">The policy to get</param>
        /// <returns>The raw policy value</returns>
        public int GetProcessMitigationPolicy(ProcessMitigationPolicy policy)
        {
            switch (policy)
            {
                case ProcessMitigationPolicy.ProcessDEPPolicy:
                case ProcessMitigationPolicy.ProcessReserved1Policy:
                case ProcessMitigationPolicy.ProcessMitigationOptionsMask:
                    throw new ArgumentException("Invalid mitigation policy");
            }

            MitigationPolicy p = new MitigationPolicy();
            p.Policy = policy;

            using (var buffer = p.ToBuffer())
            {
                int return_length;
                NtStatus status = NtSystemCalls.NtQueryInformationProcess(Handle, ProcessInfoClass.ProcessMitigationPolicy, buffer, buffer.Length, out return_length);
                if (!status.IsSuccess())
                {
                    if (status != NtStatus.STATUS_INVALID_PARAMETER && status != NtStatus.STATUS_NOT_SUPPORTED)
                    {
                        status.ToNtException();
                    }
                    return 0;
                }
                return buffer.Result.Result;
            }
        }

        /// <summary>
        /// Disable dynamic code policy on another process.
        /// </summary>
        public void DisableDynamicCodePolicy()
        {
            if (!NtToken.EnableDebugPrivilege())
            {
                throw new InvalidOperationException("Must have Debug privilege to disable code policy");
            }

            MitigationPolicy p = new MitigationPolicy();
            p.Policy = ProcessMitigationPolicy.ProcessDynamicCodePolicy;

            using (var buffer = p.ToBuffer())
            {
                NtSystemCalls.NtSetInformationProcess(Handle, ProcessInfoClass.ProcessMitigationPolicy, buffer, buffer.Length).ToNtException();
            }
        }

        /// <summary>
        /// Suspend the entire process.
        /// </summary>
        public void Suspend()
        {
            NtSystemCalls.NtSuspendProcess(Handle).ToNtException();
        }

        /// <summary>
        /// Resume the entire process.
        /// </summary>
        public void Resume()
        {
            NtSystemCalls.NtResumeProcess(Handle).ToNtException();
        }

        /// <summary>
        /// Get process DEP status
        /// </summary>
        public ProcessDepStatus DepStatus
        {
            get
            {
                using (SafeStructureInOutBuffer<uint> buffer = new SafeStructureInOutBuffer<uint>())
                {
                    int return_length;
                    ProcessDepStatus ret = new ProcessDepStatus();
                    NtStatus status = NtSystemCalls.NtQueryInformationProcess(Handle, ProcessInfoClass.ProcessExecuteFlags, buffer, buffer.Length, out return_length);
                    if (!status.IsSuccess())
                    {
                        if (status != NtStatus.STATUS_INVALID_PARAMETER)
                        {
                            status.ToNtException();
                        }
                        return ret;
                    }

                    uint result = buffer.Result;
                    if ((result & 2) == 0)
                    {
                        ret.Enabled = true;
                        if ((result & 4) != 0)
                        {
                            ret.DisableAtlThunkEmulation = true;
                        }
                    }
                    if ((result & 8) != 0)
                    {
                        ret.Permanent = true;
                    }
                    return ret;
                }
            }
        }

        /// <summary>
        /// Open the process' token
        /// </summary>
        /// <returns></returns>
        public NtToken OpenToken()
        {
            return NtToken.OpenProcessToken(this, false);
        }

        /// <summary>
        /// Get the process user.
        /// </summary>
        public Sid User
        {
            get
            {
                using (NtToken token = OpenToken())
                {
                    return token.User.Sid;
                }
            }
        }

        /// <summary>
        /// Get process mitigations
        /// </summary>
        public NtProcessMitigations Mitigations
        {
            get
            {
                return new NtProcessMitigations(this);
            }
        }

        /// <summary>
        /// Open an actual handle to the current process rather than the pseudo one used for Current
        /// </summary>
        /// <returns>The process object</returns>
        public static NtProcess OpenCurrent()
        {
            return new NtProcess(Current.DuplicateHandle());
        }

        /// <summary>
        /// Get the current process.        
        /// </summary>
        /// <remarks>This only uses the pseudo handle, for the process. If you need a proper handle use OpenCurrent.</remarks>
        public static NtProcess Current { get { return new NtProcess(new SafeKernelObjectHandle(new IntPtr(-1), false)); } }

        /// <summary>
        /// Read memory from a process.
        /// </summary>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="length">The length to read.</param>
        /// <returns>The array of bytes read from the location. 
        /// If a read is short then returns fewer bytes than requested.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public byte[] ReadMemory(long base_address, int length)
        {
            return NtVirtualMemory.ReadMemory(Handle, base_address, length);
        }

        /// <summary>
        /// Write memory to a process.
        /// </summary>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="data">The data to write.</param>
        /// <returns>The number of bytes written to the location</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int WriteMemory(long base_address, byte[] data)
        {
            return NtVirtualMemory.WriteMemory(Handle, base_address, data);
        }

        /// <summary>
        /// Query memory information for a process.
        /// </summary>
        /// <param name="base_address">The base address.</param>
        /// <returns>The queries memory information.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public MemoryInformation QueryMemoryInformation(long base_address)
        {
            return NtVirtualMemory.QueryMemoryInformation(Handle, base_address);
        }

        /// <summary>
        /// Query all memory information regions in process memory.
        /// </summary>
        /// <returns>The list of memory regions.</returns>
        /// <param name="include_free_regions">True to include free regions of memory.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<MemoryInformation> QueryAllMemoryInformation(bool include_free_regions)
        {
            IEnumerable<MemoryInformation> mem_infos = NtVirtualMemory.QueryMemoryInformation(Handle);
            if (!include_free_regions)
            {
                return mem_infos.Where(m => m.State != MemoryState.Free);
            }
            return mem_infos;
        }

        /// <summary>
        /// Query all memory information regions in process memory excluding free regions.
        /// </summary>
        /// <returns>The list of memory regions.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<MemoryInformation> QueryAllMemoryInformation()
        {
            return QueryAllMemoryInformation(false);
        }

        /// <summary>
        /// Query a list of mapped images in a process.
        /// </summary>
        /// <returns>The list of mapped images</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<MappedFile> QueryMappedImages()
        {
            return QueryAllMappedFiles().Where(m => m.IsImage);
        }

        /// <summary>
        /// Query a list of mapped files in a process.
        /// </summary>
        /// <returns>The list of mapped images</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<MappedFile> QueryMappedFiles()
        {
            return QueryAllMappedFiles().Where(m => !m.IsImage);
        }

        /// <summary>
        /// Query a list of all mapped files and images in a process.
        /// </summary>
        /// <returns>The list of mapped images</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<MappedFile> QueryAllMappedFiles()
        {
            return NtVirtualMemory.QueryMappedFiles(Handle);
        }

        /// <summary>
        /// Allocate virtual memory in a process.
        /// </summary>
        /// <param name="base_address">Optional base address, if 0 will automatically select a base.</param>
        /// <param name="region_size">The region size to allocate.</param>
        /// <param name="allocation_type">The type of allocation.</param>
        /// <param name="protect">The allocation protection.</param>
        /// <returns>The address of the allocated region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public long AllocateMemory(long base_address,
            long region_size, MemoryAllocationType allocation_type, MemoryAllocationProtect protect)
        {
            return NtVirtualMemory.AllocateMemory(Handle, base_address, region_size, allocation_type, protect);
        }

        /// <summary>
        /// Free virtual emmory in a process.
        /// </summary>
        /// <param name="base_address">Base address of region to free</param>
        /// <param name="region_size">The size of the region.</param>
        /// <param name="free_type">The type to free.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void FreeMemory(long base_address, long region_size, MemoryFreeType free_type)
        {
            NtVirtualMemory.FreeMemory(Handle, base_address, region_size, free_type);
        }

        /// <summary>
        /// Change protection on a region of memory.
        /// </summary>
        /// <param name="base_address">The base address</param>
        /// <param name="region_size">The size of the memory region.</param>
        /// <param name="new_protect">The new protection type.</param>
        /// <returns>The old protection for the region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public MemoryAllocationProtect ProtectMemory(long base_address,
            long region_size, MemoryAllocationProtect new_protect)
        {
            return NtVirtualMemory.ProtectMemory(Handle, base_address, 
                region_size, new_protect);
        }

        /// <summary>
        /// Set the process device map.
        /// </summary>
        /// <param name="device_map">The device map directory to set.</param>
        public void SetProcessDeviceMap(NtDirectory device_map)
        {
            ProcessDeviceMapInformationSet device_map_set = new ProcessDeviceMapInformationSet();
            device_map_set.DirectoryHandle = device_map.Handle.DangerousGetHandle();
            using (var buffer = device_map_set.ToBuffer())
            {
                NtSystemCalls.NtSetInformationProcess(Handle, ProcessInfoClass.ProcessDeviceMap, buffer, buffer.Length);
            }
        }
    }
}
