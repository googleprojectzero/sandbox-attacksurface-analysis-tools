﻿//  Copyright 2016 Google Inc. All Rights Reserved.
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
using NtApiDotNet.Win32;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum ThreadAccessRights : uint
    {
        [SDKName("THREAD_TERMINATE")]
        Terminate = 0x0001,
        [SDKName("THREAD_SUSPEND_RESUME")]
        SuspendResume = 0x0002,
        [SDKName("THREAD_ALERT")]
        Alert = 0x0004,
        [SDKName("THREAD_GET_CONTEXT")]
        GetContext = 0x0008,
        [SDKName("THREAD_SET_CONTEXT")]
        SetContext = 0x0010,
        [SDKName("THREAD_SET_INFORMATION")]
        SetInformation = 0x0020,
        [SDKName("THREAD_QUERY_INFORMATION")]
        QueryInformation = 0x0040,
        [SDKName("THREAD_SET_THREAD_TOKEN")]
        SetThreadToken = 0x0080,
        [SDKName("THREAD_IMPERSONATE")]
        Impersonate = 0x0100,
        [SDKName("THREAD_DIRECT_IMPERSONATION")]
        DirectImpersonation = 0x0200,
        [SDKName("THREAD_SET_LIMITED_INFORMATION")]
        SetLimitedInformation = 0x0400,
        [SDKName("THREAD_QUERY_LIMITED_INFORMATION")]
        QueryLimitedInformation = 0x0800,
        [SDKName("THREAD_RESUME")]
        Resume = 0x1000,
        AllAccess = 0x1FFFFF,
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

    public enum ThreadInformationClass
    {
        ThreadBasicInformation = 0,
        ThreadTimes = 1,
        ThreadPriority = 2,
        ThreadBasePriority = 3,
        ThreadAffinityMask = 4,
        ThreadImpersonationToken = 5,
        ThreadDescriptorTableEntry = 6,
        ThreadEnableAlignmentFaultFixup = 7,
        ThreadEventPair_Reusable = 8,
        ThreadQuerySetWin32StartAddress = 9,
        ThreadZeroTlsCell = 10,
        ThreadPerformanceCount = 11,
        ThreadAmILastThread = 12,
        ThreadIdealProcessor = 13,
        ThreadPriorityBoost = 14,
        ThreadSetTlsArrayAddress = 15,
        ThreadIsIoPending = 16,
        ThreadHideFromDebugger = 17,
        ThreadBreakOnTermination = 18,
        ThreadSwitchLegacyState = 19,
        ThreadIsTerminated = 20,
        ThreadLastSystemCall = 21,
        ThreadIoPriority = 22,
        ThreadCycleTime = 23,
        ThreadPagePriority = 24,
        ThreadActualBasePriority = 25,
        ThreadTebInformation = 26,
        ThreadCSwitchMon = 27,
        ThreadCSwitchPmu = 28,
        ThreadWow64Context = 29,
        ThreadGroupInformation = 30,
        ThreadUmsInformation = 31,
        ThreadCounterProfiling = 32,
        ThreadIdealProcessorEx = 33,
        ThreadCpuAccountingInformation = 34,
        ThreadSuspendCount = 35,
        ThreadHeterogeneousCpuPolicy = 36,
        ThreadContainerId = 37,
        ThreadNameInformation = 38,
        ThreadSelectedCpuSets = 39,
        ThreadSystemThreadInformation = 40,
        ThreadActualGroupAffinity = 41,
        ThreadDynamicCodePolicyInfo = 42,
        ThreadExplicitCaseSensitivity = 43,
        ThreadWorkOnBehalfTicket = 44,
        ThreadSubsystemInformation = 45,
        ThreadDbgkWerReportActive = 46,
        ThreadAttachContainer = 47,
        ThreadManageWritesToExecutableMemory = 48,
        ThreadPowerThrottlingState = 49,
        ThreadWorkloadClass = 50,
    }

    [StructLayout(LayoutKind.Sequential)]
    public class ThreadBasicInformation
    {
        public int ExitStatus;
        public IntPtr TebBaseAddress;
        public ClientIdStruct ClientId;
        public UIntPtr AffinityMask;
        public int Priority;
        public int BasePriority;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ThreadCycleTimeInformation
    {
        public long AccumulatedCycles;
        public long CurrentCycleCount;
    }

    [Flags]
    public enum WorkOnBehalfTicketFlags
    {
        None = 0,
        CurrentThread = 1,
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct RtlWorkOnBehalfTicket
    {
        [FieldOffset(0)]
        public uint ThreadId;
        [FieldOffset(4)]
        public uint ThreadCreationTimeLow;
        [FieldOffset(0)]
        public ulong WorkOnBehalfTicket;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RtlWorkOnBehalfTicketEx
    {
        public RtlWorkOnBehalfTicket Ticket;
        public WorkOnBehalfTicketFlags Flags;
        public int Reserved;
    }

    public class WorkOnBehalfTicket
    {
        public ulong Ticket { get; }
        public WorkOnBehalfTicketFlags Flags { get; }

        internal WorkOnBehalfTicket(RtlWorkOnBehalfTicketEx ticket)
            : this(ticket.Ticket.WorkOnBehalfTicket)
        {
            Flags = ticket.Flags;
        }

        public WorkOnBehalfTicket(ulong ticket)
        {
            Ticket = ticket;
        }

        public WorkOnBehalfTicket(int thread_id, long creation_time, ulong xor_key)
        {
            RtlWorkOnBehalfTicket ticket = new RtlWorkOnBehalfTicket() { ThreadId = (uint)thread_id,
                ThreadCreationTimeLow = (uint)(creation_time & 0xFFFFFFFF) };
            Ticket = ticket.WorkOnBehalfTicket ^ xor_key;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KernelUserTimes
    {
        public LargeIntegerStruct CreateTime;
        public LargeIntegerStruct ExitTime;
        public LargeIntegerStruct KernelTime;
        public LargeIntegerStruct UserTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct M128A
    {
        public ulong Low;
        public long High;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct X86_FLOATING_SAVE_AREA
    {
        public uint ControlWord;
        public uint StatusWord;
        public uint TagWord;
        public uint ErrorOffset;
        public uint ErrorSelector;
        public uint DataOffset;
        public uint DataSelector;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
        public byte[] RegisterArea;
        public uint Spare0;
    }

    public interface IContext
    {
        ContextFlags ContextFlags
        {
            get; set;
        }

        ulong InstructionPointer { get; }
    }

    [StructLayout(LayoutKind.Sequential)]
    public sealed class ContextX86 : IContext
    {
        //
        // The flags values within this flag control the contents of
        // a CONTEXT record.
        //
        // If the context record is used as an input parameter, then
        // for each portion of the context record controlled by a flag
        // whose value is set, it is assumed that that portion of the
        // context record contains valid context. If the context record
        // is being used to modify a threads context, then only that
        // portion of the threads context will be modified.
        //
        // If the context record is used as an IN OUT parameter to capture
        // the context of a thread, then only those portions of the thread's
        // context corresponding to set flags will be returned.
        //
        // The context record is never used as an OUT only parameter.
        //
        private ContextFlags _ContextFlags;

        public ContextFlags ContextFlags
        {
            get
            {
                return _ContextFlags & ~ContextFlags.X86;
            }
            set
            {
                _ContextFlags = value | ContextFlags.X86;
            }
        }

        public ulong InstructionPointer
        {
            get
            {
                return Eip;
            }
        }

        //
        // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
        // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
        // included in CONTEXT_FULL.
        //

        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
        //

        public X86_FLOATING_SAVE_AREA FloatSave;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_SEGMENTS.
        //

        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_INTEGER.
        //

        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_CONTROL.
        //

        public uint Ebp;
        public uint Eip;
        public uint SegCs;              // MUST BE SANITIZED
        public uint EFlags;             // MUST BE SANITIZED
        public uint Esp;
        public uint SegSs;

        //
        // This section is specified/returned if the ContextFlags word
        // contains the flag CONTEXT_EXTENDED_REGISTERS.
        // The format and contexts are processor specific
        //

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] ExtendedRegisters = new byte[512];

        public ContextX86()
        {
            FloatSave.RegisterArea = new byte[80];
        }
    }

    [Flags]
    public enum ContextFlags : uint
    {
        X86 = 0x00010000,
        Amd64 = 0x00100000,
        ARM = 0x00200000,
        ARM64 = 0x00400000,
        Control = 0x00000001,
        Integer = 0x00000002,
        Segments = 0x00000004,
        FloatingPoint = 0x00000008,
        DebugRegisters = 0x00000010,
        Full = Control | Integer | FloatingPoint,
        All = Control | Integer | Segments | FloatingPoint | DebugRegisters,
        XState = 0x00000040,
        ExceptionActive = 0x08000000,
        ServiceActive = 0x10000000,
        ExceptionRequest = 0x40000000,
        ExceptionReporting = 0x80000000,
    }

    [StructLayout(LayoutKind.Sequential)]
    public sealed class ContextAmd64 : IContext
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;

        //
        // Control flags.
        //

        private ContextFlags _ContextFlags;

        public ContextFlags ContextFlags
        {
            get => _ContextFlags & ~ContextFlags.Amd64;
            set => _ContextFlags = value | ContextFlags.Amd64;
        }

        public ulong InstructionPointer => Rip;

        public uint MxCsr;

        //
        // Segment Registers and processor flags.
        //

        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;

        //
        // Debug registers
        //

        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;

        //
        // Integer registers.
        //

        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;

        //
        // Program counter.
        //

        public ulong Rip;

        //
        // Floating point state.
        //

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public M128A[] Header = new M128A[2];
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public M128A[] Legacy = new M128A[8];
        public M128A Xmm0;
        public M128A Xmm1;
        public M128A Xmm2;
        public M128A Xmm3;
        public M128A Xmm4;
        public M128A Xmm5;
        public M128A Xmm6;
        public M128A Xmm7;
        public M128A Xmm8;
        public M128A Xmm9;
        public M128A Xmm10;
        public M128A Xmm11;
        public M128A Xmm12;
        public M128A Xmm13;
        public M128A Xmm14;
        public M128A Xmm15;

        //
        // Vector registers.
        //
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
        public M128A[] VectorRegister = new M128A[26];
        public ulong VectorControl;

        //
        // Special debug control registers.
        //

        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Arm64Neon128
    {
        public ulong Low;
        public long High;
    }

    [StructLayout(LayoutKind.Sequential)]
    public sealed class ContextARM64 : IContext
    {
        private ContextFlags _ContextFlags;
        public uint Cpsr;
        public ulong X0;
        public ulong X1;
        public ulong X2;
        public ulong X3;
        public ulong X4;
        public ulong X5;
        public ulong X6;
        public ulong X7;
        public ulong X8;
        public ulong X9;
        public ulong X10;
        public ulong X11;
        public ulong X12;
        public ulong X13;
        public ulong X14;
        public ulong X15;
        public ulong X16;
        public ulong X17;
        public ulong X18;
        public ulong X19;
        public ulong X20;
        public ulong X21;
        public ulong X22;
        public ulong X23;
        public ulong X24;
        public ulong X25;
        public ulong X26;
        public ulong X27;
        public ulong X28;
        public ulong Fp;
        public ulong Lr;
        public ulong Sp;
        public ulong Pc;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public Arm64Neon128[] V;
        public uint Fpcr;
        public uint Fpsr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public uint[] Bcr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public ulong[] Bvr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public uint[] Wcr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public ulong[] Wvr;

        public ContextFlags ContextFlags
        {
            get => _ContextFlags & ~ContextFlags.ARM64;
            set => _ContextFlags = value | ContextFlags.ARM64;
        }

        public ulong InstructionPointer => Pc;
    }

    [StructLayout(LayoutKind.Sequential)]
    public sealed class ContextARM : IContext
    {
        //
        // Control flags.
        //

        private ContextFlags _ContextFlags;

        //
        // Integer registers
        //

        public uint R0;
        public uint R1;
        public uint R2;
        public uint R3;
        public uint R4;
        public uint R5;
        public uint R6;
        public uint R7;
        public uint R8;
        public uint R9;
        public uint R10;
        public uint R11;
        public uint R12;

        //
        // Control Registers
        //

        public uint Sp;
        public uint Lr;
        public uint Pc;
        public uint Cpsr;

        //
        // Floating Point/NEON Registers
        //

        public uint Fpscr;
        public uint Padding;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public ulong[] D;

        // Debug registers
        //
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public uint[] Bvr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public uint[] Bcr;
        public uint Wvr;
        public uint Wcr;
        public uint Padding2_0;
        public uint Padding2_1;

        public ContextFlags ContextFlags
        {
            get => _ContextFlags & ~ContextFlags.ARM;
            set => _ContextFlags = value | ContextFlags.ARM;
        }

        public ulong InstructionPointer => Pc;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ThreadLastSystemCallInformation
    {
        public IntPtr FirstArgument;
        public ushort SystemCallNumber;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ThreadLastSystemCallExtendedInformation
    {
        public IntPtr FirstArgument;
        public ushort SystemCallNumber;
        public long TickCountSinceSystemCall;
    }

    public class ThreadLastSystemCall
    {
        public long FirstArgument { get; }
        public int SystemCallNumber { get; }
        public long TickCountSinceSystemCall { get; }

        internal ThreadLastSystemCall(ThreadLastSystemCallInformation info)
        {
            FirstArgument = info.FirstArgument.ToInt64();
            SystemCallNumber = info.SystemCallNumber;
        }

        internal ThreadLastSystemCall(ThreadLastSystemCallExtendedInformation info)
        {
            FirstArgument = info.FirstArgument.ToInt64();
            SystemCallNumber = info.SystemCallNumber;
            TickCountSinceSystemCall = info.TickCountSinceSystemCall;
        }
    }

    public interface ITeb
    {
        IntPtr GetStackBase();
        IntPtr GetStackLimit();
        IntPtr GetPeb();
        Win32Error GetLastWin32Error();
    }

    public struct PartialTeb : ITeb
    {
        public IntPtr ExceptionList;
        public IntPtr StackBase;
        public IntPtr StackLimit;
        public IntPtr SubSystemTib;
        public IntPtr FiberData;
        public uint Version;
        public IntPtr ArbitraryUserPointer;
        public IntPtr Self;
        public IntPtr EnvironmentPointer;
        public ClientIdStruct ClientId;
        public IntPtr ActiveRpcHandle;
        public IntPtr ThreadLocalStoragePointer;
        public IntPtr ProcessEnvironmentBlock;
        public Win32Error LastErrorValue;
        public int CountOfOwnedCriticalSections;
        public IntPtr CsrClientThread;
        public IntPtr Win32ThreadInfo;

        Win32Error ITeb.GetLastWin32Error()
        {
            return LastErrorValue;
        }

        IntPtr ITeb.GetPeb()
        {
            return ProcessEnvironmentBlock;
        }

        IntPtr ITeb.GetStackBase()
        {
            return StackBase;
        }

        IntPtr ITeb.GetStackLimit()
        {
            return StackLimit;
        }
    }

    public struct PartialTeb32 : ITeb
    {
        public int ExceptionList;
        public int StackBase;
        public int StackLimit;
        public int SubSystemTib;
        public int FiberData;
        public uint Version;
        public int ArbitraryUserPointer;
        public int Self;
        public int EnvironmentPointer;
        public ClientIdStruct ClientId;
        public int ActiveRpcHandle;
        public int ThreadLocalStoragePointer;
        public int ProcessEnvironmentBlock;
        public Win32Error LastErrorValue;
        public int CountOfOwnedCriticalSections;
        public int CsrClientThread;
        public int Win32ThreadInfo;

        Win32Error ITeb.GetLastWin32Error()
        {
            return LastErrorValue;
        }

        IntPtr ITeb.GetPeb()
        {
            return new IntPtr(ProcessEnvironmentBlock);
        }

        IntPtr ITeb.GetStackBase()
        {
            return new IntPtr(StackBase);
        }

        IntPtr ITeb.GetStackLimit()
        {
            return new IntPtr(StackLimit);
        }
    }

    /// <summary>
    /// Delegate for APC callbacks.
    /// </summary>
    /// <param name="NormalContext">Context parameter.</param>
    /// <param name="SystemArgument1">System argument 1.</param>
    /// <param name="SystemArgument2">System argument 2.</param>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void ApcCallback(IntPtr NormalContext, IntPtr SystemArgument1, IntPtr SystemArgument2);

    public class ThreadAlpcServerInformation
    {
        public bool ThreadBlocked { get; }
        public int ConnectedProcessId { get; }
        public string ConnectionPortName { get; }

        internal ThreadAlpcServerInformation(AlpcServerInformationOut info)
        {
            ThreadBlocked = info.ThreadBlocked != 0;
            ConnectedProcessId = info.ConnectedProcessId.ToInt32();
            ConnectionPortName = info.ConnectionPortName.ToString();
        }
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateThread(
            out SafeKernelObjectHandle ThreadHandle,
            ThreadAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            SafeKernelObjectHandle ProcessHandle,
            out ClientIdStruct ClientId,
            IntPtr ThreadContext,
            IntPtr InitialTeb,
            bool CreateSuspended
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateThreadEx(
            out SafeKernelObjectHandle ThreadHandle,
            ThreadAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            SafeKernelObjectHandle ProcessHandle,
            IntPtr StartRoutine,
            IntPtr Argument,
            ThreadCreateFlags CreateFlags,
            IntPtr ZeroBits,
            IntPtr StackSize,
            IntPtr MaximumStackSize,
            ProcessAttributeList AttributeList
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtResumeThread(SafeKernelObjectHandle ThreadHandle, out int PreviousSuspendCount);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSuspendThread(SafeKernelObjectHandle ThreadHandle, out int PreviousSuspendCount);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtTerminateThread(SafeKernelObjectHandle ThreadHandle, NtStatus status);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenThread(out SafeKernelObjectHandle ThreadHandle,
            ThreadAccessRights DesiredAccess, ObjectAttributes ObjectAttributes, ClientId ClientId);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationThread(
            SafeKernelObjectHandle ThreadHandle,
            ThreadInformationClass ThreadInformationClass,
            SafeBuffer ThreadInformation,
            int ThreadInformationLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationThread(
            SafeKernelObjectHandle ThreadHandle,
            ThreadInformationClass ThreadInformationClass,
            SafeBuffer ThreadInformation,
            int ThreadInformationLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtGetNextThread(
          SafeKernelObjectHandle ProcessHandle,
          SafeKernelObjectHandle ThreadHandle,
          ThreadAccessRights DesiredAccess,
          AttributeFlags HandleAttributes,
          int Flags,
          out SafeKernelObjectHandle NewThreadHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtImpersonateAnonymousToken(SafeKernelObjectHandle ThreadHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtImpersonateThread(
            SafeKernelObjectHandle ThreadHandle,
            SafeKernelObjectHandle ThreadToImpersonate,
            SecurityQualityOfService SecurityQualityOfService);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDelayExecution(bool Alertable, LargeInteger DelayInterval);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlertThread(SafeKernelObjectHandle ThreadHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlertThreadByThreadId(IntPtr ThreadId);


        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlertResumeThread(
                SafeKernelObjectHandle ThreadHandle,
                [Out] OptionalInt32 PreviousSuspendCount
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueueApcThread(
             SafeKernelObjectHandle ThreadHandle,
             IntPtr ApcRoutine,
             IntPtr ApcArgument1,
             IntPtr ApcArgument2,
             IntPtr ApcArgument3
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueueApcThreadEx(
            SafeKernelObjectHandle ThreadHandle,
            SafeKernelObjectHandle UserApcReserveHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueueApcThreadEx(
            SafeKernelObjectHandle ThreadHandle,
            IntPtr UserApcReserveHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtGetContextThread(
            SafeKernelObjectHandle ThreadHandle,
            SafeBuffer ThreadContext);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetContextThread(
            SafeKernelObjectHandle ThreadHandle,
            SafeBuffer ThreadContext);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtTestAlert();
    }
#pragma warning restore 1591
}
