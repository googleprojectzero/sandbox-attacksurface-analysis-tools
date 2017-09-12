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
    public enum ThreadAccessRights : uint
    {
        Terminate = 0x0001,
        SuspendResume = 0x0002,
        Alert = 0x0004,
        GetContext = 0x0008,
        SetContext = 0x0010,
        SetInformation = 0x0020,
        QueryInformation = 0x0040,
        SetThreadToken = 0x0080,
        Impersonate = 0x0100,
        DirectImpersonation = 0x0200,
        SetLimitedInformation = 0x0400,
        QueryLimitedInformation = 0x0800,
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
        ThreadSetTlsArrayAddress = 15,   // Obsolete
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
        ThreadCSwitchMon = 27,   // Obsolete
        ThreadCSwitchPmu = 28,
        ThreadWow64Context = 29,
        ThreadGroupInformation = 30,
        ThreadUmsInformation = 31,   // UMS
        ThreadCounterProfiling = 32,
        ThreadIdealProcessorEx = 33,
        ThreadCpuAccountingInformation = 34,
        ThreadSuspendCount = 35,
        ThreadDescription = 38,
        ThreadActualGroupAffinity = 41,
        ThreadDynamicCodePolicy = 42,
    }

    [StructLayout(LayoutKind.Sequential)]
    public class ThreadBasicInformation
    {
        public NtStatus ExitStatus;
        public IntPtr TebBaseAddress;        
        public ClientIdStruct ClientId;
        public IntPtr AffinityMask;
        public int Priority;
        public int BasePriority;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct M128A
    {
        public ulong Low;
        public long  High;
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
    public class ContextX86 : IContext
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
        Control = 0x00000001,
        Integer =  0x00000002,
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
    public class ContextAmd64 : IContext {
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
            get
            {
                return _ContextFlags & ~ContextFlags.Amd64;
            }
            set
            {
                _ContextFlags = value | ContextFlags.Amd64;
            }
        }

        public ulong InstructionPointer
        {
            get
            {
                return Rip;
            }
        }

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

    public static partial class NtSystemCalls
    {
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
            SafeBuffer          ThreadInformation,
            int             ThreadInformationLength,
            out int         ReturnLength
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
        public static extern NtStatus NtGetContextThread(
            SafeKernelObjectHandle ThreadHandle,
            SafeBuffer ThreadContext);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetContextThread(
            SafeKernelObjectHandle ThreadHandle,
            SafeBuffer ThreadContext);
    }
#pragma warning restore 1591

    /// <summary>
    /// Class to represent a NT Thread object
    /// </summary>
    [NtType("Thread")]
    public class NtThread : NtObjectWithDuplicate<NtThread, ThreadAccessRights>
    {
        private int? _tid;
        private int? _pid;
        private string _process_name;

        internal NtThread(SafeKernelObjectHandle handle)
            : base(handle)
        {
        }

        /// <summary>
        /// Resume the thread.
        /// </summary>
        /// <returns>The suspend count</returns>
        public int Resume()
        {
            int suspend_count;
            NtSystemCalls.NtResumeThread(Handle, out suspend_count).ToNtException();
            return suspend_count;
        }

        /// <summary>
        /// Suspend the thread
        /// </summary>
        /// <returns>The suspend count</returns>
        public int Suspend()
        {
            int suspend_count;
            NtSystemCalls.NtSuspendThread(Handle, out suspend_count).ToNtException();
            return suspend_count;
        }

        /// <summary>
        /// Terminate the thread
        /// </summary>
        /// <param name="status">The thread status exit code</param>
        public void Terminate(NtStatus status)
        {
            NtSystemCalls.NtTerminateThread(Handle, status).ToNtException();
        }

        /// <summary>
        /// Open a thread
        /// </summary>
        /// <param name="thread_id">The thread ID to open</param>
        /// <param name="desired_access">The desired access for the handle</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtThread> Open(int thread_id, ThreadAccessRights desired_access, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            return NtSystemCalls.NtOpenThread(out handle, desired_access, new ObjectAttributes(), 
                new ClientId() { UniqueThread = new IntPtr(thread_id) }).CreateResult(throw_on_error, () => new NtThread(handle) { _tid = thread_id });
        }

        private static NtResult<NtThread> Open(NtThreadInformation thread_info, ThreadAccessRights desired_access, bool throw_on_error)
        {
            var result = Open(thread_info.ThreadId, desired_access, throw_on_error);
            if (result.IsSuccess)
            {
                result.Result._process_name = thread_info.ProcessName;
            }
            return result;
        }

        /// <summary>
        /// Open a thread
        /// </summary>
        /// <param name="thread_id">The thread ID to open</param>
        /// <param name="desired_access">The desired access for the handle</param>
        /// <returns>The opened object</returns>
        public static NtThread Open(int thread_id, ThreadAccessRights desired_access)
        {
            return Open(thread_id, desired_access, true).Result;
        }

        private SafeStructureInOutBuffer<T> QueryBuffer<T>(ThreadInformationClass info_class) where T : new()
        {
            SafeStructureInOutBuffer<T> info = new SafeStructureInOutBuffer<T>();
            try
            {
                int return_length = 0;
                NtStatus status = NtSystemCalls.NtQueryInformationThread(Handle, info_class,
                  info, info.Length, out return_length);
                if (status == NtStatus.STATUS_INFO_LENGTH_MISMATCH || status == NtStatus.STATUS_BUFFER_TOO_SMALL)
                {
                    using (SafeBuffer to_close = info)
                    {
                        info = new SafeStructureInOutBuffer<T>(return_length, false);
                    }
                    status = NtSystemCalls.NtQueryInformationThread(Handle, info_class,
                                            info, info.Length, out return_length);
                }

                status.ToNtException();
                return info;
            }
            catch
            {
                info.Close();
                throw;
            }
        }

        private T Query<T>(ThreadInformationClass info_class) where T : new()
        {
            using (SafeStructureInOutBuffer<T> info = QueryBuffer<T>(info_class))
            {
                return info.Result;
            }
        }

        private void Set<T>(ThreadInformationClass info_class, T value) where T : new()
        {
            using (var buffer = value.ToBuffer())
            {
                NtSystemCalls.NtSetInformationThread(Handle, info_class, buffer, buffer.Length);
            }
        }

        private ThreadBasicInformation QueryBasicInformation()
        {
            return Query<ThreadBasicInformation>(ThreadInformationClass.ThreadBasicInformation);
        }

        /// <summary>
        /// Get thread ID
        /// </summary>
        public int ThreadId
        {
            get
            {
                if (!_tid.HasValue)
                {
                    _tid = QueryBasicInformation().ClientId.UniqueThread.ToInt32();
                }
                return _tid.Value;
            }
        }

        /// <summary>
        /// Get process ID
        /// </summary>
        public int ProcessId
        {
            get
            {
                if (!_pid.HasValue)
                {
                    _pid = QueryBasicInformation().ClientId.UniqueProcess.ToInt32();
                }
                return _pid.Value;
            }
        }

        /// <summary>
        /// Get name of process.
        /// </summary>
        public string ProcessName
        {
            get
            {
                if (_process_name == null)
                {
                    using (var proc = NtProcess.Open(ProcessId, ProcessAccessRights.QueryLimitedInformation, false))
                    {
                        if (proc.IsSuccess)
                        {
                            _process_name = proc.Result.Name;
                        }
                        else
                        {
                            _process_name = String.Empty;
                        }
                    }
                }
                return _process_name;
            }
        }

        /// <summary>
        /// Get thread's current priority
        /// </summary>
        public int Priority
        {
            get
            {
                return QueryBasicInformation().Priority;
            }
        }

        /// <summary>
        /// Get thread's base priority
        /// </summary>
        public int BasePriority
        {
            get
            {
                return QueryBasicInformation().BasePriority;
            }
        }

        /// <summary>
        /// Get the thread's TEB base address.
        /// </summary>
        public IntPtr TebBaseAddress
        {
            get
            {
                return QueryBasicInformation().TebBaseAddress;
            }
        }

        /// <summary>
        /// Get whether thread is allowed to create dynamic code.
        /// </summary>
        public bool AllowDynamicCode
        {
            get
            {
                return Query<int>(ThreadInformationClass.ThreadDynamicCodePolicy) != 0;
            }
        }

        /// <summary>
        /// Get whether thread is impersonating another token.
        /// </summary>
        /// <remarks>Note that this tries to open the thread's token and return true if it could open. There a return of false
        /// might just indicate that the caller doesn't have permission to open the token, not that it's not impersonating.</remarks>
        public bool Impersonating
        {
            get { try { using (var token = OpenToken()) { return token != null; } } catch { return false; } }
        }

        /// <summary>
        /// Wake the thread from an alertable state.
        /// </summary>
        public void Alert()
        {
            NtSystemCalls.NtAlertThread(Handle).ToNtException();
        }

        /// <summary>
        /// Wake the thread from an alertable state and resume the thread.
        /// </summary>
        /// <returns>The previous suspend count for the thread.</returns>
        public int AlertResume()
        {
            OptionalInt32 suspend_count = new OptionalInt32();
            NtSystemCalls.NtAlertResumeThread(Handle, suspend_count).ToNtException();
            return suspend_count.Value;
        }

        /// <summary>
        /// Hide the thread from debug events.
        /// </summary>
        public void HideFromDebugger()
        {
            NtSystemCalls.NtSetInformationThread(Handle, ThreadInformationClass.ThreadHideFromDebugger, SafeHGlobalBuffer.Null, 0).ToNtException();
        }

        /// <summary>
        /// The set the thread's impersonation token
        /// </summary>
        /// <param name="token">The impersonation token to set</param>
        public void SetImpersonationToken(NtToken token)
        {
            IntPtr handle = token != null ? token.Handle.DangerousGetHandle() : IntPtr.Zero;
            using (var buf = handle.ToBuffer())
            {
                NtSystemCalls.NtSetInformationThread(Handle, ThreadInformationClass.ThreadImpersonationToken, 
                    buf, buf.Length).ToNtException();
            }
        }

        /// <summary>
        /// Impersonate the anonymous token
        /// </summary>
        /// <returns>The impersonation context. Dispose to revert to self</returns>
        public ThreadImpersonationContext ImpersonateAnonymousToken()
        {
            NtSystemCalls.NtImpersonateAnonymousToken(Handle).ToNtException();
            return new ThreadImpersonationContext(Duplicate());
        }

        /// <summary>
        /// Impersonate a token
        /// </summary>
        /// <returns>The impersonation context. Dispose to revert to self</returns>
        public ThreadImpersonationContext Impersonate(NtToken token)
        {
            SetImpersonationToken(token);
            return new ThreadImpersonationContext(Duplicate());
        }

        /// <summary>
        /// Impersonate another thread.
        /// </summary>
        /// <param name="thread">The thread to impersonate.</param>
        /// <param name="impersonation_level">The impersonation level</param>
        /// <returns>The imperonsation context. Dispose to revert to self.</returns>
        public ThreadImpersonationContext ImpersonateThread(NtThread thread, SecurityImpersonationLevel impersonation_level)
        {
            NtSystemCalls.NtImpersonateThread(Handle, thread.Handle, 
                new SecurityQualityOfService(impersonation_level, SecurityContextTrackingMode.Static, false)).ToNtException();
            return new ThreadImpersonationContext(Duplicate());
        }

        /// <summary>
        /// Impersonate another thread.
        /// </summary>
        /// <param name="thread">The thread to impersonate.</param>
        /// <returns>The imperonsation context. Dispose to revert to self.</returns>
        public ThreadImpersonationContext ImpersonateThread(NtThread thread)
        {
            return ImpersonateThread(thread, SecurityImpersonationLevel.Impersonation);
        }

        /// <summary>
        /// Open an actual handle to the current thread rather than the pseudo one used for Current
        /// </summary>
        /// <returns>The thread object</returns>
        public static NtThread OpenCurrent()
        {
            return NtThread.Current.Duplicate();
        }

        /// <summary>
        /// Open the thread's token
        /// </summary>
        /// <returns>The token, null if no token available</returns>
        public NtToken OpenToken()
        {
            return NtToken.OpenThreadToken(this);
        }

        /// <summary>
        /// Queue a user APC to the thread.
        /// </summary>
        /// <param name="apc_routine">The APC callback pointer.</param>
        /// <param name="arg1">Argument 0</param>
        /// <param name="arg2">Argument 1</param>
        /// <param name="arg3">Argument 2</param>
        public void QueueUserApc(IntPtr apc_routine, IntPtr arg1, IntPtr arg2, IntPtr arg3)
        {
            NtSystemCalls.NtQueueApcThread(Handle, apc_routine, arg1, arg2, arg3).ToNtException();
        }

        /// <summary>
        /// Get name of the thread.
        /// </summary>
        public override string FullPath
        {
            get
            {
                try
                {
                    return string.Format("thread:{0} - process:{1}", ThreadId, ProcessId);
                }
                catch
                {
                    return "Unknown";
                }
            }
        }

        /// <summary>
        /// Get or set a thread's description.
        /// </summary>
        public string Description
        {
            get
            {
                try
                {
                    using (var buffer = QueryBuffer<UnicodeStringOut>(ThreadInformationClass.ThreadDescription))
                    {
                        return buffer.Result.ToString();
                    }
                }
                catch
                {
                    return String.Empty;
                }
            }

            set
            {
                Set(ThreadInformationClass.ThreadDescription, new UnicodeString(value));
            }
        }
        
        /// <summary>
        /// Gets all accessible threads on the system.
        /// </summary>
        /// <param name="desired_access">The desired access for each thread.</param>
        /// <param name="from_system_info">Get the thread list from system information.</param>
        /// <returns>The list of accessible threads.</returns>
        public static IEnumerable<NtThread> GetThreads(ThreadAccessRights desired_access, bool from_system_info)
        {
            if (from_system_info)
            {
                return NtSystemInfo.GetProcessInformation().SelectMany(p => p.Threads)
                    .Select(t => Open(t, desired_access, false)).SelectValidResults();
            }
            else
            {
                using (var threads = new DisposableList<NtThread>())
                {
                    using (var procs = NtProcess.GetProcesses(ProcessAccessRights.QueryInformation).ToDisposableList())
                    {
                        foreach (var proc in procs)
                        {
                            threads.AddRange(proc.GetThreads(desired_access));
                        }
                    }
                    return threads.ToArrayAndClear();
                }
            }
        }

        /// <summary>
        /// Gets all accessible threads on the system.
        /// </summary>
        /// <param name="desired_access">The desired access for each thread.</param>
        /// <returns>The list of accessible threads.</returns>
        public static IEnumerable<NtThread> GetThreads(ThreadAccessRights desired_access)
        {
            return GetThreads(desired_access, false);
        }

        /// <summary>
        /// Get first thread for process.
        /// </summary>
        /// <param name="process">The process handle to get the threads.</param>
        /// <param name="desired_access">The desired access for the thread.</param>
        /// <returns>The first thread, or null if no more available.</returns>
        public static NtThread GetFirstThread(NtProcess process, ThreadAccessRights desired_access)
        {
            SafeKernelObjectHandle new_handle;
            NtStatus status = NtSystemCalls.NtGetNextThread(
                process.Handle, SafeKernelObjectHandle.Null, desired_access,
                AttributeFlags.None, 0, out new_handle);
            if (status == NtStatus.STATUS_SUCCESS)
            {
                return new NtThread(new_handle);
            }
            return null;
        }

        /// <summary>
        /// Get next thread for process relative to current thread.
        /// </summary>
        /// <param name="process">The process handle to get the threads.</param>
        /// <param name="desired_access">The desired access for the thread.</param>
        /// <returns>The next thread, or null if no more available.</returns>
        public NtThread GetNextThread(NtProcess process, ThreadAccessRights desired_access)
        {
            SafeKernelObjectHandle new_handle;
            NtStatus status = NtSystemCalls.NtGetNextThread(
                process.Handle, Handle, desired_access,
                AttributeFlags.None, 0, out new_handle);
            if (status == NtStatus.STATUS_SUCCESS)
            {
                return new NtThread(new_handle);
            }
            return null;
        }

        private IContext GetX86Context(ContextFlags flags)
        {
            var context = new ContextX86();
            context.ContextFlags = flags;

            using (var buffer = context.ToBuffer())
            {
                NtSystemCalls.NtGetContextThread(Handle, buffer).ToNtException();
                return buffer.Result;
            }
        }

        private IContext GetAmd64Context(ContextFlags flags)
        {
            var context = new ContextAmd64();
            context.ContextFlags = flags;

            // Buffer needs to be 16 bytes aligned, so allocate some extract space in case.
            using (var buffer = new SafeHGlobalBuffer(Marshal.SizeOf(context) + 16))
            {
                int write_ofs = 0;
                long ptr = buffer.DangerousGetHandle().ToInt64();
                // Almost certainly 8 byte aligned, but just in case.
                if ((ptr & 0xF) != 0)
                {
                    write_ofs = (int)(0x10 - (ptr & 0xF));
                }

                Marshal.StructureToPtr(context, buffer.DangerousGetHandle() + write_ofs, false);
                var sbuffer = buffer.GetStructAtOffset<ContextAmd64>(write_ofs);
                NtSystemCalls.NtGetContextThread(Handle, sbuffer).ToNtException();
                return sbuffer.Result;
            }
        }

        /// <summary>
        /// Get the thread context.
        /// </summary>
        /// <param name="flags">Flags for context parts to get.</param>
        /// <returns>An instance of an IContext object. Needs to be cast to correct type to access.</returns>
        public IContext GetContext(ContextFlags flags)
        {
            // Really needs to support ARM as well.
            if (Environment.Is64BitProcess)
            {
                return GetAmd64Context(flags);
            }
            else
            {
                return GetX86Context(flags);
            }
        }

        /// <summary>
        /// Get the current thread.        
        /// </summary>
        /// <remarks>This only uses the pseudo handle, for the thread. You can't use it in different threads. If you need to do that use OpenCurrent.</remarks>
        /// <see cref="OpenCurrent"/>
        public static NtThread Current { get { return new NtThread(new SafeKernelObjectHandle(new IntPtr(-2), false)); } }

        /// <summary>
        /// Sleep the current thread
        /// </summary>
        /// <param name="alertable">Set if the thread should be alertable</param>
        /// <param name="delay">The delay, negative values indicate relative times.</param>
        /// <returns>True if the thread was alerted before the delay expired.</returns>
        public static bool Sleep(bool alertable, long delay)
        {
            NtStatus status = NtSystemCalls.NtDelayExecution(alertable, new LargeInteger(delay));
            if (!status.IsSuccess())
            {
                throw new NtException(status);                
            }

            return status == NtStatus.STATUS_ALERTED;
        }
    }    
}
