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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum ThreadAccessRights : uint
    {        
        DirectImpersonation = 0x0200,
        GetContext = 0x0008,
        Impersonate = 0x0100,
        QueryInformation = 0x0040,
        QueryLimitedInformation = 0x0800,        
        SetContext = 0x0010,
        SetInformation = 0x0020,
        SetLimitedInformation = 0x0400,         
        SetThreadToken = 0x0080,
        SuspendResume = 0x0002,
        Terminate = 0x0001,
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
        public static extern NtStatus NtDelayExecution(bool Alertable, LargeInteger DelayInterval);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlertThread(SafeKernelObjectHandle ThreadHandle);
    }
#pragma warning restore 1591

    /// <summary>
    /// Class to represent a NT Thread object
    /// </summary>
    public class NtThread : NtObjectWithDuplicate<NtThread, ThreadAccessRights>
    {
        private int? _tid;
        private int? _pid;

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
        /// <returns>The opened object</returns>
        public static NtThread Open(int thread_id, ThreadAccessRights desired_access)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtOpenThread(out handle, desired_access, new ObjectAttributes(), new ClientId() { UniqueThread = new IntPtr(thread_id) }).ToNtException();
            return new NtThread(handle) { _tid = thread_id };       
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
        /// Open an actual handle to the current thread rather than the pseudo one used for Current
        /// </summary>
        /// <returns>The thread object</returns>
        public static NtThread OpenCurrent()
        {
            return new NtThread(Current.DuplicateHandle());
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
                using (var buffer = QueryBuffer<UnicodeStringOut>(ThreadInformationClass.ThreadDescription))
                {
                    return buffer.Result.ToString();
                }
            }

            set
            {
                Set(ThreadInformationClass.ThreadDescription, new UnicodeString(value));
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct THREADENTRY32
        {
            public int dwSize;
            public int cntUsage;
            public int th32ThreadID;
            public int th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public int dwFlags;
        }
        
        const int TH32CS_SNAPTHREAD = 0x4;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeKernelObjectHandle CreateToolhelp32Snapshot(int dwFlags, int th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Thread32First(SafeKernelObjectHandle snapshot, ref THREADENTRY32 entry);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Thread32Next(SafeKernelObjectHandle snapshot, ref THREADENTRY32 entry);
        
        /// <summary>
        /// Gets all accessible threads on the system.
        /// </summary>
        /// <param name="desired_access">The desired access for each thread.</param>
        /// <returns>The list of accessible threads.</returns>
        public static IEnumerable<NtThread> GetThreads(ThreadAccessRights desired_access)
        {
            using (SafeKernelObjectHandle thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0))
            {
                if (thread_snap.IsInvalid)
                {
                    return new NtThread[0];
                }

                List<NtThread> threads = new List<NtThread>();
                THREADENTRY32 thread_entry = new THREADENTRY32();
                thread_entry.dwSize = Marshal.SizeOf(thread_entry);

                if (Thread32First(thread_snap, ref thread_entry))
                {
                    do
                    {
                        try
                        {
                            NtThread thread = NtThread.Open(thread_entry.th32ThreadID, desired_access);
                            thread._pid = thread_entry.th32OwnerProcessID;
                            threads.Add(thread);
                        }
                        catch (NtException)
                        {
                        }
                    } while (Thread32Next(thread_snap, ref thread_entry));
                }

                return threads.ToArray();
            }
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
