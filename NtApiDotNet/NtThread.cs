//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
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
    }

    public enum ThreadInfoClass
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
        ThreadActualGroupAffinity = 41,
        MaxThreadInfoClass = 42,
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
            ThreadInfoClass ThreadInformationClass,
            IntPtr          ThreadInformation,
            int             ThreadInformationLength,
            out int         ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationThread(
            SafeKernelObjectHandle ThreadHandle,
            ThreadInfoClass ThreadInformationClass,
            IntPtr ThreadInformation,
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
    }

    public class NtThread : NtObjectWithDuplicate<NtThread, ThreadAccessRights>
    {
        private int? _tid;
        private int? _pid;

        internal NtThread(SafeKernelObjectHandle handle)
            : base(handle)
        {
        }        

        public int Resume()
        {
            int suspend_count;
            StatusToNtException(NtSystemCalls.NtResumeThread(Handle, out suspend_count));
            return suspend_count;
        }

        public int Suspend()
        {
            int suspend_count;
            StatusToNtException(NtSystemCalls.NtSuspendThread(Handle, out suspend_count));
            return suspend_count;
        }

        public void Terminate(NtStatus status)
        {
            StatusToNtException(NtSystemCalls.NtTerminateThread(Handle, status));
        }

        public void Terminate(int status)
        {
            Terminate((NtStatus)status);
        }

        public static NtThread Open(int thread_id, ThreadAccessRights access)
        {
            SafeKernelObjectHandle handle;
            StatusToNtException(NtSystemCalls.NtOpenThread(out handle, access, new ObjectAttributes(), new ClientId() { UniqueThread = new IntPtr(thread_id) }));
            return new NtThread(handle) { _tid = thread_id };       
        }

        public int GetThreadId()
        {
            if (_tid.HasValue)
                return _tid.Value;

            using (SafeStructureInOutBuffer<ThreadBasicInformation> basic_info = new SafeStructureInOutBuffer<ThreadBasicInformation>())
            {
                int return_length = 0;
                StatusToNtException(NtSystemCalls.NtQueryInformationThread(Handle, ThreadInfoClass.ThreadBasicInformation,
                  basic_info.DangerousGetHandle(), basic_info.Length, out return_length));
                _tid = basic_info.Result.ClientId.UniqueThread.ToInt32();
                return _tid.Value;
            }
        }

        public int GetProcessId()
        {
            if (_pid.HasValue)
                return _pid.Value;

            using (SafeStructureInOutBuffer<ThreadBasicInformation> basic_info = new SafeStructureInOutBuffer<ThreadBasicInformation>())
            {
                int return_length = 0;
                StatusToNtException(NtSystemCalls.NtQueryInformationThread(Handle, ThreadInfoClass.ThreadBasicInformation,
                  basic_info.DangerousGetHandle(), basic_info.Length, out return_length));
                _pid = basic_info.Result.ClientId.UniqueProcess.ToInt32();
                return _pid.Value;
            }
        }

        public void SetImpersonationToken(NtToken token)
        {
            IntPtr handle = token != null ? token.Handle.DangerousGetHandle() : IntPtr.Zero;
            using (var buf = handle.ToBuffer())
            {
                StatusToNtException(NtSystemCalls.NtSetInformationThread(Handle, ThreadInfoClass.ThreadImpersonationToken, 
                    buf.DangerousGetHandle(), buf.Length));
            }
        }

        public ThreadImpersonationContext ImpersonateAnonymousToken()
        {
            StatusToNtException(NtSystemCalls.NtImpersonateAnonymousToken(Handle));
            return new ThreadImpersonationContext(Duplicate());
        }

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

        public NtToken OpenToken()
        {
            return NtToken.OpenThreadToken(this);
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
            if (!NtObject.IsSuccess(status))
            {
                throw new NtException(status);                
            }

            return status == NtStatus.STATUS_ALERTED;
        }
    }    
}
