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
    /// <summary>
    /// Class to represent a NT Thread object
    /// </summary>
    [NtType("Thread")]
    public class NtThread : NtObjectWithDuplicateAndInfo<NtThread, ThreadAccessRights, ThreadInformationClass, ThreadInformationClass>
    {
        #region Private Members
        private int? _tid;
        private int? _pid;
        private string _process_name;

        private static NtResult<NtThread> Open(NtThreadInformation thread_info, ThreadAccessRights desired_access, bool throw_on_error)
        {
            var result = Open(thread_info.ThreadId, desired_access, throw_on_error);
            if (result.IsSuccess)
            {
                result.Result._process_name = thread_info.ProcessName;
            }
            return result;
        }

        private ThreadBasicInformation QueryBasicInformation()
        {
            return QueryBasicInformation(true).Result;
        }

        private NtResult<ThreadBasicInformation> QueryBasicInformation(bool throw_on_error)
        {
            return Query(ThreadInformationClass.ThreadBasicInformation, new ThreadBasicInformation(), throw_on_error);
        }

        private NtResult<IContext> GetContext32<T>(ContextFlags flags, bool throw_on_error) where T : IContext, new()
        {
            var context = new T
            {
                ContextFlags = flags
            };

            using (var buffer = context.ToBuffer())
            {
                return NtSystemCalls.NtGetContextThread(Handle, buffer).CreateResult(throw_on_error, () => buffer.Result).Cast<IContext>();
            }
        }

        private NtResult<IContext> GetContext64<T>(ContextFlags flags, bool throw_on_error) where T : IContext, new()
        {
            var context = new T
            {
                ContextFlags = flags
            };

            // Buffer needs to be 16 bytes aligned, so allocate some extract space in case.
            using (var buffer = new SafeHGlobalBuffer(Marshal.SizeOf(context) + 16))
            {
                int write_ofs = 0;
                long ptr = buffer.DangerousGetHandle().ToInt64();
                // Almost certainly 16 byte aligned, but just in case.
                if ((ptr & 0xF) != 0)
                {
                    write_ofs = (int)(0x10 - (ptr & 0xF));
                }

                Marshal.StructureToPtr(context, buffer.DangerousGetHandle() + write_ofs, false);
                var sbuffer = buffer.GetStructAtOffset<T>(write_ofs);
                return NtSystemCalls.NtGetContextThread(Handle, sbuffer).CreateResult(throw_on_error, () => sbuffer.Result).Cast<IContext>();
            }
        }

        private NtStatus SetX86Context(IContext context, bool throw_on_error)
        {
            if (context is ContextX86 x86_context)
            {
                using (var buffer = x86_context.ToBuffer())
                {
                    return NtSystemCalls.NtSetContextThread(Handle, buffer).ToNtException(throw_on_error);
                }
            }
            throw new ArgumentException("Must specify a ContextX86 instance for a x86 process.");
        }

        private NtStatus SetAmd64Context(IContext context, bool throw_on_error)
        {
            if (context is ContextAmd64 amd64_context)
            {
                using (var buffer = amd64_context.ToBuffer())
                {
                    return NtSystemCalls.NtSetContextThread(Handle, buffer).ToNtException(throw_on_error);
                }
            }
            throw new ArgumentException("Must specify a ContextAmd64 instance for a x64 process.");
        }

        private NtStatus SetARMContext(IContext context, bool throw_on_error)
        {
            if (context is ContextARM arm_context)
            {
                using (var buffer = arm_context.ToBuffer())
                {
                    return NtSystemCalls.NtSetContextThread(Handle, buffer).ToNtException(throw_on_error);
                }
            }
            throw new ArgumentException("Must specify a ContextARM instance for an ARM process.");
        }

        private NtStatus SetARM64Context(IContext context, bool throw_on_error)
        {
            if (context is ContextARM64 arm_context)
            {
                using (var buffer = arm_context.ToBuffer())
                {
                    return NtSystemCalls.NtSetContextThread(Handle, buffer).ToNtException(throw_on_error);
                }
            }
            throw new ArgumentException("Must specify a ContextARM instance for an ARM64 process.");
        }

        private static NtResult<WorkOnBehalfTicket> GetTicket(int thread_id, bool throw_on_error)
        {
            var xor_key = GetWorkOnBehalfTicketXor(throw_on_error);
            if (!xor_key.IsSuccess)
                return xor_key.Cast<WorkOnBehalfTicket>();

            var create_time = GetThreadCreateTime(thread_id, throw_on_error);
            if (!create_time.IsSuccess)
                return create_time.Cast<WorkOnBehalfTicket>();

            return new WorkOnBehalfTicket(thread_id, create_time.Result, xor_key.Result).CreateResult();
        }

        private static NtResult<long> GetThreadCreateTime(int thread_id, bool throw_on_error)
        {
            using (var thread = Open(thread_id, ThreadAccessRights.QueryLimitedInformation, false))
            {
                if (thread.IsSuccess)
                {
                    var times = thread.Result.Query<KernelUserTimes>(ThreadInformationClass.ThreadTimes, default, false);
                    if (times.IsSuccess)
                    {
                        return times.Result.CreateTime.QuadPart.CreateResult();
                    }
                }
            }

            var threads = NtSystemInfo.GetThreadInformationExtended(throw_on_error);
            if (!threads.IsSuccess)
            {
                return threads.Cast<long>();
            }
            var th = threads.Result.FirstOrDefault(t => t.ThreadId == thread_id);
            if (th == null)
            {
                return NtStatus.STATUS_NOT_FOUND.CreateResultFromError<long>(throw_on_error);
            }
            return th.CreateTime.CreateResult();
        }

        #endregion

        #region Constructors
        internal NtThread(SafeKernelObjectHandle handle)
            : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(false, MandatoryLabelPolicy.NoWriteUp | MandatoryLabelPolicy.NoReadUp)
            {
            }
        }
        #endregion

        #region Static Methods

        /// <summary>
        /// Create a new thread in a process.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the thread object.</param>
        /// <param name="desired_acccess">Desired access for the handle.</param>
        /// <param name="process">Process to create the thread in.</param>
        /// <param name="start_routine">Address of the start routine.</param>
        /// <param name="argument">Argument to pass to the thread.</param>
        /// <param name="create_flags">Creation flags.</param>
        /// <param name="zero_bits">Zero bits for the stack address.</param>
        /// <param name="stack_size">Size of the committed stack.</param>
        /// <param name="maximum_stack_size">Maximum reserved stack size.</param>
        /// <param name="attribute_list">Optional attribute list.</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The created thread object.</returns>
        /// <remarks>This creates a native thread, not a Win32 thread. This might cause unexpected things to fail as they're not initialized.</remarks>
        public static NtResult<NtThread> Create(
            ObjectAttributes object_attributes,
            ThreadAccessRights desired_acccess,
            NtProcess process,
            long start_routine,
            long argument,
            ThreadCreateFlags create_flags,
            long zero_bits,
            long stack_size,
            long maximum_stack_size,
            IEnumerable<ProcessAttribute> attribute_list,
            bool throw_on_error)
        {
            using (ProcessAttributeList attr_list = ProcessAttributeList.Create(attribute_list))
            {
                return NtSystemCalls.NtCreateThreadEx(out SafeKernelObjectHandle handle, desired_acccess, object_attributes, process.Handle, new IntPtr(start_routine), new IntPtr(argument),
                    create_flags, new IntPtr(zero_bits), new IntPtr(stack_size), new IntPtr(maximum_stack_size), attr_list).CreateResult(throw_on_error, () => new NtThread(handle));
            }
        }

        /// <summary>
        /// Create a new thread in a process.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the thread object.</param>
        /// <param name="desired_acccess">Desired access for the handle.</param>
        /// <param name="process">Process to create the thread in.</param>
        /// <param name="start_routine">Address of the start routine.</param>
        /// <param name="argument">Argument to pass to the thread.</param>
        /// <param name="create_flags">Creation flags.</param>
        /// <param name="zero_bits">Zero bits for the stack address.</param>
        /// <param name="stack_size">Size of the committed stack.</param>
        /// <param name="maximum_stack_size">Maximum reserved stack size.</param>
        /// <param name="attribute_list">Optional attribute list.</param>
        /// <returns>The created thread object.</returns>
        /// <remarks>This creates a native thread, not a Win32 thread. This might cause unexpected things to fail as they're not initialized.</remarks>
        public static NtThread Create(
            ObjectAttributes object_attributes,
            ThreadAccessRights desired_acccess,
            NtProcess process,
            long start_routine,
            long argument,
            ThreadCreateFlags create_flags,
            long zero_bits,
            long stack_size,
            long maximum_stack_size,
            IEnumerable<ProcessAttribute> attribute_list)
        {
            return Create(object_attributes, desired_acccess, process, start_routine, argument, create_flags,
                zero_bits, stack_size, maximum_stack_size, attribute_list, true).Result;
        }

        /// <summary>
        /// Create a new thread in a process.
        /// </summary>
        /// <param name="process">Process to create the thread in.</param>
        /// <param name="start_routine">Address of the start routine.</param>
        /// <param name="argument">Argument to pass to the thread.</param>
        /// <param name="create_flags">Creation flags.</param>
        /// <param name="stack_size">Size of the committed stack.</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The created thread object.</returns>
        /// <remarks>This creates a native thread, not a Win32 thread. This might cause unexpected things to fail as they're not initialized.</remarks>
        public static NtResult<NtThread> Create(
            NtProcess process,
            long start_routine,
            long argument,
            ThreadCreateFlags create_flags,
            long stack_size,
            bool throw_on_error)
        {
            return Create(null, ThreadAccessRights.MaximumAllowed, process, start_routine, argument, create_flags, 0, stack_size, 0, null, throw_on_error);
        }

        /// <summary>
        /// Create a new thread in a process.
        /// </summary>
        /// <param name="process">Process to create the thread in.</param>
        /// <param name="start_routine">Address of the start routine.</param>
        /// <param name="argument">Argument to pass to the thread.</param>
        /// <param name="create_flags">Creation flags.</param>
        /// <param name="stack_size">Size of the committed stack.</param>
        /// <returns>The created thread object.</returns>
        /// <remarks>This creates a native thread, not a Win32 thread. This might cause unexpected things to fail as they're not initialized.</remarks>
        public static NtThread Create(
            NtProcess process,
            long start_routine,
            long argument,
            ThreadCreateFlags create_flags,
            long stack_size)
        {
            return Create(process, start_routine, argument, create_flags, stack_size, true).Result;
        }

        /// <summary>
        /// Open a thread
        /// </summary>
        /// <param name="process_id">The process ID containing the thread.</param>
        /// <param name="thread_id">The thread ID to open</param>
        /// <param name="desired_access">The desired access for the handle</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtThread> Open(int process_id, int thread_id, ThreadAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenThread(out SafeKernelObjectHandle handle, desired_access, new ObjectAttributes(),
                new ClientId() { UniqueProcess = new IntPtr(process_id), UniqueThread = new IntPtr(thread_id) })
                .CreateResult(throw_on_error, () => new NtThread(handle) { _tid = thread_id });
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
            return Open(0, thread_id, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open a thread
        /// </summary>
        /// <param name="process_id">The process ID containing the thread.</param>
        /// <param name="thread_id">The thread ID to open</param>
        /// <param name="desired_access">The desired access for the handle</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtThread Open(int process_id, int thread_id, ThreadAccessRights desired_access)
        {
            return Open(process_id, thread_id, desired_access, true).Result;
        }

        /// <summary>
        /// Open a thread
        /// </summary>
        /// <param name="thread_id">The thread ID to open</param>
        /// <param name="desired_access">The desired access for the handle</param>
        /// <returns>The opened object</returns>
        public static NtThread Open(int thread_id, ThreadAccessRights desired_access)
        {
            return Open(0, thread_id, desired_access);
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
            NtStatus status = NtSystemCalls.NtGetNextThread(
                process.Handle, SafeKernelObjectHandle.Null, desired_access,
                AttributeFlags.None, 0, out SafeKernelObjectHandle new_handle);
            if (status == NtStatus.STATUS_SUCCESS)
            {
                return new NtThread(new_handle);
            }
            return null;
        }

        /// <summary>
        /// Sleep the current thread
        /// </summary>
        /// <param name="alertable">Set if the thread should be alertable</param>
        /// <param name="delay">The delay, negative values indicate relative times.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>STATUS_ALERTED if the thread was alerted, other success or error code.</returns>
        public static NtStatus Sleep(bool alertable, NtWaitTimeout delay, bool throw_on_error)
        {
            return NtSystemCalls.NtDelayExecution(alertable, delay?.Timeout).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Sleep the current thread
        /// </summary>
        /// <param name="alertable">Set if the thread should be alertable</param>
        /// <param name="delay">The delay, negative values indicate relative times.</param>
        /// <returns>True if the thread was alerted before the delay expired.</returns>
        public static bool Sleep(bool alertable, NtWaitTimeout delay)
        {
            return Sleep(alertable, delay, true) == NtStatus.STATUS_ALERTED;
        }

        /// <summary>
        /// Sleep the current thread
        /// </summary>
        /// <param name="alertable">Set if the thread should be alertable</param>
        /// <param name="delay">The delay, negative values indicate relative times.</param>
        /// <returns>True if the thread was alerted before the delay expired.</returns>
        public static bool Sleep(bool alertable, long delay)
        {
            return Sleep(alertable, new NtWaitTimeout(delay));
        }

        /// <summary>
        /// Sleep the current thread for a specified number of milliseconds.
        /// </summary>
        /// <param name="delay_ms">The delay in milliseconds.</param>
        /// <returns>True if the thread was alerted before the delay expired.</returns>
        public static bool SleepMs(long delay_ms)
        {
            return Sleep(false, NtWaitTimeout.FromMilliseconds(delay_ms));
        }

        /// <summary>
        /// Open an actual handle to the current thread rather than the pseudo one used for Current
        /// </summary>
        /// <returns>The thread object</returns>
        public static NtThread OpenCurrent()
        {
            return Current.Duplicate();
        }

        /// <summary>
        /// Set the work on behalf ticket.
        /// </summary>
        /// <param name="ticket">The ticket to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The status code from the set.</returns>
        public static NtStatus SetWorkOnBehalfTicket(ulong ticket, bool throw_on_error)
        {
            return SetWorkOnBehalfTicket(new WorkOnBehalfTicket(ticket), throw_on_error);
        }

        /// <summary>
        /// Set the work on behalf ticket.
        /// </summary>
        /// <param name="ticket">The ticket to set.</param>
        public static void SetWorkOnBehalfTicket(ulong ticket)
        {
            SetWorkOnBehalfTicket(ticket, true);
        }

        /// <summary>
        /// Set the work on behalf ticket.
        /// </summary>
        /// <param name="ticket">The ticket to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The status code from the set.</returns>
        public static NtStatus SetWorkOnBehalfTicket(WorkOnBehalfTicket ticket, bool throw_on_error)
        {
            return Current.Set(ThreadInformationClass.ThreadWorkOnBehalfTicket, new RtlWorkOnBehalfTicket() { WorkOnBehalfTicket = ticket.Ticket }, throw_on_error);
        }

        /// <summary>
        /// Set the work on behalf ticket.
        /// </summary>
        /// <param name="ticket">The ticket to set.</param>
        public static void SetWorkOnBehalfTicket(WorkOnBehalfTicket ticket)
        {
            SetWorkOnBehalfTicket(ticket, true);
        }

        /// <summary>
        /// Set the work on behalf ticket.
        /// </summary>
        /// <param name="thread_id">The thread ID.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status.</returns>
        public static NtStatus SetWorkOnBehalfTicket(int thread_id, bool throw_on_error)
        {
            var ticket = GetTicket(thread_id, throw_on_error);
            if (!ticket.IsSuccess)
                return ticket.Status;

            return SetWorkOnBehalfTicket(ticket.Result, throw_on_error);
        }

        /// <summary>
        /// Set the work on behalf ticket.
        /// </summary>
        /// <param name="thread_id">The thread ID.</param>
        public static void SetWorkOnBehalfTicket(int thread_id)
        {
            SetWorkOnBehalfTicket(thread_id, true);
        }

        /// <summary>
        /// Test alert status for the current thread.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus TestAlert(bool throw_on_error)
        {
            return NtSystemCalls.NtTestAlert();
        }

        /// <summary>
        /// Test alert status for the current thread.
        /// </summary>
        public static void TestAlert()
        {
            TestAlert(true);
        }

        /// <summary>
        /// Attach a silo container to the current thread.
        /// </summary>
        /// <param name="silo">The silo to attach.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The thread impersonation context.</returns>
        public static NtResult<ThreadImpersonationContext> AttachContainer(NtJob silo, bool throw_on_error)
        {
            if (silo is null)
            {
                throw new ArgumentNullException(nameof(silo));
            }

            return Current.Set(ThreadInformationClass.ThreadAttachContainer, silo.Handle.DangerousGetHandle(),
                false).CreateResult(throw_on_error, () => new ThreadImpersonationContext(true));
        }

        /// <summary>
        /// Attach a silo container to the current thread.
        /// </summary>
        /// <param name="silo">The silo to attach.</param>
        /// <returns>The thread impersonation context.</returns>
        public static ThreadImpersonationContext AttachContainer(NtJob silo)
        {
            return AttachContainer(silo, true).Result;
        }

        /// <summary>
        /// Detach container from the current thread.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus DetachContainer(bool throw_on_error)
        {
            return Current.Set(ThreadInformationClass.ThreadAttachContainer, IntPtr.Zero,
                throw_on_error);
        }

        /// <summary>
        /// Detach container from the current thread.
        /// </summary>
        public static void DetachContainer()
        {
            DetachContainer(true);
        }

        /// <summary>
        /// Get XOR key for the work-on-behalf ticket.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The XOR key.</returns>
        public static NtResult<ulong> GetWorkOnBehalfTicketXor(bool throw_on_error)
        {
            var result = Current.Query<RtlWorkOnBehalfTicketEx>(ThreadInformationClass.ThreadWorkOnBehalfTicket, default, throw_on_error);
            if (!result.IsSuccess)
                return result.Cast<ulong>();

            var ticket = result.Result.Ticket;
            uint tid = (uint)Current.ThreadId;
            var time = Current.Query<KernelUserTimes>(ThreadInformationClass.ThreadTimes, default, throw_on_error);
            if (!time.IsSuccess)
                return time.Cast<ulong>();
            ticket.ThreadId ^= tid;
            ticket.ThreadCreationTimeLow ^= time.Result.CreateTime.LowPart;
            return ticket.WorkOnBehalfTicket.CreateResult();
        }

        #endregion

        #region Static Properties

        /// <summary>
        /// Get the current thread.
        /// </summary>
        /// <remarks>This only uses the pseudo handle, for the thread. You can't use it in different threads. If you need to do that use OpenCurrent.</remarks>
        /// <see cref="OpenCurrent"/>
        public static NtThread Current { get { return new NtThread(new SafeKernelObjectHandle(-2)); } }


        /// <summary>
        /// Get or set the work on behalf ticket for the current thread.
        /// </summary>
        public static WorkOnBehalfTicket WorkOnBehalfTicket
        {
            get => Current.GetWorkOnBehalfTicket();
            set => SetWorkOnBehalfTicket(value);
        }

        /// <summary>
        /// Get the work on behalf ticket xor key.
        /// </summary>
        public static ulong WorkOnBehalfTicketXor => GetWorkOnBehalfTicketXor(true).Result;

        #endregion

        #region Public Methods

        /// <summary>
        /// Reopen object with different access rights.
        /// </summary>
        /// <param name="desired_access">The desired access.</param>
        /// <param name="attributes">Additional attributes for open.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The reopened object.</returns>
        public override NtResult<NtThread> ReOpen(ThreadAccessRights desired_access, AttributeFlags attributes, bool throw_on_error)
        {
            return Open(ThreadId, desired_access, throw_on_error);
        }

        /// <summary>
        /// Resume the thread.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The suspend count</returns>
        public NtResult<int> Resume(bool throw_on_error)
        {
            return NtSystemCalls.NtResumeThread(Handle, out int suspend_count).CreateResult(throw_on_error, () => suspend_count);
        }

        /// <summary>
        /// Resume the thread.
        /// </summary>
        /// <returns>The suspend count</returns>
        public int Resume()
        {
            return Resume(true).Result;
        }

        /// <summary>
        /// Suspend the thread.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The suspend count</returns>
        public NtResult<int> Suspend(bool throw_on_error)
        {
            return NtSystemCalls.NtSuspendThread(Handle, out int suspend_count).CreateResult(throw_on_error, () => suspend_count);
        }

        /// <summary>
        /// Suspend the thread
        /// </summary>
        /// <returns>The suspend count</returns>
        public int Suspend()
        {
            return Suspend(true).Result;
        }

        /// <summary>
        /// Terminate the thread
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <param name="status">The thread status exit code</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Terminate(NtStatus status, bool throw_on_error)
        {
            return NtSystemCalls.NtTerminateThread(Handle, status).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Terminate the thread
        /// </summary>
        /// <param name="status">The thread status exit code</param>
        public void Terminate(NtStatus status)
        {
            Terminate(status, true);
        }

        /// <summary>
        /// Wake the thread from an alertable state.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Alert(bool throw_on_error)
        {
            return NtSystemCalls.NtAlertThread(Handle).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Wake the thread from an alertable state.
        /// </summary>
        public void Alert()
        {
            Alert(true);
        }

        /// <summary>
        /// Wake the thread from an alertable state and resume the thread.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The previous suspend count for the thread.</returns>
        public NtResult<int> AlertResume(bool throw_on_error)
        {
            OptionalInt32 suspend_count = new OptionalInt32();
            return NtSystemCalls.NtAlertResumeThread(Handle, suspend_count).CreateResult(throw_on_error, () => suspend_count.Value);
        }

        /// <summary>
        /// Wake the thread from an alertable state and resume the thread.
        /// </summary>
        /// <returns>The previous suspend count for the thread.</returns>
        public int AlertResume()
        {
            return AlertResume(true).Result;
        }

        /// <summary>
        /// Hide the thread from debug events.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus HideFromDebugger(bool throw_on_error)
        {
            return SetBuffer(ThreadInformationClass.ThreadHideFromDebugger, SafeHGlobalBuffer.Null, throw_on_error);
        }

        /// <summary>
        /// Hide the thread from debug events.
        /// </summary>
        public void HideFromDebugger()
        {
            HideFromDebugger(true);
        }

        /// <summary>
        /// The set the thread's impersonation token
        /// </summary>
        /// <param name="token">The impersonation token to set</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetImpersonationToken(NtToken token, bool throw_on_error)
        {
            IntPtr handle = token != null ? token.Handle.DangerousGetHandle() : IntPtr.Zero;
            using (var buf = handle.ToBuffer())
            {
                return NtSystemCalls.NtSetInformationThread(Handle, ThreadInformationClass.ThreadImpersonationToken,
                    buf, buf.Length).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// The set the thread's impersonation token
        /// </summary>
        /// <param name="token">The impersonation token to set</param>
        public void SetImpersonationToken(NtToken token)
        {
            SetImpersonationToken(token, true);
        }

        /// <summary>
        /// Impersonate the anonymous token
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The impersonation context. Dispose to revert to self</returns>
        public NtResult<ThreadImpersonationContext> ImpersonateAnonymousToken(bool throw_on_error)
        {
            return NtSystemCalls.NtImpersonateAnonymousToken(Handle)
                .CreateResult(throw_on_error, () => new ThreadImpersonationContext(Duplicate()));
        }

        /// <summary>
        /// Impersonate the anonymous token
        /// </summary>
        /// <returns>The impersonation context. Dispose to revert to self</returns>
        public ThreadImpersonationContext ImpersonateAnonymousToken()
        {
            return ImpersonateAnonymousToken(true).Result;
        }

        /// <summary>
        /// Impersonate a token
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <param name="token">The token to impersonate.</param>
        /// <returns>The impersonation context. Dispose to revert to self</returns>
        public NtResult<ThreadImpersonationContext> Impersonate(NtToken token, bool throw_on_error)
        {
            return SetImpersonationToken(token, false).CreateResult(throw_on_error, () => new ThreadImpersonationContext(Duplicate()));
        }

        /// <summary>
        /// Impersonate a token
        /// </summary>
        /// <param name="token">The token to impersonate.</param>
        /// <returns>The impersonation context. Dispose to revert to self</returns>
        public ThreadImpersonationContext Impersonate(NtToken token)
        {
            return Impersonate(token, true).Result;
        }

        /// <summary>
        /// Impersonate another thread.
        /// </summary>
        /// <param name="thread">The thread to impersonate.</param>
        /// <param name="security_quality_of_service">The impersonation security quality of service.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The imperonsation context. Dispose to revert to self.</returns>
        public NtResult<ThreadImpersonationContext> ImpersonateThread(NtThread thread,
            SecurityQualityOfService security_quality_of_service, bool throw_on_error)
        {
            return NtSystemCalls.NtImpersonateThread(Handle, thread.Handle, security_quality_of_service)
                .CreateResult(throw_on_error, () => new ThreadImpersonationContext(Duplicate()));
        }

        /// <summary>
        /// Impersonate another thread's security context.
        /// </summary>
        /// <param name="thread">The thread to impersonate.</param>
        /// <param name="impersonation_level">The impersonation level for the token.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The imperonsation context. Dispose to revert to self.</returns>
        public NtResult<ThreadImpersonationContext> ImpersonateThread(NtThread thread,
            SecurityImpersonationLevel impersonation_level, bool throw_on_error)
        {
            return ImpersonateThread(thread, new SecurityQualityOfService(impersonation_level,
                SecurityContextTrackingMode.Static, false), throw_on_error);
        }

        /// <summary>
        /// Impersonate another thread's security context.
        /// </summary>
        /// <param name="thread">The thread to impersonate.</param>
        /// <param name="impersonation_level">The impersonation level for the token.</param>
        /// <returns>The imperonsation context. Dispose to revert to self.</returns>
        public ThreadImpersonationContext ImpersonateThread(NtThread thread, SecurityImpersonationLevel impersonation_level)
        {
            return ImpersonateThread(thread, impersonation_level, true).Result;
        }

        /// <summary>
        /// Impersonate another thread's security context at impersonation level.
        /// </summary>
        /// <param name="thread">The thread to impersonate.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The imperonsation context. Dispose to revert to self.</returns>
        public NtResult<ThreadImpersonationContext> ImpersonateThread(NtThread thread, bool throw_on_error)
        {
            return ImpersonateThread(thread, SecurityImpersonationLevel.Impersonation, throw_on_error);
        }

        /// <summary>
        /// Impersonate another thread's security context at impersonation level.
        /// </summary>
        /// <param name="thread">The thread to impersonate.</param>
        /// <returns>The imperonsation context. Dispose to revert to self.</returns>
        public ThreadImpersonationContext ImpersonateThread(NtThread thread)
        {
            return ImpersonateThread(thread, SecurityImpersonationLevel.Impersonation);
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
        /// Queue a special user APC to the thread.
        /// </summary>
        /// <param name="apc_routine">The APC callback pointer.</param>
        /// <param name="normal_context">Context parameter.</param>
        /// <param name="system_argument1">System argument 1.</param>
        /// <param name="system_argument2">System argument 2.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS5)]
        public NtStatus QueueSpecialUserApc(IntPtr apc_routine, IntPtr normal_context, IntPtr system_argument1, IntPtr system_argument2, bool throw_on_error)
        {
            return NtSystemCalls.NtQueueApcThreadEx(Handle, new IntPtr(1), apc_routine, normal_context, system_argument1, system_argument2).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Queue a special user APC to the thread.
        /// </summary>
        /// <param name="apc_routine">The APC callback pointer.</param>
        /// <param name="normal_context">Context parameter.</param>
        /// <param name="system_argument1">System argument 1.</param>
        /// <param name="system_argument2">System argument 2.</param>
        /// <returns>The NT status code.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS5)]
        public void QueueSpecialUserApc(IntPtr apc_routine, IntPtr normal_context, IntPtr system_argument1, IntPtr system_argument2)
        {
            QueueSpecialUserApc(apc_routine, normal_context, system_argument1, system_argument2, true);
        }

        /// <summary>
        /// Queue a special user APC to the thread.
        /// </summary>
        /// <param name="apc_routine">The APC callback pointer.</param>
        /// <param name="normal_context">Context parameter.</param>
        /// <param name="system_argument1">System argument 1.</param>
        /// <param name="system_argument2">System argument 2.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS5)]
        public NtStatus QueueSpecialUserApc(ApcCallback apc_routine, IntPtr normal_context, IntPtr system_argument1, IntPtr system_argument2, bool throw_on_error)
        {
            if (ProcessId != NtProcess.Current.ProcessId)
                throw new ArgumentException("Thread must be in current process to queue a delegate.");
            return QueueSpecialUserApc(Marshal.GetFunctionPointerForDelegate(apc_routine), normal_context, system_argument1, system_argument2, throw_on_error);
        }

        /// <summary>
        /// Queue a special user APC to the thread.
        /// </summary>
        /// <param name="apc_routine">The APC callback pointer.</param>
        /// <param name="normal_context">Context parameter.</param>
        /// <param name="system_argument1">System argument 1.</param>
        /// <param name="system_argument2">System argument 2.</param>
        /// <returns>The NT status code.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS5)]
        public void QueueSpecialUserApc(ApcCallback apc_routine, IntPtr normal_context, IntPtr system_argument1, IntPtr system_argument2)
        {
            QueueSpecialUserApc(apc_routine, normal_context, system_argument1, system_argument2, true);
        }

        /// <summary>
        /// Queue a user APC to the thread.
        /// </summary>
        /// <param name="apc_routine">The APC callback pointer.</param>
        /// <param name="normal_context">Context parameter.</param>
        /// <param name="system_argument1">System argument 1.</param>
        /// <param name="system_argument2">System argument 2.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus QueueUserApc(IntPtr apc_routine, IntPtr normal_context, IntPtr system_argument1, IntPtr system_argument2, bool throw_on_error)
        {
            return NtSystemCalls.NtQueueApcThread(Handle, apc_routine, normal_context, system_argument1, system_argument2).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Queue a user APC to the thread.
        /// </summary>
        /// <param name="apc_routine">The APC callback pointer.</param>
        /// <param name="normal_context">Context parameter.</param>
        /// <param name="system_argument1">System argument 1.</param>
        /// <param name="system_argument2">System argument 2.</param>
        public void QueueUserApc(IntPtr apc_routine, IntPtr normal_context, IntPtr system_argument1, IntPtr system_argument2)
        {
            QueueUserApc(apc_routine, normal_context, system_argument1, system_argument2, true);
        }

        /// <summary>
        /// Queue a user APC to the thread.
        /// </summary>
        /// <param name="apc_routine">The APC callback delegate.</param>
        /// <param name="normal_context">Context parameter.</param>
        /// <param name="system_argument1">System argument 1.</param>
        /// <param name="system_argument2">System argument 2.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <remarks>This is only for APCs in the current process. You also must ensure the delegate is
        /// valid at all times as this method doesn't take a reference to the delegate to prevent it being
        /// garbage collected.</remarks>
        public NtStatus QueueUserApc(ApcCallback apc_routine, IntPtr normal_context,
            IntPtr system_argument1, IntPtr system_argument2, bool throw_on_error)
        {
            if (ProcessId != NtProcess.Current.ProcessId)
                throw new ArgumentException("Thread must be in current process to queue a delegate.");
            return QueueUserApc(Marshal.GetFunctionPointerForDelegate(apc_routine),
                normal_context, system_argument1, system_argument2, throw_on_error);
        }

        /// <summary>
        /// Queue a user APC to the thread.
        /// </summary>
        /// <param name="apc_routine">The APC callback delegate.</param>
        /// <param name="normal_context">Context parameter.</param>
        /// <param name="system_argument1">System argument 1.</param>
        /// <param name="system_argument2">System argument 2.</param>
        /// <remarks>This is only for APCs in the current process. You also must ensure the delegate is
        /// valid at all times as this method doesn't take a reference to the delegate to prevent it being
        /// garbage collected.</remarks>
        public void QueueUserApc(ApcCallback apc_routine, IntPtr normal_context, IntPtr system_argument1, IntPtr system_argument2)
        {
            QueueUserApc(apc_routine, normal_context, system_argument1, system_argument2, true);
        }

        /// <summary>
        /// Get next thread for process relative to current thread.
        /// </summary>
        /// <param name="process">The process handle to get the threads.</param>
        /// <param name="desired_access">The desired access for the thread.</param>
        /// <returns>The next thread, or null if no more available.</returns>
        public NtThread GetNextThread(NtProcess process, ThreadAccessRights desired_access)
        {
            NtStatus status = NtSystemCalls.NtGetNextThread(
                process.Handle, Handle, desired_access,
                AttributeFlags.None, 0, out SafeKernelObjectHandle new_handle);
            if (status == NtStatus.STATUS_SUCCESS)
            {
                return new NtThread(new_handle);
            }
            return null;
        }

        /// <summary>
        /// Get the thread context.
        /// </summary>
        /// <param name="flags">Flags for context parts to get.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>An instance of an IContext object. Needs to be cast to correct type to access.</returns>
        public NtResult<IContext> GetContext(ContextFlags flags, bool throw_on_error)
        {
            var processor = NtSystemInfo.ProcessorInformation.ProcessorArchitecture;
            switch (processor)
            {
                case ProcessorAchitecture.AMD64:
                    return GetContext64<ContextAmd64>(flags, throw_on_error);
                case ProcessorAchitecture.Intel:
                    return GetContext32<ContextX86>(flags, throw_on_error);
                case ProcessorAchitecture.ARM:
                    return GetContext32<ContextARM>(flags, throw_on_error);
                case ProcessorAchitecture.ARM64:
                    return GetContext32<ContextARM64>(flags, throw_on_error);
            }

            throw new InvalidOperationException($"GetContext doesn't support {processor} architecture");
        }

        /// <summary>
        /// Get the thread context.
        /// </summary>
        /// <param name="flags">Flags for context parts to get.</param>
        /// <returns>An instance of an IContext object. Needs to be cast to correct type to access.</returns>
        public IContext GetContext(ContextFlags flags)
        {
            return GetContext(flags, true).Result;
        }

        /// <summary>
        /// Set the thread's context.
        /// </summary>
        /// <param name="context">The thread context to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetContext(IContext context, bool throw_on_error)
        {
            var processor = NtSystemInfo.ProcessorInformation.ProcessorArchitecture;
            switch (processor)
            {
                case ProcessorAchitecture.AMD64:
                    return SetAmd64Context(context, throw_on_error);
                case ProcessorAchitecture.Intel:
                    return SetX86Context(context, throw_on_error);
                case ProcessorAchitecture.ARM:
                    return SetARMContext(context, throw_on_error);
                case ProcessorAchitecture.ARM64:
                    return SetARM64Context(context, throw_on_error);
            }

            throw new InvalidOperationException($"SetContext doesn't support {processor} architecture");
        }

        /// <summary>
        /// Set the thread's context.
        /// </summary>
        /// <param name="context">The thread context to set.</param>
        public void SetContext(IContext context)
        {
            SetContext(context, true);
        }

        /// <summary>
        /// Get current waiting server information.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The thread ALPC server information.</returns>
        public NtResult<ThreadAlpcServerInformation> GetAlpcServerInformation(bool throw_on_error)
        {
            AlpcServerInformation info = new AlpcServerInformation() { ThreadHandle = Handle.DangerousGetHandle() };
            using (var buffer = info.ToBuffer(1024, true))
            {
                return NtSystemCalls.NtAlpcQueryInformation(SafeKernelObjectHandle.Null, AlpcPortInformationClass.AlpcServerInformation,
                    buffer, buffer.Length, out int return_length).CreateResult(throw_on_error, () => new ThreadAlpcServerInformation(buffer.Result.Out));
            }
        }

        /// <summary>
        /// Get current waiting server information.
        /// </summary>
        /// <returns>The thread ALPC server information.</returns>
        public ThreadAlpcServerInformation GetAlpcServerInformation()
        {
            return GetAlpcServerInformation(true).Result;
        }

        /// <summary>
        /// Get the process ID associated with the thread.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The process ID.</returns>
        public NtResult<int> GetProcessId(bool throw_on_error)
        {
            if (_pid.HasValue)
                return _pid.Value.CreateResult();
            return QueryBasicInformation(throw_on_error).Map(i => i.ClientId.UniqueProcess.ToInt32());
        }

        /// <summary>
        /// Get the thread ID.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The thread ID.</returns>
        public NtResult<int> GeThreadId(bool throw_on_error)
        {
            if (_tid.HasValue)
                return _tid.Value.CreateResult();
            return QueryBasicInformation(throw_on_error).Map(i => i.ClientId.UniqueProcess.ToInt32());
        }

        /// <summary>
        /// Cancel all synchronous IO for this thread.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status.</returns>
        public NtStatus CancelSynchronousIo(bool throw_on_error = true)
        {
            return NtSystemCalls.NtCancelSynchronousIoFile(Handle, SafeIoStatusBuffer.Null, new IoStatus()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Get a partial TEB for the thread.
        /// </summary>
        /// <returns>The partial TEB.</returns>
        public ITeb GetTeb()
        {
            using (var process = NtProcess.Open(ProcessId, ProcessAccessRights.VmRead))
            {
                return process.ReadMemory<PartialTeb>(TebBaseAddress.ToInt64());
            }
        }

        /// <summary>
        /// Get the work on behalf ticket for a thread.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The work on behalf ticket.</returns>
        public NtResult<WorkOnBehalfTicket> GetWorkOnBehalfTicket(bool throw_on_error)
        {
            if (Handle.DangerousGetHandle() == new IntPtr(-2))
            {
                return Query<RtlWorkOnBehalfTicketEx>(ThreadInformationClass.ThreadWorkOnBehalfTicket,
                    default, throw_on_error).Map(t => new WorkOnBehalfTicket(t));
            }
            else
            {
                return GetTicket(ThreadId, throw_on_error);
            }
        }

        /// <summary>
        /// Get the work on behalf ticket for a thread.
        /// </summary>
        /// <returns>The work on behalf ticket.</returns>
        public WorkOnBehalfTicket GetWorkOnBehalfTicket()
        {
            return GetWorkOnBehalfTicket(true).Result;
        }

        /// <summary>
        /// Get the effective container ID for the thread.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The effective container ID.</returns>
        public NtResult<Guid> GetContainerId(bool throw_on_error)
        {
            return Query<Guid>(ThreadInformationClass.ThreadContainerId, default, throw_on_error);
        }

        /// <summary>
        /// Get priority boost disable value.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>True if priority base </returns>
        public NtResult<bool> GetPriorityBoostDisabled(bool throw_on_error)
        {
            return Query(ThreadInformationClass.ThreadPriorityBoost, 0, throw_on_error).Map(i => i != 0);
        }

        /// <summary>
        /// Set priority boost disable value.
        /// </summary>
        /// <param name="disable">True to disable priority boost.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetPriorityBoostDisabled(bool disable, bool throw_on_error)
        {
            return Set(ThreadInformationClass.ThreadPriorityBoost, disable ? 1 : 0, throw_on_error);
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(ThreadInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryInformationThread(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public override NtStatus SetInformation(ThreadInformationClass info_class, SafeBuffer buffer)
        {
            return NtSystemCalls.NtSetInformationThread(Handle, info_class, buffer, buffer.GetLength());
        }

        /// <summary>
        /// Query the information class as an object.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The information class as an object.</returns>
        public override NtResult<object> QueryObject(ThreadInformationClass info_class, bool throw_on_error)
        {
            switch (info_class)
            {
                case ThreadInformationClass.ThreadBasicInformation:
                    return Query<ThreadBasicInformation>(info_class, default, throw_on_error);
                case ThreadInformationClass.ThreadTimes:
                    return Query<KernelUserTimes>(info_class, default, throw_on_error);
                case ThreadInformationClass.ThreadCycleTime:
                    return Query<ThreadCycleTimeInformation>(info_class, default, throw_on_error);
            }
            return base.QueryObject(info_class, throw_on_error);
        }

        #endregion

        #region Public Properties
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
                            _process_name = string.Empty;
                        }
                    }
                }
                return _process_name;
            }
        }

        /// <summary>
        /// Get or set the thread's current priority
        /// </summary>
        public int Priority
        {
            get => QueryBasicInformation().Priority;
            set => Set(ThreadInformationClass.ThreadPriority, value);
        }

        /// <summary>
        /// Get or set the thread's base priority
        /// </summary>
        public int BasePriority
        {
            get => QueryBasicInformation().BasePriority;
            set => Set(ThreadInformationClass.ThreadBasePriority, value);
        }

        /// <summary>
        /// Get or set the thread's affinity mask.
        /// </summary>
        public ulong AffinityMask
        {
            get => QueryBasicInformation().AffinityMask.ToUInt64();
            set => Set(ThreadInformationClass.ThreadAffinityMask, new UIntPtr(value));
        }

        /// <summary>
        /// Get the thread's TEB base address.
        /// </summary>
        public IntPtr TebBaseAddress => QueryBasicInformation().TebBaseAddress;

        /// <summary>
        /// Get or set whether thread is allowed to create dynamic code.
        /// </summary>
        /// <remarks>Set can only be done on the current thread.</remarks>
        public bool AllowDynamicCode
        {
            get => Query<int>(ThreadInformationClass.ThreadDynamicCodePolicyInfo) != 0;
            set => Set(ThreadInformationClass.ThreadDynamicCodePolicyInfo, value ? 1 : 0);
        }

        /// <summary>
        /// Get whether thread is impersonating another token.
        /// </summary>
        /// <remarks>Note that this tries to open the thread's token and return true if it could open. A return of false
        /// might just indicate that the caller doesn't have permission to open the token, not that it's not impersonating.</remarks>
        public bool Impersonating
        {
            get
            {
                if (!GrantedAccess.HasFlagSet(ThreadAccessRights.QueryLimitedInformation))
                {
                    return false;
                }

                // This might be possible to read from the TEB IsImpersonating flag but not clear if it's
                // ever officially documented.
                using (var token = NtToken.OpenThreadToken(this, true, TokenAccessRights.Query, false))
                {
                    return token.Status != NtStatus.STATUS_NO_TOKEN;
                }
            }
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
                    string description = Description;
                    if (string.IsNullOrEmpty(description))
                    {
                        return $"thread:{ThreadId} - process:{ProcessId}";
                    }
                    return description;
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
                using (var buffer = QueryBuffer(ThreadInformationClass.ThreadNameInformation, new UnicodeStringOut(), false))
                {
                    if (buffer.IsSuccess)
                    {
                        return buffer.Result.Result.ToString();
                    }
                    return string.Empty;
                }
            }

            set
            {
                Set(ThreadInformationClass.ThreadNameInformation, new UnicodeStringIn(value));
            }
        }

        /// <summary>
        /// Get the Win32 start address for the thread.
        /// </summary>
        public long Win32StartAddress => Query<IntPtr>(ThreadInformationClass.ThreadQuerySetWin32StartAddress).ToInt64();

        /// <summary>
        /// Get the current Instruction Pointer for the thread.
        /// </summary>
        public long InstructionPointer => (long)GetContext(ContextFlags.Control).InstructionPointer;

        /// <summary>
        /// Get last system call on the thread.
        /// </summary>
        public ThreadLastSystemCall LastSystemCall
        {
            get
            {
                var result = Query(ThreadInformationClass.ThreadLastSystemCall, new ThreadLastSystemCallExtendedInformation(), false);
                if (result.IsSuccess)
                {
                    return new ThreadLastSystemCall(result.Result);
                }

                if (result.Status == NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                {
                    return new ThreadLastSystemCall(Query<ThreadLastSystemCallInformation>(ThreadInformationClass.ThreadLastSystemCall));
                }

                throw new NtException(result.Status);
            }
        }

        /// <summary>
        /// Get the thread's suspend count.
        /// </summary>
        public int SuspendCount => Query<int>(ThreadInformationClass.ThreadSuspendCount);

        /// <summary>
        /// Get whether the thread has pending IO.
        /// </summary>
        public bool IoPending => Query<int>(ThreadInformationClass.ThreadIsIoPending) != 0;

        /// <summary>
        /// Get the creation time of the thread.
        /// </summary>
        public DateTime CreateTime => DateTime.FromFileTime(Query<KernelUserTimes>(ThreadInformationClass.ThreadTimes).CreateTime.QuadPart);

        /// <summary>
        /// Get the exit time of the thread (0 if not exited)
        /// </summary>
        public DateTime ExitTime => DateTime.FromFileTime(Query<KernelUserTimes>(ThreadInformationClass.ThreadTimes).ExitTime.QuadPart);

        /// <summary>
        /// Get the time spent in the kernel.
        /// </summary>
        public long KernelTime => Query<KernelUserTimes>(ThreadInformationClass.ThreadTimes).KernelTime.QuadPart;

        /// <summary>
        /// Get the time spent in user mode.
        /// </summary>
        public long UserTime => Query<KernelUserTimes>(ThreadInformationClass.ThreadTimes).UserTime.QuadPart;

        /// <summary>
        /// Get thread information.
        /// </summary>
        public NtThreadInformation ThreadInformation => new NtThreadInformation(ProcessName, Query<SystemThreadInformation>(ThreadInformationClass.ThreadSystemThreadInformation));

        /// <summary>
        /// Get thread exit status.
        /// </summary>
        public int ExitStatus => QueryBasicInformation().ExitStatus;

        /// <summary>
        /// Get thread exit status.
        /// </summary>
        public NtStatus ExitNtStatus => (NtStatus)ExitStatus;

        /// <summary>
        /// Get the effective container ID.
        /// </summary>
        /// <remarks>Should be called on the current thread psuedo handle.</remarks>
        public Guid ContainerId => GetContainerId(true).Result;

        /// <summary>
        /// Get or set priority boost disabled.
        /// </summary>
        public bool PriorityBoostDisabled
        {
            get => GetPriorityBoostDisabled(true).Result;
            set => SetPriorityBoostDisabled(value, true);
        }
        #endregion
    }
}
