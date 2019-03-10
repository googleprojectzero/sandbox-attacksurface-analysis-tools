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

namespace NtApiDotNet
{
    /// <summary>
    /// Class representing a NT Debug object
    /// </summary>
    [NtType("DebugObject")]
    public class NtDebug : NtObjectWithDuplicate<NtDebug, DebugAccessRights>
    {
        #region Constructors
        internal NtDebug(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtDebug> OpenInternal(ObjectAttributes obj_attributes,
                DebugAccessRights desired_access, bool throw_on_error)
            {
                return NtDebug.Open(obj_attributes, desired_access, throw_on_error);
            }
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Create a debug object
        /// </summary>
        /// <param name="name">The debug object name (can be null)</param>
        /// <param name="root">The root directory for relative names</param>
        /// <param name="flags">Debug object flags.</param>
        /// <returns>The debug object</returns>
        public static NtDebug Create(string name, NtObject root, DebugObjectFlags flags)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, DebugAccessRights.MaximumAllowed, DebugObjectFlags.None);
            }
        }

        /// <summary>
        /// Create a debug object
        /// </summary>
        /// <param name="desired_access">Desired access for the debug object</param>
        /// <param name="object_attributes">Object attributes for debug object</param>
        /// <param name="flags">Debug object flags.</param>
        /// <returns>The debug object</returns>
        public static NtDebug Create(ObjectAttributes object_attributes, DebugAccessRights desired_access, DebugObjectFlags flags)
        {
            return Create(object_attributes, desired_access, flags, true).Result;
        }

        /// <summary>
        /// Create a debug object
        /// </summary>
        /// <param name="desired_access">Desired access for the debug object</param>
        /// <param name="object_attributes">Object attributes for debug object</param>
        /// <param name="flags">Debug object flags.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtDebug> Create(ObjectAttributes object_attributes, DebugAccessRights desired_access, DebugObjectFlags flags, bool throw_on_error)
        {
            return NtSystemCalls.NtCreateDebugObject(out SafeKernelObjectHandle handle, desired_access, object_attributes, flags).CreateResult(throw_on_error, () => new NtDebug(handle));
        }

        /// <summary>
        /// Create a debug object
        /// </summary>
        /// <returns>The debug object</returns>
        public static NtDebug Create()
        {
            return Create(null, null, DebugObjectFlags.None);
        }

        /// <summary>
        /// Open a named debug object
        /// </summary>
        /// <param name="name">The debug object name </param>
        /// <param name="root">The root directory for relative names</param>
        /// <param name="desired_access">Desired access for the debug object</param>
        /// <returns>The debug object</returns>
        public static NtDebug Open(string name, NtObject root, DebugAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive | AttributeFlags.OpenIf, root))
            {
                return Create(obja, DebugAccessRights.MaximumAllowed, DebugObjectFlags.None);
            }
        }

        /// <summary>
        /// Open a named debug object
        /// </summary>
        /// <param name="object_attributes">The object attributes to open.</param>
        /// <param name="desired_access">Desired access for the debug object</param>
        /// <returns>The debug object</returns>
        public static NtDebug Open(ObjectAttributes object_attributes, DebugAccessRights desired_access)
        {
            return Create(object_attributes, DebugAccessRights.MaximumAllowed, DebugObjectFlags.None, true).Result;
        }

        /// <summary>
        /// Open a named debug object
        /// </summary>
        /// <param name="object_attributes">The object attributes to open.</param>
        /// <param name="desired_access">Desired access for the debug object</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtDebug> Open(ObjectAttributes object_attributes, DebugAccessRights desired_access, bool throw_on_error)
        {
            return Create(object_attributes, DebugAccessRights.MaximumAllowed, DebugObjectFlags.None, throw_on_error);
        }

        /// <summary>
        /// Open the current thread's debug object.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened debug object. Returns null if no object exists.</returns>
        public static NtResult<NtDebug> OpenCurrent(bool throw_on_error)
        {
            IntPtr current_debug_object = NtDbgUi.DbgUiGetThreadDebugObject();
            if (current_debug_object == IntPtr.Zero)
            {
                return new NtResult<NtDebug>();
            }
            return DuplicateFrom(NtProcess.Current, current_debug_object, 0, 
                DuplicateObjectOptions.SameAttributes | DuplicateObjectOptions.SameAccess, false);
        }

        #endregion

        #region Status Properties

        /// <summary>
        /// Open the current thread's debug object. Returns null if no object exists.
        /// </summary>
        public static NtDebug Current => OpenCurrent(true).Result;

        #endregion

        #region Public Methods

        /// <summary>
        /// Attach to an active process.
        /// </summary>
        /// <param name="process">The process to debug.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Attach(NtProcess process, bool throw_on_error)
        {
            return NtSystemCalls.NtDebugActiveProcess(process.Handle, Handle).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Attach to an active process.
        /// </summary>
        /// <param name="pid">The process ID to debug.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Attach(int pid, bool throw_on_error)
        {
            using (var process = NtProcess.Open(pid, ProcessAccessRights.SuspendResume, throw_on_error))
            {
                if (!process.IsSuccess)
                {
                    return process.Status;
                }

                return Attach(process.Result, throw_on_error);
            }
        }

        /// <summary>
        /// Attach to an active process.
        /// </summary>
        /// <param name="process">The process to debug.</param>
        public void Attach(NtProcess process)
        {
            Attach(process, true);
        }

        /// <summary>
        /// Attach to an active process.
        /// </summary>
        /// <param name="pid">The process ID to debug.</param>
        public void Attach(int pid)
        {
            Attach(pid, true);
        }

        /// <summary>
        /// Detach a process from this debug object.
        /// </summary>
        /// <param name="process">The process to remove.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Detach(NtProcess process, bool throw_on_error)
        {
            return NtSystemCalls.NtRemoveProcessDebug(process.Handle, Handle).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Detach a process from this debug object.
        /// </summary>
        /// <param name="process">The process to remove.</param>
        public void Detach(NtProcess process)
        {
            Detach(process, true);
        }

        /// <summary>
        /// Detach a process from this debug object.
        /// </summary>
        /// <param name="pid">The process ID to remove.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Detach(int pid, bool throw_on_error)
        {
            using (var process = NtProcess.Open(pid, ProcessAccessRights.SuspendResume, throw_on_error))
            {
                if (!process.IsSuccess)
                {
                    return process.Status;
                }

                return Detach(process.Result, throw_on_error);
            }
        }

        /// <summary>
        /// Detach a process from this debug object.
        /// </summary>
        /// <param name="pid">The process ID to remove.</param>
        public void Detach(int pid)
        {
            Detach(pid, true);
        }

        /// <summary>
        /// Set kill process on close flag.
        /// </summary>
        /// <param name="kill_on_close">The flag state.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetKillOnClose(bool kill_on_close, bool throw_on_error)
        {
            DebugObjectFlags flags = kill_on_close ? DebugObjectFlags.KillOnClose : DebugObjectFlags.None;
            using (var buffer = ((int)flags).ToBuffer())
            {
                return NtSystemCalls.NtSetInformationDebugObject(Handle, DebugObjectInformationClass.DebugObjectKillProcessOnExitInformation,
                    buffer, buffer.Length, out int return_length).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Set kill process on close flag.
        /// </summary>
        /// <param name="kill_on_close">The flag state.</param>
        public void SetKillOnClose(bool kill_on_close)
        {
            SetKillOnClose(kill_on_close, true);
        }

        /// <summary>
        /// Continue the debugged process.
        /// </summary>
        /// <param name="client_id">The client ID for the process and thread IDs.</param>
        /// <param name="continue_status">The continue status code.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Continue(ClientId client_id, NtStatus continue_status, bool throw_on_error)
        {
            return NtSystemCalls.NtDebugContinue(Handle, client_id, continue_status).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Continue the debugged process.
        /// </summary>
        /// <param name="pid">The process ID to continue.</param>
        /// <param name="tid">The thread ID to continue.</param>
        /// <param name="continue_status">The continue status code.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Continue(int pid, int tid, NtStatus continue_status, bool throw_on_error)
        {
            return Continue(new ClientId(pid, tid), continue_status, throw_on_error);
        }

        /// <summary>
        /// Continue the debugged process.
        /// </summary>
        /// <param name="client_id">The client ID for the process and thread IDs.</param>
        /// <param name="continue_status">The continue status code.</param>
        public void Continue(ClientId client_id, NtStatus continue_status)
        {
            Continue(client_id, continue_status, true);
        }

        /// <summary>
        /// Continue the debugged process.
        /// </summary>
        /// <param name="pid">The process ID to continue.</param>
        /// <param name="tid">The thread ID to continue.</param>
        /// <param name="continue_status">The continue status code.</param>
        public void Continue(int pid, int tid, NtStatus continue_status)
        {
            Continue(pid, tid, continue_status, true);
        }

        /// <summary>
        /// Continue the debugged process with a success code.
        /// </summary>
        /// <param name="pid">The process ID to continue.</param>
        /// <param name="tid">The thread ID to continue.</param>
        public void Continue(int pid, int tid)
        {
            Continue(pid, tid, NtStatus.DBG_CONTINUE);
        }

        /// <summary>
        /// Wait for a debug event.
        /// </summary>
        /// <param name="alertable">True to set the thread as alertable.</param>
        /// <param name="timeout">Wait timeout.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The debug event.</returns>
        public NtResult<DebugEvent> WaitForDebugEvent(bool alertable, NtWaitTimeout timeout, bool throw_on_error)
        {
            using (var buffer = new SafeStructureInOutBuffer<DbgUiWaitStatusChange>())
            {
                return NtSystemCalls.NtWaitForDebugEvent(Handle, alertable, timeout.ToLargeInteger(), buffer)
                    .CreateResult(throw_on_error, () => DebugEvent.FromDebugEvent(buffer.Result, this));
            }
        }

        /// <summary>
        /// Wait for a debug event.
        /// </summary>
        /// <param name="alertable">True to set the thread as alertable.</param>
        /// <param name="timeout">Wait timeout.</param>
        /// <returns>The debug event.</returns>
        public DebugEvent WaitForDebugEvent(bool alertable, NtWaitTimeout timeout)
        {
            return WaitForDebugEvent(alertable, timeout, true).Result;
        }

        /// <summary>
        /// Wait for a debug event.
        /// </summary>
        /// <param name="timeout">Wait timeout.</param>
        /// <returns>The debug event.</returns>
        public DebugEvent WaitForDebugEvent(NtWaitTimeout timeout)
        {
            return WaitForDebugEvent(false, timeout);
        }

        /// <summary>
        /// Wait for a debug event.
        /// </summary>
        /// <param name="timeout_ms">Wait timeout in milliseconds.</param>
        /// <returns>The debug event.</returns>
        public DebugEvent WaitForDebugEvent(long timeout_ms)
        {
            return WaitForDebugEvent(false, NtWaitTimeout.FromMilliseconds(timeout_ms));
        }

        /// <summary>
        /// Wait for a debug event.
        /// </summary>
        /// <returns>The debug event.</returns>
        public DebugEvent WaitForDebugEvent()
        {
            return WaitForDebugEvent(false, NtWaitTimeout.Infinite);
        }

        #endregion
    }
}
