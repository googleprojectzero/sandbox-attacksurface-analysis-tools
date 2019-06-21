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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent an NT Timer object
    /// </summary>
    [NtType("Timer")]
    public class NtTimer : NtObjectWithDuplicateAndInfo<NtTimer, TimerAccessRights, TimerInformationClass, TimerSetInformationClass>
    {
        #region Constructors
        internal NtTimer(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtTimer> OpenInternal(ObjectAttributes obj_attributes,
                TimerAccessRights desired_access, bool throw_on_error)
            {
                return NtTimer.Open(obj_attributes, desired_access, throw_on_error);
            }
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Create a timer object
        /// </summary>
        /// <param name="name">The path to the event</param>
        /// <param name="root">The root object for relative path names</param>
        /// <param name="type">The type of the timer.</param>
        /// <returns>The timer object</returns>
        public static NtTimer Create(string name, NtObject root, TimerType type)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, type, TimerAccessRights.MaximumAllowed);
            }
        }

        /// <summary>
        /// Create a timer object
        /// </summary>
        /// <param name="object_attributes">The timer object attributes</param>
        /// <param name="type">The type of the event</param>
        /// <param name="desired_access">The desired access for the timer</param>
        /// <returns>The timer object</returns>
        public static NtTimer Create(ObjectAttributes object_attributes, TimerType type, TimerAccessRights desired_access)
        {
            return Create(object_attributes, type, desired_access, true).Result;
        }


        /// <summary>
        /// Create a timer object
        /// </summary>
        /// <param name="object_attributes">The timer object attributes</param>
        /// <param name="type">The type of the timer</param>
        /// <param name="desired_access">The desired access for the timer</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtTimer> Create(ObjectAttributes object_attributes, TimerType type, 
            TimerAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtCreateTimer(out SafeKernelObjectHandle handle, desired_access, 
                object_attributes, type).CreateResult(throw_on_error, () => new NtTimer(handle));
        }

        /// <summary>
        /// Create a timer object
        /// </summary>
        /// <param name="name">The path to the timer</param>
        /// <param name="type">The type of the timer</param>
        /// <returns>The timer object</returns>
        public static NtTimer Create(string name, TimerType type)
        {
            return Create(name, null, type);
        }

        /// <summary>
        /// Create a timer object
        /// </summary>
        /// <param name="type">The type of the timer</param>
        /// <returns>The timer object</returns>
        public static NtTimer Create(TimerType type)
        {
            return Create(null, type);
        }

        /// <summary>
        /// Create a timer object
        /// </summary>
        /// <returns>The timer object</returns>
        public static NtTimer Create()
        {
            return Create(TimerType.Notification);
        }

        /// <summary>
        /// Open a timer object
        /// </summary>
        /// <param name="name">The path to the timer</param>
        /// <param name="root">The root object for relative path names</param>
        /// <param name="desired_access">The desired access for the timer</param>
        /// <returns>The timer object</returns>
        public static NtTimer Open(string name, NtObject root, TimerAccessRights desired_access)
        {
            return Open(name, root, desired_access, true).Result;
        }

        /// <summary>
        /// Open a timer object
        /// </summary>
        /// <param name="name">The path to the timer</param>
        /// <param name="root">The root object for relative path names</param>
        /// <param name="desired_access">The desired access for the timer</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The timer object</returns>
        public static NtResult<NtTimer> Open(string name, NtObject root, TimerAccessRights desired_access, bool throw_on_error)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access, throw_on_error);
            }
        }

        /// <summary>
        /// Open a timer object
        /// </summary>
        /// <param name="object_attributes">The timer object attributes</param>
        /// <param name="desired_access">The desired access for the timer</param>
        /// <returns>The timer object.</returns>
        public static NtTimer Open(ObjectAttributes object_attributes, TimerAccessRights desired_access)
        {
            return Open(object_attributes, desired_access, true).Result;
        }

        /// <summary>
        /// Open a timer object
        /// </summary>
        /// <param name="object_attributes">The event object attributes</param>
        /// <param name="desired_access">The desired access for the timer</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtTimer> Open(ObjectAttributes object_attributes, TimerAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenTimer(out SafeKernelObjectHandle handle, desired_access, object_attributes).CreateResult(throw_on_error, () => new NtTimer(handle));
        }

        /// <summary>
        /// Open a timer object
        /// </summary>
        /// <param name="name">The path to the timer</param>
        /// <param name="root">The root object for relative path names</param>
        /// <returns>The timer object</returns>
        public static NtTimer Open(string name, NtObject root)
        {
            return Open(name, root, TimerAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open a timer object
        /// </summary>
        /// <param name="name">The path to the timer</param>
        /// <returns>The timer object</returns>
        public static NtTimer Open(string name)
        {
            return Open(name, null);
        }
        #endregion

        #region Public Methods

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(TimerInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryTimer(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public override NtStatus SetInformation(TimerSetInformationClass info_class, SafeBuffer buffer)
        {
            return NtSystemCalls.NtSetTimerEx(Handle, info_class, buffer, buffer.GetLength());
        }

        /// <summary>
        /// Set timer state.
        /// </summary>
        /// <param name="due_time">The due time for the timer.</param>
        /// <param name="apc_routine">Optional APC routine.</param>
        /// <param name="context">Optional APC context pointer.</param>
        /// <param name="resume">True to resume.</param>
        /// <param name="period">Period time.</param>
        /// <param name="throw_on_error">True throw on error.</param>
        /// <returns>The NT result and previous state.</returns>
        public NtResult<bool> Set(NtWaitTimeout due_time,
            TimerApcCallback apc_routine,
            IntPtr context,
            bool resume,
            int period,
            bool throw_on_error)
        {
            IntPtr apc_ptr = apc_routine != null ? Marshal.GetFunctionPointerForDelegate(apc_routine) : IntPtr.Zero;
            return NtSystemCalls.NtSetTimer(Handle, due_time.Timeout, apc_ptr, context, resume, period,
                out bool previous_state).CreateResult(throw_on_error, () => previous_state);
        }

        /// <summary>
        /// Set timer state.
        /// </summary>
        /// <param name="due_time">The due time for the timer.</param>
        /// <param name="apc_routine">Optional APC routine.</param>
        /// <param name="context">Optional APC context pointer.</param>
        /// <param name="resume">True to resume.</param>
        /// <param name="period">Period time.</param>
        /// <returns>The previous state.</returns>
        public bool Set(NtWaitTimeout due_time,
            TimerApcCallback apc_routine,
            IntPtr context,
            bool resume,
            int period)
        {
            return Set(due_time, apc_routine, context, resume, period, true).Result;
        }

        /// <summary>
        /// Set timer state.
        /// </summary>
        /// <param name="due_time">The due time for the timer.</param>
        /// <returns>The previous state.</returns>
        public bool Set(NtWaitTimeout due_time)
        {
            return Set(due_time, null, IntPtr.Zero, false, 0);
        }

        /// <summary>
        /// Set timer state in milliseconds.
        /// </summary>
        /// <param name="due_time_ms">The due time for the timer in milliseconds.</param>
        /// <returns>The previous state.</returns>
        public bool SetMs(long due_time_ms)
        {
            return Set(NtWaitTimeout.FromMilliseconds(due_time_ms));
        }

        /// <summary>
        /// Cancel the timer.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The previous state.</returns>
        public NtResult<bool> Cancel(bool throw_on_error)
        {
            return NtSystemCalls.NtCancelTimer(Handle, out bool state).CreateResult(throw_on_error, () => state);
        }

        /// <summary>
        /// Cancel the timer.
        /// </summary>
        /// <returns>The previous state.</returns>
        public bool Cancel()
        {
            return Cancel(true).Result;
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Remaining time for the timer.
        /// </summary>
        public long RemainingTime => Query<TimerBasicInformation>(TimerInformationClass.TimerBasicInformation).RemainingTime.QuadPart;

        /// <summary>
        /// Signal state of the timer.
        /// </summary>
        public bool State => Query<TimerBasicInformation>(TimerInformationClass.TimerBasicInformation).TimerState;

        #endregion
    }
}
