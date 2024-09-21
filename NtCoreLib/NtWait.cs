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

namespace NtApiDotNet
{
    /// <summary>
    /// Native Wait methods.
    /// </summary>
    public static class NtWait
    {
        /// <summary>
        /// Wait on a single object to become signaled
        /// </summary>
        /// <param name="obj">The object to wait on</param>
        /// <param name="alertable">Whether the thread should be alertable</param>
        /// <param name="timeout">The timeout to wait for</param>
        /// <returns>The success status of the wait, such as STATUS_SUCCESS or STATUS_TIMEOUT</returns>
        public static NtStatus Wait(NtObject obj, bool alertable, NtWaitTimeout timeout)
        {
            return NtSystemCalls.NtWaitForSingleObject(obj.Handle, alertable, timeout.ToLargeInteger()).ToNtException();
        }

        /// <summary>
        /// Wait on multiple objects to become signaled
        /// </summary>
        /// <param name="objs">The objects to wait on</param>
        /// <param name="alertable">Whether the thread should be alerable</param>
        /// <param name="wait_all">True to wait for all objects to be signaled</param>
        /// <param name="timeout">The timeout to wait for</param>
        /// <returns>The success status of the wait, such as STATUS_WAIT_OBJECT_0 or STATUS_TIMEOUT</returns>
        public static NtStatus Wait(IEnumerable<NtObject> objs, bool alertable, bool wait_all, NtWaitTimeout timeout)
        {
            IntPtr[] handles = objs.Select(o => o.Handle.DangerousGetHandle()).ToArray();
            return NtSystemCalls.NtWaitForMultipleObjects(handles.Length, handles,
                wait_all ? WaitType.WaitAll : WaitType.WaitAny, alertable, timeout.ToLargeInteger()).ToNtException();
        }

        /// <summary>
        /// Signal an object then wait for another to become signaled.
        /// </summary>
        /// <param name="object_to_signal">The object to signal</param>
        /// <param name="object_to_wait">The object to wait on.</param>
        /// <param name="alertable">Whether the thread should be alertable</param>
        /// <param name="timeout">The timeout to wait for</param>
        /// <returns>The success status of the wait, such as STATUS_SUCCESS or STATUS_TIMEOUT</returns>
        public static NtStatus SignalAndWait(NtObject object_to_signal, NtObject object_to_wait, bool alertable, NtWaitTimeout timeout)
        {
            return NtSystemCalls.NtSignalAndWaitForSingleObject(object_to_signal.Handle, object_to_wait.Handle, alertable, timeout.Timeout);
        }
    }
}
