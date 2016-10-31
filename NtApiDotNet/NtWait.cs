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

using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    public enum WaitType
    {
        WaitAll,
        WaitAny
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtWaitForSingleObject(
          SafeKernelObjectHandle Handle,
          bool Alertable,
          LargeInteger Timeout
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtWaitForMultipleObjects(int HandleCount, 
            [Out] SafeKernelObjectHandle[] Handles, WaitType WaitType, bool Alertable, LargeInteger Timeout);
    }
#pragma warning disable 1591

    /// <summary>
    /// Class to represent an NT timeout
    /// </summary>
    public sealed class NtWaitTimeout
    {
        const long units_per_second = 10000000;

        internal NtWaitTimeout()
        {
        }

        internal NtWaitTimeout(long value)
        {
            Timeout = new LargeInteger(value);
        }

        /// <summary>
        /// Get a timeout which will wait infinitely.
        /// </summary>
        public static NtWaitTimeout Infinite { get { return new NtWaitTimeout(); } }
        
        /// <summary>
        /// Get a relative timeout in seconds
        /// </summary>
        /// <param name="seconds">The number of seconds to wait.</param>
        /// <returns>An instance of the timeout class</returns>
        public static NtWaitTimeout FromSeconds(int seconds)
        {
            return new NtWaitTimeout(-(seconds * units_per_second));
        }

        /// <summary>
        /// Get an absolute time out from system start.
        /// </summary>
        /// <param name="absolute">The absolute time to wait until</param>
        /// <returns>An instance of the timeout class</returns>
        public static NtWaitTimeout FromAbsolute(long absolute)
        {
            return new NtWaitTimeout(absolute);
        }

        /// <summary>
        /// Get a relative time out from the current time.
        /// </summary>
        /// <param name="relative">The relative time to wait in units of 100ns</param>
        /// <returns>An instance of the timeout class</returns>
        public static NtWaitTimeout FromRelative(long relative)
        {
            return new NtWaitTimeout(-relative);
        }
        
        internal LargeInteger Timeout { get; private set; }
    }

    /// <summary>
    /// Wait methods
    /// </summary>
    public class NtWait
    {
        /// <summary>
        /// Wait on a single object to become signalled
        /// </summary>
        /// <param name="obj">The object to wait on</param>
        /// <param name="alertable">Whether the thread should be alerable</param>
        /// <param name="timeout">The timeout to wait for</param>
        /// <returns>The success status of the wait, such as STATUS_WAIT_OBJECT_0 or STATUS_USER_APC</returns>
        public static NtStatus Wait(NtObject obj, bool alertable, NtWaitTimeout timeout)
        {
            return NtSystemCalls.NtWaitForSingleObject(obj.Handle, alertable, timeout.Timeout).ToNtException();
        }

        /// <summary>
        /// Wait on multiple objects to become signalled
        /// </summary>
        /// <param name="objs">The objects to wait on</param>
        /// <param name="alertable">Whether the thread should be alerable</param>
        /// <param name="wait_all">True to wait for all objects to be signalled</param>
        /// <param name="timeout">The timeout to wait for</param>
        /// <returns>The success status of the wait, such as STATUS_WAIT_OBJECT_0 or STATUS_USER_APC</returns>
        public static NtStatus Wait(IEnumerable<NtObject> objs, bool alertable, bool wait_all, NtWaitTimeout timeout)
        {
            SafeKernelObjectHandle[] handles = objs.Select(o => o.Handle).ToArray();
            return NtSystemCalls.NtWaitForMultipleObjects(handles.Length, handles,
                wait_all ? WaitType.WaitAll : WaitType.WaitAny, alertable, timeout.Timeout).ToNtException();
        }
    }
}
