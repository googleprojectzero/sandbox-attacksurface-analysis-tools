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

using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

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
            IntPtr[] Handles, WaitType WaitType, bool Alertable, LargeInteger Timeout);
    }
#pragma warning disable 1591

    /// <summary>
    /// Class to represent an NT timeout
    /// </summary>
    public sealed class NtWaitTimeout
    {
        const long units_per_ms = 10000;

        internal NtWaitTimeout()
        {
        }

        internal NtWaitTimeout(long value)
        {
            Timeout = new LargeInteger(value);
        }

        /// <summary>
        /// Get a timeout which will wait indefinitely.
        /// </summary>
        public static NtWaitTimeout Infinite { get { return new NtWaitTimeout(); } }
        
        /// <summary>
        /// Get a relative timeout in seconds.
        /// </summary>
        /// <param name="seconds">The number of seconds to wait.</param>
        /// <returns>An instance of the timeout class.</returns>
        public static NtWaitTimeout FromSeconds(int seconds)
        {
            return FromMilliseconds(seconds * 1000L);
        }

        /// <summary>
        /// Get a relative timeout in milliseconds.
        /// </summary>
        /// <param name="ms">The number of milliseconds to wait.</param>
        /// <returns>An instance of the timeout class.</returns>
        public static NtWaitTimeout FromMilliseconds(long ms)
        {
            return new NtWaitTimeout(-(ms * units_per_ms));
        }

        /// <summary>
        /// Get an absolute time out from system start.
        /// </summary>
        /// <param name="absolute">The absolute time to wait until.</param>
        /// <returns>An instance of the timeout class.</returns>
        public static NtWaitTimeout FromAbsolute(long absolute)
        {
            return new NtWaitTimeout(absolute);
        }

        /// <summary>
        /// Get a relative time out from the current time.
        /// </summary>
        /// <param name="relative">The relative time to wait in units of 100ns.</param>
        /// <returns>An instance of the timeout class.</returns>
        public static NtWaitTimeout FromRelative(long relative)
        {
            return new NtWaitTimeout(-relative);
        }
        
        internal LargeInteger Timeout { get; private set; }
    }

    /// <summary>
    /// A .NET wait handle to use for interop.
    /// </summary>
    public sealed class NtWaitHandle : WaitHandle
    {
        /// <summary>
        /// Create a .NET wait handle from an object.
        /// </summary>
        /// <param name="obj">The object to create the wait handle on</param>
        internal NtWaitHandle(NtObject obj)
        {
            using (SafeKernelObjectHandle handle = obj.DuplicateHandle())
            {
                SafeWaitHandle = new SafeWaitHandle(handle.DangerousGetHandle(), true);
                handle.SetHandleAsInvalid();
            }
        }

        /// <summary>
        /// Wait asynchronously for the handle to be signaled.
        /// </summary>
        /// <param name="timeout_ms">Timeout in milliseconds.</param>
        /// <param name="cancellation_token">Cancellation token for wait.</param>
        /// <returns>A task to wait on. If result is true then event was signaled.</returns>
        public Task<bool> WaitAsync(int timeout_ms, CancellationToken cancellation_token)
        {
            TaskCompletionSource<bool> tcs = new TaskCompletionSource<bool>();
            if (cancellation_token.IsCancellationRequested)
            {
                tcs.SetCanceled();
                return tcs.Task;
            }

            RegisteredWaitHandle rwh = ThreadPool.RegisterWaitForSingleObject(this,
                (o, b) => tcs.TrySetResult(!b), null, timeout_ms, true);

            Task<bool> task = tcs.Task;
            // Unregister event wait.
            task.ContinueWith((a) => rwh.Unregister(null));
            if (cancellation_token.CanBeCanceled)
            {
                CancellationTokenRegistration reg = 
                    cancellation_token.Register(() => tcs.TrySetCanceled());
                task.ContinueWith((a) => reg.Dispose());
            }

            return task;
        }

        /// <summary>
        /// Wait asynchronously for the handle to be signaled.
        /// </summary>
        /// <param name="timeout_ms">Timeout in milliseconds.</param>
        /// <returns>A task to wait on. If result is true then event was signaled.</returns>
        public Task<bool> WaitAsync(int timeout_ms)
        {
            return WaitAsync(timeout_ms, CancellationToken.None);
        }

        /// <summary>
        /// Wait asynchronously for the handle to be signaled.
        /// Will wait an infinite time.
        /// </summary>
        /// <returns>A task to wait on.</returns>
        public Task WaitAsync()
        {
            return WaitAsync(-1);
        }
    }

    /// <summary>
    /// Native Wait methods.
    /// </summary>
    public static class NtWait
    {
        /// <summary>
        /// Wait on a single object to become signalled
        /// </summary>
        /// <param name="obj">The object to wait on</param>
        /// <param name="alertable">Whether the thread should be alerable</param>
        /// <param name="timeout">The timeout to wait for</param>
        /// <returns>The success status of the wait, such as STATUS_SUCCESS or STATUS_TIMEOUT</returns>
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
        /// <returns>The success status of the wait, such as STATUS_WAIT_OBJECT_0 or STATUS_TIMEOUT</returns>
        public static NtStatus Wait(IEnumerable<NtObject> objs, bool alertable, bool wait_all, NtWaitTimeout timeout)
        {
            IntPtr[] handles = objs.Select(o => o.Handle.DangerousGetHandle()).ToArray();
            return NtSystemCalls.NtWaitForMultipleObjects(handles.Length, handles,
                wait_all ? WaitType.WaitAll : WaitType.WaitAny, alertable, timeout.Timeout).ToNtException();
        }
    }
}
