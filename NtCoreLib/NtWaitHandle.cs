//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Threading;
using System.Threading.Tasks;

namespace NtApiDotNet
{
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
            using (SafeKernelObjectHandle handle = NtObject.DuplicateHandle(obj.Handle))
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
}
