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

using NtApiDotNet.Utilities.SafeBuffers;
using System;

namespace NtApiDotNet
{
    /// <summary>
    /// Base class to implement an enclave.
    /// </summary>
    public abstract class NtEnclave : IDisposable
    {
        #region Private Members
        private protected readonly SafeEnclaveHandle _handle;
        #endregion

        #region Public Properties
        /// <summary>
        /// The base address of the enclave.
        /// </summary>
        public long BaseAddress => _handle.DangerousGetHandle().ToInt64();

        /// <summary>
        /// The type of enclave.
        /// </summary>
        public LdrEnclaveType Type { get; }
        #endregion

        #region Public Methods

        /// <summary>
        /// Dispose of the enclave.
        /// </summary>
        public virtual void Dispose()
        {
            _handle?.Dispose();
        }

        /// <summary>
        /// Close the enclave.
        /// </summary>
        public void Close()
        {
            Dispose();
        }
        #endregion

        #region Static Methods

        /// <summary>
        /// Call a method in the enclave.
        /// </summary>
        /// <param name="routine">The routine address to call.</param>
        /// <param name="parameter">The parameter to pass to the routine.</param>
        /// <param name="wait_for_threads">True to wait for a free thread.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The return value from the call.</returns>
        public static NtResult<long> Call(long routine, long parameter, bool wait_for_threads, bool throw_on_error)
        {
            IntPtr ptr = new IntPtr(parameter);
            return NtLdrNative.LdrCallEnclave(new IntPtr(routine),
                wait_for_threads, ref ptr).CreateResult(throw_on_error, () => ptr.ToInt64());
        }

        /// <summary>
        /// Call a method in the enclave.
        /// </summary>
        /// <param name="routine">The routine address to call.</param>
        /// <param name="parameter">The parameter to pass to the routine.</param>
        /// <param name="wait_for_threads">True to wait for a free thread.</param>
        /// <returns>The return value from the call.</returns>
        public static long Call(long routine, long parameter, bool wait_for_threads)
        {
            return Call(routine, parameter, wait_for_threads, true).Result;
        }
        #endregion

        #region Constructors
        private protected NtEnclave(SafeEnclaveHandle handle, LdrEnclaveType type)
        {
            _handle = handle;
            Type = type;
        }
        #endregion
    }
}
