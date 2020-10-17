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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent a VBS enclave.
    /// </summary>
    public sealed class NtEnclaveVBS : NtEnclave
    {
        #region Private Members
        private readonly SafeKernelObjectHandle _process;
        #endregion

        #region Constructors
        internal NtEnclaveVBS(SafeEnclaveHandle handle, SafeKernelObjectHandle process) 
            : base(handle, LdrEnclaveType.VBS)
        {
            _process = process.PseudoHandle ? process : NtObject.DuplicateHandle(process);
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Create a VBS enclave.
        /// </summary>
        /// <param name="process">The process to create the enclave in.</param>
        /// <param name="size">Size of the enclave.</param>
        /// <param name="flags">Flags for the enclave.</param>
        /// <param name="owner_id">Owner ID. Must be 32 bytes.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created enclave.</returns>
        public static NtResult<NtEnclaveVBS> Create(
            SafeKernelObjectHandle process,
            long size,
            LdrEnclaveVBSFlags flags,
            byte[] owner_id,
            bool throw_on_error)
        {
            if (owner_id is null)
            {
                owner_id = new byte[32];
            }

            if (owner_id.Length != 32)
                throw new ArgumentException("Owner ID must be 32 bytes.", nameof(owner_id));

            IntPtr base_address_value = IntPtr.Zero;
            var create_info = new EnclaveCreateInfoVBS()
            {
                Flags = flags,
                OwnerID = owner_id
            };

            using (var buffer = create_info.ToBuffer())
            {
                return NtLdrNative.LdrCreateEnclave(process, ref base_address_value,
                    IntPtr.Zero, new IntPtr(size), IntPtr.Zero,
                    LdrEnclaveType.VBS, buffer, buffer.Length, out int error)
                    .CreateResult(throw_on_error, () => new NtEnclaveVBS(new SafeEnclaveHandle(base_address_value), process));
            }
        }

        /// <summary>
        /// Create a VBS enclave.
        /// </summary>
        /// <param name="process">The process to create the enclave in.</param>
        /// <param name="size">Size of the enclave.</param>
        /// <param name="flags">Flags for the enclave.</param>
        /// <param name="owner_id">Owner ID. Must be 32 bytes.</param>
        /// <returns>The created enclave.</returns>
        public static NtEnclaveVBS Create(
            SafeKernelObjectHandle process,
            long size,
            LdrEnclaveVBSFlags flags,
            byte[] owner_id)
        {
            return Create(process, size, flags, owner_id, true).Result;
        }

        /// <summary>
        /// Get a procedure address in the loaded enclave.
        /// </summary>
        /// <param name="name">The name of the procedure.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The address of the procedure.</returns>
        public NtResult<long> GetProcAddress(string name, bool throw_on_error)
        {
            return NtLdr.GetProcedureAddress(_handle.DangerousGetHandle(), name, throw_on_error).Map(p => p.ToInt64());
        }

        /// <summary>
        /// Get a procedure address in the loaded enclave.
        /// </summary>
        /// <param name="name">The name of the procedure.</param>
        /// <returns>The address of the procedure.</returns>
        public long GetProcAddress(string name)
        {
            return GetProcAddress(name, true).Result;
        }

        /// <summary>
        /// Terminate the enclave.
        /// </summary>
        /// <param name="flags">Flags for the terminate.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Terminate(TerminateEnclaveFlags flags, bool throw_on_error)
        {
            return NtSystemCalls.NtTerminateEnclave(_handle, flags).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Terminate the enclave.
        /// </summary>
        /// <param name="flags">Flags for the terminate.</param>
        /// <returns>The NT status code.</returns>
        public void Terminate(TerminateEnclaveFlags flags)
        {
            Terminate(flags, true);
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Load a module into the enclave.
        /// </summary>
        /// <param name="module_name">The name of the module</param>
        /// <param name="flags">Flags or path.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status.</returns>
        public NtStatus LoadModule(string module_name, IntPtr flags, bool throw_on_error)
        {
            return NtLdrNative.LdrLoadEnclaveModule(_handle, flags, new UnicodeString(module_name)).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Load a module into the enclave.
        /// </summary>
        /// <param name="module_name">The name of the module</param>
        /// <param name="flags">Flags or path.</param>
        /// <returns>The NT status.</returns>
        public void LoadModule(string module_name, IntPtr flags)
        {
            LoadModule(module_name, flags, true);
        }

        /// <summary>
        /// Initialize the enclave.
        /// </summary>
        /// <param name="thread_count">The number of threads to create.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The number of created threads.</returns>
        public NtResult<int> Initialize(int thread_count, bool throw_on_error)
        {
            EnclaveInitInfoVBS init_info = new EnclaveInitInfoVBS()
            {
                Length = Marshal.SizeOf(typeof(EnclaveInitInfoVBS)),
                ThreadCount = thread_count
            };
            using (var buffer = init_info.ToBuffer())
            {
                return NtLdrNative.LdrInitializeEnclave(_process, _handle, buffer, 
                    buffer.Length, out int error).CreateResult(throw_on_error, () => buffer.Result.ThreadCount);
            }
        }

        /// <summary>
        /// Initialize the enclave.
        /// </summary>
        /// <param name="thread_count">The number of threads to create.</param>
        /// <returns>The number of created threads.</returns>
        public int Initialize(int thread_count)
        {
            return Initialize(thread_count, true).Result;
        }

        /// <summary>
        /// Dispose of the enclave.
        /// </summary>
        public override void Dispose()
        {
            Terminate(TerminateEnclaveFlags.WaitForThreads, false);
            base.Dispose();
            _process?.Dispose();
        }
        #endregion
    }
}
