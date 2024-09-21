//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Win32;
using System;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to scope a firewall transaction.
    /// </summary>
    public sealed class FirewallTransaction : IDisposable
    {
        private SafeFwpmEngineHandle _handle;

        private NtStatus Invoke(Func<SafeFwpmEngineHandle, Win32Error> f, bool throw_on_error)
        {
            if (_handle == null)
                return NtStatus.STATUS_SUCCESS;
            try
            {
                return f(_handle).ToNtException(throw_on_error);
            }
            finally
            {
                _handle = null;
            }
        }

        internal FirewallTransaction(SafeFwpmEngineHandle handle)
        {
            _handle = handle;
        }

        /// <summary>
        /// Abort the transaction.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Abort(bool throw_on_error)
        {
            return Invoke(FirewallNativeMethods.FwpmTransactionAbort0, throw_on_error);
        }

        /// <summary>
        /// Abort the transaction.
        /// </summary>
        public void Abort()
        {
            Abort(true);
        }

        /// <summary>
        /// Commit the transaction.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Commit(bool throw_on_error)
        {
            return Invoke(FirewallNativeMethods.FwpmTransactionCommit0, throw_on_error);
        }

        /// <summary>
        /// Commit the transaction.
        /// </summary>
        public void Commit()
        {
            Commit(true);
        }

        /// <summary>
        /// Dispose the transaction. Will ca
        /// </summary>
        public void Dispose()
        {
            Abort(false);
        }
    }
}
