//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Class to represent an LSA secret.
    /// </summary>
    public sealed class LsaSecret : LsaObject
    {
        #region Internal Members
        internal LsaSecret(SafeLsaHandle handle, LsaSecretAccessRights granted_access, string name, string system_name) 
            : base(handle, granted_access, LsaPolicyUtils.LSA_SECRET_NT_TYPE_NAME, $"LSA Secret ({name})", system_name)
        {
        }
        #endregion

        #region Public Methods

        /// <summary>
        /// Query the value of the secret.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The value of the secret.</returns>
        public NtResult<LsaSecretValue> Query(bool throw_on_error)
        {
            LargeInteger current_value_set_time = new LargeInteger();
            LargeInteger old_value_set_time = new LargeInteger();
            var status = SecurityNativeMethods.LsaQuerySecret(Handle, out SafeLsaMemoryBuffer current_value, 
                current_value_set_time, out SafeLsaMemoryBuffer old_value, old_value_set_time);
            if (!status.IsSuccess())
            {
                return status.CreateResultFromError<LsaSecretValue>(throw_on_error);
            }
            using(current_value)
            {
                using (old_value)
                {
                    return new LsaSecretValue(current_value, current_value_set_time, old_value, old_value_set_time).CreateResult();
                }
            }
        }

        /// <summary>
        /// Query the value of the secret.
        /// </summary>
        /// <returns>The value of the secret.</returns>
        public LsaSecretValue Query()
        {
            return Query(true).Result;
        }

        /// <summary>
        /// Query the current value of the secret.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The current value of the secret.</returns>
        public NtResult<byte[]> QueryCurrent(bool throw_on_error)
        {
            return Query(throw_on_error).Map(v => v.CurrentValue);
        }

        /// <summary>
        /// Query the current value of the secret.
        /// </summary>
        /// <returns>The current value of the secret.</returns>
        public byte[] QueryCurrent()
        {
            return QueryCurrent(true).Result;
        }

        /// <summary>
        /// Query the old value of the secret.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The old value of the secret.</returns>
        public NtResult<byte[]> QueryOld(bool throw_on_error)
        {
            return Query(throw_on_error).Map(v => v.OldValue);
        }

        /// <summary>
        /// Query the old value of the secret.
        /// </summary>
        /// <returns>The old value of the secret.</returns>
        public byte[] QueryOld()
        {
            return QueryCurrent(true).Result;
        }

        /// <summary>
        /// Set the value of the secret.
        /// </summary>
        /// <param name="current_value">The current value to set.</param>
        /// <param name="old_value">The old value to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Set(byte[] current_value, byte[] old_value, bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var current_value_buffer = list.AddResource(current_value.ToUnicodeStringBuffer());
                var old_value_buffer = list.AddResource(old_value.ToUnicodeStringBuffer());
                return SecurityNativeMethods.LsaSetSecret(Handle, current_value_buffer, old_value_buffer).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Set the value of the secret.
        /// </summary>
        /// <param name="current_value">The current value to set.</param>
        /// <param name="old_value">The old value to set.</param>
        public void Set(byte[] current_value, byte[] old_value)
        {
            Set(current_value, old_value, true);
        }

        #endregion
    }
}
