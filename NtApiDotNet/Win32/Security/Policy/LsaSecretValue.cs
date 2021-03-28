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
using System;

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Class to represent an LSA secret value.
    /// </summary>
    public sealed class LsaSecretValue
    {
        /// <summary>
        /// The current value of the secret.
        /// </summary>
        public byte[] CurrentValue { get; }

        /// <summary>
        /// The set time for the current value.
        /// </summary>
        public DateTime CurrentValueSetTime { get; }

        /// <summary>
        /// The old value of the secret.
        /// </summary>
        public byte[] OldValue { get; }

        /// <summary>
        /// The set time for the old value.
        /// </summary>
        public DateTime OldValueSetTime { get; }

        internal LsaSecretValue(SafeLsaMemoryBuffer current_value, LargeInteger current_value_set_time,
            SafeLsaMemoryBuffer old_value, LargeInteger old_value_set_time)
        {
            if (!current_value.IsInvalid)
            {
                CurrentValue = current_value.GetUnicodeString().ToArray();
                CurrentValueSetTime = current_value_set_time.ToDateTime();
            }
            else
            {
                CurrentValue = new byte[0];
                CurrentValueSetTime = DateTime.MinValue;
            }

            if (!old_value.IsInvalid)
            {
                OldValue = old_value.GetUnicodeString().ToArray();
                OldValueSetTime = old_value_set_time.ToDateTime();
            }
            else
            {
                OldValue = new byte[0];
                OldValueSetTime = DateTime.MinValue;
            }
        }
    }
}
