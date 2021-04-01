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

using NtApiDotNet.Win32.Security.Native;
using System;

namespace NtApiDotNet.Win32.Security.Sam
{
    /// <summary>
    /// The domain password policy.
    /// </summary>
    public struct SamDomainPasswordInformation
    {
        /// <summary>
        /// Minimum password length.
        /// </summary>
        public int MinimumLength { get; }
        /// <summary>
        /// Password history length.
        /// </summary>
        public int HistoryLength { get; }
        /// <summary>
        /// Password properties flags.
        /// </summary>
        public SamDomainPasswordPropertyFlags Properties;
        /// <summary>
        /// Maximum password age.
        /// </summary>
        public TimeSpan MaximumAge;
        /// <summary>
        /// Minimum password age.
        /// </summary>
        public TimeSpan MinimumAge;

        internal SamDomainPasswordInformation(DOMAIN_PASSWORD_INFORMATION info)
        {
            MinimumLength = info.MinPasswordLength;
            HistoryLength = info.PasswordHistoryLength;
            Properties = (SamDomainPasswordPropertyFlags)info.PasswordProperties;
            MaximumAge = TimeSpan.FromTicks(-info.MaxPasswordAge.QuadPart);
            MinimumAge = TimeSpan.FromTicks(-info.MinPasswordAge.QuadPart);
        }
    }
}
