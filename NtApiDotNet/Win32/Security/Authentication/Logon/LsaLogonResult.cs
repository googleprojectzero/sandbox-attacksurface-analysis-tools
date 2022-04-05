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

namespace NtApiDotNet.Win32.Security.Authentication.Logon
{
    /// <summary>
    /// Result from an LsaLogonUser call.
    /// </summary>
    public sealed class LsaLogonResult : IDisposable
    {
        /// <summary>
        /// The user's token.
        /// </summary>
        public NtToken Token { get; }

        /// <summary>
        /// The user's profile information. Format depends on the authentication package.
        /// </summary>
        public SafeBufferGeneric Profile { get; }

        /// <summary>
        /// The authentication ID of the logon session.
        /// </summary>
        public Luid LogonId { get; }

        /// <summary>
        /// Paged pool quota.
        /// </summary>
        public long PagedPoolLimit { get; }

        /// <summary>
        /// Non paged pool quota.
        /// </summary>
        public long NonPagedPoolLimit { get; }

        /// <summary>
        /// Minimum working set size.
        /// </summary>
        public long MinimumWorkingSetSize { get; }

        /// <summary>
        /// Maximum working set size.
        /// </summary>
        public long MaximumWorkingSetSize { get; }

        /// <summary>
        /// Page file limit.
        /// </summary>
        public long PagefileLimit { get; }

        /// <summary>
        /// Process time limit.
        /// </summary>
        public TimeSpan TimeLimit { get; }

        /// <summary>
        /// Dispose the LSA logon result.
        /// </summary>
        public void Dispose()
        {
            Token?.Dispose();
            Profile?.Dispose();
        }

        internal LsaLogonResult(NtToken token, SafeBufferGeneric profile,
            Luid logon_id, QUOTA_LIMITS quota_limits)
        {
            Token = token;
            Profile = profile;
            LogonId = logon_id;
            PagedPoolLimit = quota_limits.PagedPoolLimit.ToInt64();
            NonPagedPoolLimit = quota_limits.NonPagedPoolLimit.ToInt64();
            MinimumWorkingSetSize = quota_limits.MinimumWorkingSetSize.ToInt64();
            MaximumWorkingSetSize = quota_limits.MaximumWorkingSetSize.ToInt64();
            PagefileLimit = quota_limits.PagefileLimit.ToInt64();
            TimeLimit = TimeSpan.FromTicks(quota_limits.TimeLimit.QuadPart);
        }
    }
}
