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

using System;

namespace NtApiDotNet.Win32.Security.Audit
{
    /// <summary>
    /// Audit policy flags.
    /// </summary>
    [Flags]
    public enum AuditPolicyFlags
    {
        /// <summary>
        /// Set unchanged.
        /// </summary>
        Unchanged = 0,
        /// <summary>
        /// Audit on success.
        /// </summary>
        Success = 1,
        /// <summary>
        /// Audit on failure.
        /// </summary>
        Failure = 2,
        /// <summary>
        /// Audit nothing.
        /// </summary>
        None = 4,
    }

    /// <summary>
    /// Per user policy flags.
    /// </summary>
    [Flags]
    public enum AuditPerUserPolicyFlags
    {
        /// <summary>
        /// Set unchanged.
        /// </summary>
        Unchanged = 0,
        /// <summary>
        /// Audit on success included.
        /// </summary>
        SuccessInclude = 1,
        /// <summary>
        /// Audit on success excluded.
        /// </summary>
        SuccessExclude = 2,
        /// <summary>
        /// Audit on failure included.
        /// </summary>
        FailureInclude = 4,
        /// <summary>
        /// Audit on failure excluded.
        /// </summary>
        FailureExclude = 8,
        /// <summary>
        /// Audit nothing.
        /// </summary>
        None = 0x10
    }
}
