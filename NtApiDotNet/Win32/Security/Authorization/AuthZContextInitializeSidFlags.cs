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

namespace NtApiDotNet.Win32.Security.Authorization
{
    /// <summary>
    /// Flags to initialize a client context from a SID.
    /// </summary>
    public enum AuthZContextInitializeSidFlags
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Skip gathering token groups.
        /// </summary>
        SkipTokenGroups = 2,
        /// <summary>
        /// Require S4U logon.
        /// </summary>
        RequireS4ULogon = 4,
        /// <summary>
        /// Computer token privileges.
        /// </summary>
        ComputePrivileges = 8
    }
}
