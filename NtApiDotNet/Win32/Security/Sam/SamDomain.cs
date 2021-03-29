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

namespace NtApiDotNet.Win32.Security.Sam
{
    /// <summary>
    /// Class to represent a SAM domain object.
    /// </summary>
    public sealed class SamDomain : SamObject
    {
        #region Internal Members
        internal SamDomain(SafeSamHandle handle, SamDomainAccessRights granted_access, string server_name, string domain_name, Sid domain_sid)
            : base(handle, granted_access, SamUtils.SAM_DOMAIN_NT_TYPE_NAME, $"SAM Domain ({domain_name ?? domain_sid.ToString()})", server_name)
        {
            DomainId = domain_sid;
            Name = domain_name ?? string.Empty;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The domain name.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The domain SID.
        /// </summary>
        public Sid DomainId { get; }
        #endregion
    }
}
