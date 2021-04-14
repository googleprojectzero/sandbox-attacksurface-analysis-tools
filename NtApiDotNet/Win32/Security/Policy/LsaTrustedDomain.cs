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

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Class to represent an LSA trusted domain.
    /// </summary>
    public class LsaTrustedDomain : LsaObject
    {
        #region Private Members
        private readonly LsaTrustedDomainInformation _domain_info;
        #endregion

        #region Internal Members
        internal LsaTrustedDomain(SafeLsaHandle handle, LsaTrustedDomainAccessRights granted_access, string name, Sid sid, LsaTrustedDomainInformation domain_info, string system_name)
            : base(handle, granted_access, LsaPolicyUtils.LSA_TRUSTED_DOMAIN_NT_TYPE_NAME, $"LSA Trusted Domain ({(name ?? domain_info.Name)})", system_name)
        {
            _domain_info = domain_info;
            Sid = sid ?? domain_info.Sid;
            Name = name ?? domain_info.Name;
        }
        #endregion

        #region Public Members
        /// <summary>
        /// Flat name (NETBIOS) of domain.
        /// </summary>
        public string FlatName => _domain_info.FlatName;
        /// <summary>
        /// Domain SID.
        /// </summary>
        public Sid Sid { get; }
        /// <summary>
        /// Name of the domain.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Domain trust direction.
        /// </summary>
        public LsaTrustDirection TrustDirection => _domain_info.TrustDirection;
        /// <summary>
        /// Domain trust type.
        /// </summary>
        public LsaTrustType TrustType => _domain_info.TrustType;
        /// <summary>
        /// Domain trust attributes.
        /// </summary>
        public LsaTrustAttributes TrustAttributes => _domain_info.TrustAttributes;
        #endregion
    }
}
