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

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Information for a trusted domain.
    /// </summary>
    public struct LsaTrustedDomainInformation
    {
        /// <summary>
        /// DNS name of domain.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Flat name (NETBIOS) of domain.
        /// </summary>
        public string FlatName { get; }
        /// <summary>
        /// Domain SID.
        /// </summary>
        public Sid Sid { get; }
        /// <summary>
        /// Domain trust direction.
        /// </summary>
        public LsaTrustDirection TrustDirection { get; }
        /// <summary>
        /// Domain trust type.
        /// </summary>
        public LsaTrustType TrustType { get; }
        /// <summary>
        /// Domain trust attributes.
        /// </summary>
        public LsaTrustAttributes TrustAttributes { get; }

        internal LsaTrustedDomainInformation(TRUSTED_DOMAIN_INFORMATION_EX info)
        {
            Name = info.Name.ToString();
            FlatName = info.FlatName.ToString();
            Sid = new Sid(info.Sid);
            TrustDirection = info.TrustDirection;
            TrustType = info.TrustType;
            TrustAttributes = info.TrustAttributes;
        }
    }
}
