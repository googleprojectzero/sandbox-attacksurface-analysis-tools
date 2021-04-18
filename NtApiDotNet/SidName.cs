//  Copyright 2019 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet
{
    /// <summary>
    /// Source for a SID name.
    /// </summary>
    public enum SidNameSource
    {
        /// <summary>
        /// SDDL string.
        /// </summary>
        Sddl,
        /// <summary>
        /// LSASS lookup.
        /// </summary>
        Account,
        /// <summary>
        /// Named capability.
        /// </summary>
        Capability,
        /// <summary>
        /// Package name SID.
        /// </summary>
        Package,
        /// <summary>
        /// From a process trust level.
        /// </summary>
        ProcessTrust,
        /// <summary>
        /// Well known SID.
        /// </summary>
        WellKnown,
        /// <summary>
        /// Scoped policy SID.
        /// </summary>
        ScopedPolicyId,
        /// <summary>
        /// Manually added name.
        /// </summary>
        Manual
    }

    /// <summary>
    /// Represents a name for a SID.
    /// </summary>
    public sealed class SidName
    {
        private readonly Sid _sid;

        /// <summary>
        /// The qualified name of the SID. Either the combination of
        /// Domain and Name or the SDDL SID.
        /// </summary>
        public string QualifiedName { get; }

        /// <summary>
        /// The domain name, if present.
        /// </summary>
        public string Domain { get; }

        /// <summary>
        /// The user name.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The source of name.
        /// </summary>
        public SidNameSource Source { get; }

        /// <summary>
        /// The use of the name.
        /// </summary>
        public SidNameUse NameUse { get; }

        /// <summary>
        /// The SDDL format of the SID.
        /// </summary>
        public string Sddl { get; }

        /// <summary>
        /// Used for caching. Indicates the lookup name was denied rather than not available.
        /// </summary>
        internal bool LookupDenied { get; }

        internal Sid Sid => _sid;

        internal SidName(Sid sid, string domain, string name, SidNameSource source, SidNameUse name_use, bool lookup_denied)
        {
            Domain = domain;
            Name = name;
            if (string.IsNullOrEmpty(domain))
                QualifiedName = Name;
            else
                QualifiedName = $"{Domain}\\{Name}";
            Source = source;
            NameUse = name_use;
            _sid = sid;
            Sddl = sid.ToString();
            LookupDenied = lookup_denied;
        }
    }

#pragma warning restore 1591
}
