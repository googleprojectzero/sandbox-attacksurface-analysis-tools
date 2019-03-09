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

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent an Access Control Entry for a Mandatory Label.
    /// </summary>
    public sealed class MandatoryLabelAce : Ace
    {
        internal MandatoryLabelAce() : base(AceType.MandatoryLabel)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="flags">Flags for the ACE.</param>
        /// <param name="policy">The mandatory label policy.</param>
        /// <param name="integrity_level">The integrity level.</param>
        public MandatoryLabelAce(AceFlags flags, MandatoryLabelPolicy policy, TokenIntegrityLevel integrity_level)
            : this(flags, policy, NtSecurity.GetIntegritySid(integrity_level))
        {
        }

        /// <summary>
        /// Constructor from a raw integrity level.
        /// </summary>
        /// <param name="flags">Flags for the ACE.</param>
        /// <param name="policy">The mandatory label policy.</param>
        /// <param name="sid">The integrity level sid.</param>
        public MandatoryLabelAce(AceFlags flags, MandatoryLabelPolicy policy, Sid sid)
            : base(AceType.MandatoryLabel, flags, policy, sid)
        {
        }

        /// <summary>
        /// The policy for the mandatory label.
        /// </summary>
        public MandatoryLabelPolicy Policy
        {
            get
            {
                return Mask.ToMandatoryLabelPolicy();
            }
            set
            {
                Mask = value;
            }
        }

        /// <summary>
        /// Get or set the integrity level
        /// </summary>
        public TokenIntegrityLevel IntegrityLevel
        {
            get
            {
                return NtSecurity.GetIntegrityLevel(Sid);
            }
            set
            {
                Sid = NtSecurity.GetIntegritySid(value);
            }
        }

        /// <summary>
        /// Convert ACE to a string.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"Mandatory Label - Flags {Flags} - Policy {Policy} - IntegrityLevel {IntegrityLevel}";
        }
    }
}
