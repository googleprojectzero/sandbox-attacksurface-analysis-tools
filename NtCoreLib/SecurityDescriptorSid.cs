//  Copyright 2016 Google Inc. All Rights Reserved.
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
    /// A security descriptor SID which maintains defaulted state.
    /// </summary>
    public sealed class SecurityDescriptorSid
    {
        #region Public Properties
        /// <summary>
        /// The SID.
        /// </summary>
        public Sid Sid { get; set; }

        /// <summary>
        /// Indicates whether the SID was defaulted or not.
        /// </summary>
        public bool Defaulted { get; set; }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor from existing SID.
        /// </summary>
        /// <param name="sid">The SID.</param>
        /// <param name="defaulted">Whether the SID was defaulted or not.</param>
        public SecurityDescriptorSid(Sid sid, bool defaulted)
        {
            Sid = sid;
            Defaulted = defaulted;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Convert to a string.
        /// </summary>
        /// <returns>The string form of the SID</returns>
        public override string ToString()
        {
            return $"{Sid} - Defaulted: {Defaulted}";
        }

        /// <summary>
        /// Clone the security descriptor SID.
        /// </summary>
        /// <returns>The cloned SID.</returns>
        public SecurityDescriptorSid Clone()
        {
            return new SecurityDescriptorSid(Sid, Defaulted);
        }

        #endregion
    }
}
