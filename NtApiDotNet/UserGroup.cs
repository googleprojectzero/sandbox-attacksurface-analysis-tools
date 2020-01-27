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
    /// Class to represent a user group
    /// </summary>
    public sealed class UserGroup
    {
        /// <summary>
        /// The SID of the user group
        /// </summary>
        public Sid Sid { get; }

        /// <summary>
        /// The attributes of the user group
        /// </summary>
        public GroupAttributes Attributes { get; }

        /// <summary>
        /// Get whether the user group is enabled
        /// </summary>
        public bool Enabled => (Attributes & GroupAttributes.Enabled) == GroupAttributes.Enabled;

        /// <summary>
        /// Get whether the user group is mandatory
        /// </summary>
        public bool Mandatory => (Attributes & GroupAttributes.Mandatory) == GroupAttributes.Mandatory;

        /// <summary>
        /// Get whether the user group is used for deny only
        /// </summary>
        public bool DenyOnly => (Attributes & GroupAttributes.UseForDenyOnly) == GroupAttributes.UseForDenyOnly;

        /// <summary>
        /// Get the resolved name of the SID.
        /// </summary>
        public string Name => Sid.Name;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="sid">The SID</param>
        /// <param name="attributes">The attributes</param>
        public UserGroup(Sid sid, GroupAttributes attributes)
        {
            Sid = sid;
            Attributes = attributes;
        }

        /// <summary>
        /// Constructor from a SID.
        /// </summary>
        /// <param name="sid">The SID</param>
        public UserGroup(Sid sid)
            : this(sid, GroupAttributes.None)
        {
        }

        private static Sid LookupAccountSid(string name)
        {
            var sid = NtSecurity.SidFromSddl(name, false);
            if (sid.IsSuccess)
                return sid.Result;
            return NtSecurity.LookupAccountName(name);
        }

        /// <summary>
        /// Constructor from a SID or account name.
        /// </summary>
        /// <param name="name">The SID or account name.</param>
        public UserGroup(string name)
            : this(LookupAccountSid(name))
        {
        }

        /// <summary>
        /// Convert to a string
        /// </summary>
        /// <returns>The account name if available or the SDDL SID</returns>
        public override string ToString()
        {
            string ret = null;
            try
            {
                ret = Sid.Name;
            }
            catch
            {
            }

            return ret ?? Sid.ToString();
        }
    }
}
