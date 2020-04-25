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
using NtApiDotNet.Win32.Security;
using System;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent the state of a token privilege
    /// </summary>
    public sealed class TokenPrivilege
    {
        private static Luid LookupPrivilegeLuid(string name)
        {
            if (!Win32NativeMethods.LookupPrivilegeValue(".", name, out Luid luid))
            {
                throw new NtException(NtStatus.STATUS_NO_SUCH_PRIVILEGE);
            }
            return luid;
        }

        /// <summary>
        /// Privilege attributes
        /// </summary>
        public PrivilegeAttributes Attributes { get; set; }

        /// <summary>
        /// Privilege LUID
        /// </summary>
        public Luid Luid { get; }

        /// <summary>
        /// Get the token privilege value enum.
        /// </summary>
        public TokenPrivilegeValue Value => (TokenPrivilegeValue)Luid.LowPart;

        /// <summary>
        /// Get the name of the privilege
        /// </summary>
        /// <returns>The privilege name</returns>
        public string Name
        {
            get
            {
                if ((Luid.HighPart == 0) && Enum.IsDefined(typeof(TokenPrivilegeValue), Luid.LowPart))
                {
                    return Enum.GetName(typeof(TokenPrivilegeValue), Luid.LowPart);
                }
                else
                {
                    Luid luid = Luid;
                    StringBuilder builder = new StringBuilder(256);
                    int name_length = 256;
                    if (Win32NativeMethods.LookupPrivilegeName(null, ref luid, builder, ref name_length))
                    {
                        return builder.ToString();
                    }
                    return $"UnknownPrivilege-{luid}";
                }
            }
        }

        /// <summary>
        /// Get the display name/description of the privilege
        /// </summary>
        /// <returns>The display name</returns>
        public string DisplayName => Win32Security.LookupPrivilegeDisplayName(null, Name);

        /// <summary>
        /// Get whether privilege is enabled
        /// </summary>
        public bool Enabled
        {
            get { return Attributes.HasFlag(PrivilegeAttributes.Enabled); }
        }

        /// <summary>
        /// Get whether privilege is enabled
        /// </summary>
        public bool UsedForAccess
        {
            get { return Attributes.HasFlag(PrivilegeAttributes.UsedForAccess); }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="luid">The privilege LUID</param>
        /// <param name="attribute">The privilege attributes</param>
        public TokenPrivilege(Luid luid, PrivilegeAttributes attribute)
        {
            Luid = luid;
            Attributes = attribute;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The privilege value</param>
        /// <param name="attribute">The privilege attributes</param>
        public TokenPrivilege(TokenPrivilegeValue value, PrivilegeAttributes attribute)
            : this(new Luid((uint)value, 0), attribute)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">The privilege name.</param>
        /// <param name="attribute">The privilege attributes</param>
        public TokenPrivilege(string name, PrivilegeAttributes attribute)
            : this(LookupPrivilegeLuid(name), attribute)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">The privilege name.</param>
        public TokenPrivilege(string name) : this(name, PrivilegeAttributes.Enabled)
        {
        }

        /// <summary>
        /// Conver to a string
        /// </summary>
        /// <returns>The privilege name.</returns>
        public override string ToString()
        {
            return Name;
        }
    }
}
