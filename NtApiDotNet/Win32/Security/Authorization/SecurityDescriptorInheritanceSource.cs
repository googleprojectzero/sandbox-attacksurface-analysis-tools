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

using NtApiDotNet.Win32.Security.Native;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authorization
{
    /// <summary>
    /// The source of inheritance for a resource.
    /// </summary>
    public class SecurityDescriptorInheritanceSource
    {
        /// <summary>
        /// The depth between the resource and the parent.
        /// </summary>
        public int Depth { get; }

        /// <summary>
        /// The name of the ancestor.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The security descriptor if accessible.
        /// </summary>
        public SecurityDescriptor SecurityDescriptor { get; }

        /// <summary>
        /// The original ACE which was inherited.
        /// </summary>
        public Ace InheritedAce { get; }

        /// <summary>
        /// The SID of the original ACE.
        /// </summary>
        public Sid Sid { get; }

        /// <summary>
        /// Access mask as a formatted string.
        /// </summary>
        public string Access { get; }

        /// <summary>
        /// Generic access mask as a formatted string.
        /// </summary>
        public string GenericAccess { get; }

        internal SecurityDescriptorInheritanceSource(
            Ace ace, INHERITED_FROM inherited_from, SeObjectType type, 
            NtType native_type,
            bool container,
            bool query_security, bool sacl)
        {
            InheritedAce = ace;
            Sid = ace.Sid;
            if (native_type != null)
            {
                Access = NtSecurity.AccessMaskToString(ace.Mask, container
                    ? native_type.ContainerAccessRightsType
                    : native_type.AccessRightsType,
                    native_type.GenericMapping, false);
                GenericAccess = NtSecurity.AccessMaskToString(ace.Mask, container
                    ? native_type.ContainerAccessRightsType
                    : native_type.AccessRightsType,
                    native_type.GenericMapping, true);
            }
            else
            {
                Access = NtSecurity.AccessMaskToString(ace.Mask.ToGenericAccess());
                GenericAccess = NtSecurity.AccessMaskToString(ace.Mask.ToGenericAccess());
            }
            Depth = inherited_from.GenerationGap;
            Name = Marshal.PtrToStringUni(inherited_from.AncestorName);
            if (query_security && Name != null)
            {
                SecurityInformation sec_info = sacl ? SecurityInformation.All : SecurityInformation.AllNoSacl;
                var sd = Win32Security.GetSecurityInfo(Name, type, sec_info, false);
                if (sd.IsSuccess)
                {
                    SecurityDescriptor = sd.Result;
                }
            }
        }
    }
}
