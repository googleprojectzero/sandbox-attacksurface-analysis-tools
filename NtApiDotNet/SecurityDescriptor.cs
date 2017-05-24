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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Security descriptor control flags.
    /// </summary>
    [Flags]
    public enum SecurityDescriptorControl : ushort
    {
#pragma warning disable 1591
        OwnerDefaulted = 0x0001,
        GroupDefaulted = 0x0002,
        DaclPresent = 0x0004,
        DaclDefaulted = 0x0008,
        SaclPresent = 0x0010,
        SaclDefaulted = 0x0020,
        DaclAutoInheritReq = 0x0100,
        SaclAutoInheritReq = 0x0200,
        DaclAutoInherited = 0x0400,
        SaclAutoInherited = 0x0800,
        DaclProtected = 0x1000,
        SaclProtected = 0x2000,
        RmControlValid = 0x4000,
        SelfRelative = 0x8000,
        ValidControlSetMask = DaclAutoInheritReq | SaclAutoInheritReq
        | DaclAutoInherited | SaclAutoInherited | DaclProtected | SaclProtected
#pragma warning restore 1591
    }

    /// <summary>
    /// A security descriptor SID which maintains defaulted state.
    /// </summary>
    public sealed class SecurityDescriptorSid
    {
        /// <summary>
        /// The SID.
        /// </summary>
        public Sid Sid { get; private set; }

        /// <summary>
        /// Indicates whether the SID was defaulted or not.
        /// </summary>
        public bool Defaulted { get; private set; }

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

        /// <summary>
        /// Convert to a string.
        /// </summary>
        /// <returns>The string form of the SID</returns>
        public override string ToString()
        {
            return String.Format("{0} - Defaulted: {1}", Sid, Defaulted);
        }
    }

    /// <summary>
    /// Security descriptor.
    /// </summary>
    public sealed class SecurityDescriptor
    {
        /// <summary>
        /// Discretionary access control list (can be null)
        /// </summary>
        public Acl Dacl { get; set; }
        /// <summary>
        /// Systerm access control list (can be null)
        /// </summary>
        public Acl Sacl { get; set; }
        /// <summary>
        /// Owner (can be null)
        /// </summary>
        public SecurityDescriptorSid Owner { get; set; }
        /// <summary>
        /// Group (can be null)
        /// </summary>
        public SecurityDescriptorSid Group { get; set; }
        /// <summary>
        /// Control flags
        /// </summary>
        public SecurityDescriptorControl Control { get; set; }
        /// <summary>
        /// Revision value
        /// </summary>
        public uint Revision { get; set; }

        private delegate NtStatus QuerySidFunc(SafeBuffer SecurityDescriptor, out IntPtr sid, out bool defaulted);

        private delegate NtStatus QueryAclFunc(SafeBuffer SecurityDescriptor, out bool acl_present, out IntPtr acl, out bool acl_defaulted);

        private static SecurityDescriptorSid QuerySid(SafeBuffer buffer, QuerySidFunc func)
        {
            IntPtr sid;
            bool sid_defaulted;
            func(buffer, out sid, out sid_defaulted).ToNtException();
            if (sid != IntPtr.Zero)
            {
                return new SecurityDescriptorSid(new Sid(sid), sid_defaulted);
            }
            return null;
        }

        private static Acl QueryAcl(SafeBuffer buffer, QueryAclFunc func)
        {
            IntPtr acl;
            bool acl_present;
            bool acl_defaulted;

            func(buffer, out acl_present, out acl, out acl_defaulted).ToNtException();
            if (!acl_present)
            {
                return null;
            }

            return new Acl(acl, acl_defaulted);
        }

        private void ParseSecurityDescriptor(SafeBuffer buffer)
        {
            if (!NtRtl.RtlValidSecurityDescriptor(buffer))
            {
                throw new ArgumentException("Invalid security descriptor");
            }

            Owner = QuerySid(buffer, NtRtl.RtlGetOwnerSecurityDescriptor);
            Group = QuerySid(buffer, NtRtl.RtlGetGroupSecurityDescriptor);
            Dacl = QueryAcl(buffer, NtRtl.RtlGetDaclSecurityDescriptor);
            Sacl = QueryAcl(buffer, NtRtl.RtlGetSaclSecurityDescriptor);
            SecurityDescriptorControl control;
            uint revision;
            NtRtl.RtlGetControlSecurityDescriptor(buffer, out control, out revision).ToNtException();
            Control = control;
            Revision = revision;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public SecurityDescriptor()
        {
            Revision = 1;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="security_descriptor">Binary form of security descriptor</param>
        public SecurityDescriptor(byte[] security_descriptor)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(security_descriptor))
            {
                ParseSecurityDescriptor(buffer);
            }
        }

        /// <summary>
        /// Constructor from a token default DACL and ownership values.
        /// </summary>
        /// <param name="token">The token to use for its default DACL</param>
        public SecurityDescriptor(NtToken token) : this()
        {
            Owner = new SecurityDescriptorSid(token.Owner, true);
            Group = new SecurityDescriptorSid(token.PrimaryGroup, true);
            Dacl = token.DefaultDalc;
            if (token.IntegrityLevel< TokenIntegrityLevel.Medium)
            {
                Sacl = new Acl();
                Sacl.Add(new Ace(AceType.MandatoryLabel, AceFlags.None, 1, token.IntegrityLevelSid.Sid));
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="base_object">Base object for security descriptor</param>
        /// <param name="token">Token for determining user rights</param>
        /// <param name="is_directory">True if a directory security descriptor</param>
        public SecurityDescriptor(NtObject base_object, NtToken token, bool is_directory) : this()
        {
            if ((base_object == null) && (token == null))
            {
                throw new ArgumentNullException();
            }

            SecurityDescriptor parent_sd = null;
            if (base_object != null)
            {
                parent_sd = base_object.SecurityDescriptor;
            }

            SecurityDescriptor creator_sd = null;
            if (token != null)
            {
                creator_sd = new SecurityDescriptor();
                creator_sd.Owner = new SecurityDescriptorSid(token.Owner, false);
                creator_sd.Group = new SecurityDescriptorSid(token.PrimaryGroup, false);
                creator_sd.Dacl = token.DefaultDalc;
            }

            NtType type = NtType.GetTypeByName(base_object.NtTypeName);

            SafeBuffer parent_sd_buffer = SafeHGlobalBuffer.Null;
            SafeBuffer creator_sd_buffer = SafeHGlobalBuffer.Null;
            SafeSecurityObjectHandle security_obj = null;
            try
            {
                if (parent_sd != null)
                {
                    parent_sd_buffer = parent_sd.ToSafeBuffer();
                }
                if (creator_sd != null)
                {
                    creator_sd_buffer = creator_sd.ToSafeBuffer();
                }

                GenericMapping mapping = type.GenericMapping;
                NtRtl.RtlNewSecurityObject(parent_sd_buffer, creator_sd_buffer, out security_obj, is_directory,
                    token != null ? token.Handle : SafeKernelObjectHandle.Null, ref mapping).ToNtException();
                ParseSecurityDescriptor(security_obj);
            }
            finally
            {
                parent_sd_buffer?.Close();
                creator_sd_buffer?.Close();
                security_obj?.Close();
            }
        }

        /// <summary>
        /// Constructor from an SDDL string
        /// </summary>
        /// <param name="sddl">The SDDL string</param>
        /// <exception cref="NtException">Thrown if invalid SDDL</exception>
        public SecurityDescriptor(string sddl)
            : this(NtSecurity.SddlToSecurityDescriptor(sddl))
        {
        }

        /// <summary>
        /// Convert security descriptor to a byte array
        /// </summary>
        /// <returns>The binary security descriptor</returns>
        public byte[] ToByteArray()
        {
            SafeStructureInOutBuffer<SecurityDescriptorStructure> sd_buffer = null;
            SafeHGlobalBuffer dacl_buffer = null;
            SafeHGlobalBuffer sacl_buffer = null;
            SafeSidBufferHandle owner_buffer = null;
            SafeSidBufferHandle group_buffer = null;

            try
            {
                sd_buffer = new SafeStructureInOutBuffer<SecurityDescriptorStructure>();
                NtRtl.RtlCreateSecurityDescriptor(sd_buffer, Revision).ToNtException();
                SecurityDescriptorControl control = Control & SecurityDescriptorControl.ValidControlSetMask;
                NtRtl.RtlSetControlSecurityDescriptor(sd_buffer, control, control).ToNtException();
                if (Dacl != null)
                {
                    if (!Dacl.NullAcl)
                    {
                        dacl_buffer = new SafeHGlobalBuffer(Dacl.ToByteArray());
                    }
                    else
                    {
                        dacl_buffer = new SafeHGlobalBuffer(IntPtr.Zero, 0, false);
                    }

                    NtRtl.RtlSetDaclSecurityDescriptor(sd_buffer, true, dacl_buffer.DangerousGetHandle(), Dacl.Defaulted).ToNtException();
                }
                if (Sacl != null)
                {
                    if (!Sacl.NullAcl)
                    {
                        sacl_buffer = new SafeHGlobalBuffer(Sacl.ToByteArray());
                    }
                    else
                    {
                        sacl_buffer = new SafeHGlobalBuffer(IntPtr.Zero, 0, false);
                    }

                    NtRtl.RtlSetSaclSecurityDescriptor(sd_buffer, true, sacl_buffer.DangerousGetHandle(), Sacl.Defaulted).ToNtException();
                }
                if (Owner != null)
                {
                    owner_buffer = Owner.Sid.ToSafeBuffer();
                    NtRtl.RtlSetOwnerSecurityDescriptor(sd_buffer, owner_buffer.DangerousGetHandle(), Owner.Defaulted);
                }
                if (Group != null)
                {
                    group_buffer = Group.Sid.ToSafeBuffer();
                    NtRtl.RtlSetGroupSecurityDescriptor(sd_buffer, group_buffer.DangerousGetHandle(), Group.Defaulted);
                }

                int total_length = 0;
                NtStatus status = NtRtl.RtlAbsoluteToSelfRelativeSD(sd_buffer, new SafeHGlobalBuffer(IntPtr.Zero, 0, false), ref total_length);
                if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
                {
                    status.ToNtException();
                }

                using (SafeHGlobalBuffer relative_sd = new SafeHGlobalBuffer(total_length))
                {
                    NtRtl.RtlAbsoluteToSelfRelativeSD(sd_buffer, relative_sd, ref total_length).ToNtException();
                    return relative_sd.ToArray();
                }
            }
            finally
            {
                sd_buffer?.Close();
                dacl_buffer?.Close();
                sacl_buffer?.Close();
                owner_buffer?.Close();
                group_buffer?.Close();
            }
        }

        /// <summary>
        /// Convert security descriptor to SDDL string
        /// </summary>
        /// <param name="security_information">The parts of the security descriptor to return</param>
        /// <returns>The SDDL string</returns>
        public string ToSddl(SecurityInformation security_information)
        {
            return NtSecurity.SecurityDescriptorToSddl(ToByteArray(), security_information);
        }

        /// <summary>
        /// Convert security descriptor to SDDL string
        /// </summary>
        /// <returns>The SDDL string</returns>
        public string ToSddl()
        {
            return ToSddl(SecurityInformation.Dacl | SecurityInformation.Label | SecurityInformation.Owner | SecurityInformation.Group);
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The security descriptor as an SDDL string.</returns>
        public override string ToString()
        {
            return ToSddl();
        }

        /// <summary>
        /// Convert security descriptor to a safe buffer.
        /// </summary>
        /// <returns></returns>
        public SafeBuffer ToSafeBuffer()
        {
            return new SafeHGlobalBuffer(ToByteArray());
        }

        private void AddAce(AceType type, uint mask, AceFlags flags, Sid sid)
        {
            if (Dacl == null)
            {
                Dacl = new Acl();
            }
            Dacl.NullAcl = false;
            Dacl.Add(new Ace(type, flags, mask, sid));
        }

        /// <summary>
        /// Add an access allowed ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The SID in SDDL form</param>
        public void AddAccessAllowedAce(GenericAccessRights mask, AceFlags flags, string sid)
        {
            AddAccessAllowedAce((uint)mask, flags, sid);
        }

        /// <summary>
        /// Add an access allowed ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The SID in SDDL form</param>
        public void AddAccessAllowedAce(uint mask, AceFlags flags, string sid)
        {
            AddAccessAllowedAceInternal(mask, flags, sid);
        }

        /// <summary>
        /// Add an access allowed ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="sid">The SID in SDDL form</param>
        public void AddAccessAllowedAce(uint mask, string sid)
        {
            AddAccessAllowedAceInternal(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access allowed ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="sid">The SID in SDDL form</param>
        public void AddAccessAllowedAce(GenericAccessRights mask, string sid)
        {
            AddAccessAllowedAceInternal((uint)mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access allowed ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The SID</param>
        public void AddAccessAllowedAce(GenericAccessRights mask, AceFlags flags, Sid sid)
        {
            AddAccessAllowedAceInternal((uint)mask, flags, sid);
        }

        /// <summary>
        /// Add an access allowed ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The SID</param>
        public void AddAccessAllowedAce(uint mask, AceFlags flags, Sid sid)
        {
            AddAccessAllowedAceInternal(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access allowed ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="sid">The SID</param>
        public void AddAccessAllowedAce(uint mask, Sid sid)
        {
            AddAccessAllowedAceInternal(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access allowed ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="sid">The SID</param>
        public void AddAccessAllowedAce(GenericAccessRights mask, Sid sid)
        {
            AddAccessAllowedAceInternal((uint)mask, AceFlags.None, sid);
        }

        private void AddAccessAllowedAceInternal(uint mask, AceFlags flags, Sid sid)
        {
            AddAce(AceType.Allowed, mask, flags, sid);
        }

        private void AddAccessAllowedAceInternal(uint mask, AceFlags flags, string sid)
        {
            AddAce(AceType.Allowed, mask, flags, NtSecurity.SidFromSddl(sid));
        }

        /// <summary>
        /// Add an access denied ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The SID in SDDL form</param>
        public void AddAccessDeniedAce(uint mask, AceFlags flags, string sid)
        {
            AddAccessDeniedAceInternal(mask, flags, sid);
        }

        /// <summary>
        /// Add an access denied ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The SID in SDDL form</param>
        public void AddAccessDeniedAce(GenericAccessRights mask, AceFlags flags, string sid)
        {
            AddAccessDeniedAceInternal((uint)mask, flags, sid);
        }

        /// <summary>
        /// Add an access denied ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="sid">The SID in SDDL form</param>
        public void AddAccessDeniedAce(uint mask, string sid)
        {
            AddAccessDeniedAceInternal(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access denied ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="sid">The SID in SDDL form</param>
        public void AddAccessDeniedAce(GenericAccessRights mask, string sid)
        {
            AddAccessDeniedAceInternal((uint)mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access denied ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The SID</param>
        public void AddAccessDeniedAce(GenericAccessRights mask, AceFlags flags, Sid sid)
        {
            AddAccessDeniedAceInternal((uint)mask, flags, sid);
        }

        /// <summary>
        /// Add an access denied ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="sid">The SID</param>
        public void AddAccessDeniedAce(uint mask, Sid sid)
        {
            AddAccessDeniedAceInternal(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access denied ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="sid">The SID</param>
        public void AddAccessDeniedAce(GenericAccessRights mask, Sid sid)
        {
            AddAccessDeniedAceInternal((uint)mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access denied ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The SID</param>
        public void AddAccessDeniedAce(uint mask, AceFlags flags, Sid sid)
        {
            AddAccessDeniedAceInternal(mask, flags, sid);
        }


        private void AddAccessDeniedAceInternal(uint mask, AceFlags flags, Sid sid)
        {
            AddAce(AceType.Denied, mask, flags, sid);
        }

        private void AddAccessDeniedAceInternal(uint mask, AceFlags flags, string sid)
        {
            AddAce(AceType.Denied, mask, flags, NtSecurity.SidFromSddl(sid));
        }

        /// <summary>
        /// Add mandatory integrity label to SACL
        /// </summary>
        /// <param name="level">The integrity level</param>
        public void AddMandatoryLabel(TokenIntegrityLevel level)
        {
            AddMandatoryLabel(NtSecurity.GetIntegritySid(level), AceFlags.None, MandatoryLabelPolicy.NoWriteUp);
        }

        /// <summary>
        /// Add mandatory integrity label to SACL
        /// </summary>
        /// <param name="level">The integrity level</param>
        /// <param name="policy">The mandatory label policy</param>
        public void AddMandatoryLabel(TokenIntegrityLevel level, MandatoryLabelPolicy policy)
        {
            AddMandatoryLabel(NtSecurity.GetIntegritySid(level), AceFlags.None, policy);
        }

        /// <summary>
        /// Add mandatory integrity label to SACL
        /// </summary>
        /// <param name="level">The integrity level</param>
        /// <param name="flags">The ACE flags.</param>
        /// <param name="policy">The mandatory label policy</param>
        public void AddMandatoryLabel(TokenIntegrityLevel level, AceFlags flags, MandatoryLabelPolicy policy)
        {
            AddMandatoryLabel(NtSecurity.GetIntegritySid(level), flags, policy);
        }

        /// <summary>
        /// Add mandatory integrity label to SACL
        /// </summary>
        /// <param name="label">The integrity label SID</param>
        /// <param name="flags">The ACE flags.</param>
        /// <param name="policy">The mandatory label policy</param>
        public void AddMandatoryLabel(Sid label, AceFlags flags, MandatoryLabelPolicy policy)
        {
            if (Sacl == null)
            {
                Sacl = new Acl();
            }
            Sacl.NullAcl = false;
            Sacl.Add(new Ace(AceType.MandatoryLabel, flags, (uint)policy, label));
        }
    }
}
