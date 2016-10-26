//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
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
        public Acl Dacl { get; set; }
        public Acl Sacl { get; set; }
        public SecurityDescriptorSid Owner { get; set; }
        public SecurityDescriptorSid Group { get; set; }
        public SecurityDescriptorControl Control { get; set; }
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

        public SecurityDescriptor()
        {
            Revision = 1;
        }

        public SecurityDescriptor(byte[] security_descriptor)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(security_descriptor))
            {
                ParseSecurityDescriptor(buffer);
            }
        }

        public SecurityDescriptor(NtToken token) : this()
        {
            Owner = new SecurityDescriptorSid(token.GetOwner(), true);
            Group = new SecurityDescriptorSid(token.GetPrimaryGroup(), true);
            Dacl = token.GetDefaultDalc();
            if (token.GetIntegrityLevel() < TokenIntegrityLevel.Medium)
            {
                Sacl = new Acl();
                Sacl.Add(new Ace(AceType.MandatoryLabel, AceFlags.None, 1, token.GetIntegrityLevelSid().Sid));
            }
        }

        public SecurityDescriptor(NtObject base_object, NtToken token, bool is_directory) : this()
        {
            if ((base_object == null) && (token == null))
            {
                throw new ArgumentNullException();
            }

            SecurityDescriptor parent_sd = null;
            if (base_object != null)
            {
                parent_sd = base_object.GetSecurityDescriptor();
            }

            SecurityDescriptor creator_sd = null;
            if (token != null)
            {
                creator_sd = new SecurityDescriptor();
                creator_sd.Owner = new SecurityDescriptorSid(token.GetOwner(), false);
                creator_sd.Group = new SecurityDescriptorSid(token.GetPrimaryGroup(), false);
                creator_sd.Dacl = token.GetDefaultDalc();
            }

            ObjectTypeInfo type = ObjectTypeInfo.GetTypeByName(base_object.GetTypeName());

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
                if (parent_sd_buffer != null)
                {
                    parent_sd_buffer.Close();
                }
                if (creator_sd_buffer != null)
                {
                    creator_sd_buffer.Close();
                }
                if (security_obj != null)
                {
                    security_obj.Close();
                }
            }
        }

        public SecurityDescriptor(string sddl)
            : this(NtSecurity.SddlToSecurityDescriptor(sddl))
        {
        }

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
                if (sd_buffer != null)
                {
                    sd_buffer.Close();
                }
                if (dacl_buffer != null)
                {
                    dacl_buffer.Close();
                }
                if (sacl_buffer != null)
                {
                    sacl_buffer.Close();
                }
                if (owner_buffer != null)
                {
                    owner_buffer.Close();
                }
                if (group_buffer != null)
                {
                    group_buffer.Close();
                }
            }
        }

        public string ToSddl(SecurityInformation security_information)
        {
            return NtSecurity.SecurityDescriptorToSddl(ToByteArray(), security_information);
        }

        public string ToSddl()
        {
            return ToSddl(SecurityInformation.Dacl | SecurityInformation.Label | SecurityInformation.Owner | SecurityInformation.Group);
        }

        public SafeBuffer ToSafeBuffer()
        {
            return new SafeHGlobalBuffer(ToByteArray());
        }

        public void AddAccessAllowedAce(GenericAccessRights mask, AceFlags flags, string sid)
        {
            AddAccessAllowedAce((uint)mask, flags, sid);
        }

        private void AddAce(AceType type, uint mask, AceFlags flags, Sid sid)
        {
            if (Dacl == null)
            {
                Dacl = new Acl();
            }
            Dacl.NullAcl = false;
            Dacl.Add(new NtApiDotNet.Ace(type, flags, mask, sid));
        }

        public void AddAccessAllowedAce(uint mask, AceFlags flags, string sid)
        {
            AddAccessAllowedAceInternal(mask, flags, sid);
        }

        public void AddAccessAllowedAce(uint mask, string sid)
        {
            AddAccessAllowedAceInternal(mask, AceFlags.None, sid);
        }

        public void AddAccessAllowedAce(GenericAccessRights mask, string sid)
        {
            AddAccessAllowedAceInternal((uint)mask, AceFlags.None, sid);
        }

        public void AddAccessAllowedAce(GenericAccessRights mask, AceFlags flags, Sid sid)
        {
            AddAccessAllowedAceInternal((uint)mask, flags, sid);
        }

        public void AddAccessAllowedAce(uint mask, AceFlags flags, Sid sid)
        {
            AddAccessAllowedAceInternal(mask, AceFlags.None, sid);
        }

        public void AddAccessAllowedAce(uint mask, Sid sid)
        {
            AddAccessAllowedAceInternal((uint)mask, AceFlags.None, sid);
        }

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

        public void AddAccessDeniedAce(uint mask, AceFlags flags, string sid)
        {
            AddAccessDeniedAce(mask, flags, sid);
        }

        public void AddAccessDeniedAce(GenericAccessRights mask, AceFlags flags, string sid)
        {
            AddAccessDeniedAceInternal((uint)mask, flags, sid);
        }

        public void AddAccessDeniedAce(uint mask, string sid)
        {
            AddAccessDeniedAceInternal(mask, AceFlags.None, sid);
        }

        public void AddAccessDeniedAce(GenericAccessRights mask, string sid)
        {
            AddAccessDeniedAceInternal((uint)mask, AceFlags.None, sid);
        }

        public void AddAccessDeniedAce(GenericAccessRights mask, AceFlags flags, Sid sid)
        {
            AddAccessDeniedAceInternal((uint)mask, flags, sid);
        }

        public void AddAccessDeniedAce(uint mask, Sid sid)
        {
            AddAccessDeniedAceInternal(mask, AceFlags.None, sid);
        }

        public void AddAccessDeniedAce(GenericAccessRights mask, Sid sid)
        {
            AddAccessDeniedAceInternal((uint)mask, AceFlags.None, sid);
        }

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

        public void AddMandatoryLabel(TokenIntegrityLevel level)
        {
            AddMandatoryLabel(NtSecurity.GetIntegritySid(level), AceFlags.None, MandatoryLabelPolicy.NoWriteUp);
        }

        public void AddMandatoryLabel(TokenIntegrityLevel level, MandatoryLabelPolicy policy)
        {
            AddMandatoryLabel(NtSecurity.GetIntegritySid(level), AceFlags.None, policy);
        }

        public void AddMandatoryLabel(TokenIntegrityLevel level, AceFlags flags, MandatoryLabelPolicy policy)
        {
            AddMandatoryLabel(NtSecurity.GetIntegritySid(level), flags, policy);
        }

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
