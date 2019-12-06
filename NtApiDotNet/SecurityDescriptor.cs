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
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

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
        #endregion
    }

    /// <summary>
    /// Security descriptor.
    /// </summary>
    public sealed class SecurityDescriptor
    {
        #region Private Members
        private static SecurityDescriptorSid ReadSid(NtProcess process, long address, bool defaulted)
        {
            if (address == 0)
            {
                return null;
            }

            SidHeader header = process.ReadMemory<SidHeader>(address);
            if (header.Revision != 1)
            {
                throw new NtException(NtStatus.STATUS_INVALID_SID);
            }

            Sid sid = new Sid(process.ReadMemory(address, 8 + header.RidCount * 4, true));
            return new SecurityDescriptorSid(sid, defaulted);
        }

        private static Acl ReadAcl(NtProcess process, long address, bool defaulted)
        {
            if (address == 0)
            {
                return new Acl() { NullAcl = true };
            }

            AclHeader header = process.ReadMemory<AclHeader>(address);
            if (header.AclRevision > 4)
            {
                throw new NtException(NtStatus.STATUS_INVALID_ACL);
            }

            if (header.AclSize < Marshal.SizeOf(typeof(AclHeader)))
            {
                throw new NtException(NtStatus.STATUS_INVALID_ACL);
            }

            return new Acl(process.ReadMemory(address, header.AclSize, true), defaulted);
        }

        private void ParseSecurityDescriptor(NtProcess process, long address)
        {
            SecurityDescriptorHeader header = process.ReadMemory<SecurityDescriptorHeader>(address);
            if (header.Revision != 1)
            {
                throw new NtException(NtStatus.STATUS_INVALID_SECURITY_DESCR);
            }
            Revision = header.Revision;
            Control = header.Control & ~SecurityDescriptorControl.SelfRelative;

            ISecurityDescriptor sd = null;
            if (header.HasFlag(SecurityDescriptorControl.SelfRelative))
            {
                sd = process.ReadMemory<SecurityDescriptorRelative>(address);
            }
            else if (process.Is64Bit)
            {
                sd = process.ReadMemory<SecurityDescriptorAbsolute>(address);
            }
            else
            {
                sd = process.ReadMemory<SecurityDescriptorAbsolute32>(address);
            }

            Owner = ReadSid(process, sd.GetOwner(address), header.HasFlag(SecurityDescriptorControl.OwnerDefaulted));
            Group = ReadSid(process, sd.GetGroup(address), header.HasFlag(SecurityDescriptorControl.GroupDefaulted));
            if (header.HasFlag(SecurityDescriptorControl.DaclPresent))
            {
                Dacl = ReadAcl(process, sd.GetDacl(address), header.HasFlag(SecurityDescriptorControl.DaclDefaulted));
            }
            if (header.HasFlag(SecurityDescriptorControl.SaclPresent))
            {
                Sacl = ReadAcl(process, sd.GetSacl(address), header.HasFlag(SecurityDescriptorControl.SaclDefaulted));
            }
        }

        private Ace FindSaclAce(AceType type)
        {
            if (Sacl != null && !Sacl.NullAcl)
            {
                return Sacl.Where(ace => ace.Type == type).FirstOrDefault();
            }
            return null;
        }

        private delegate NtStatus QuerySidFunc(SafeBuffer SecurityDescriptor, out IntPtr sid, out bool defaulted);

        private delegate NtStatus QueryAclFunc(SafeBuffer SecurityDescriptor, out bool acl_present, out IntPtr acl, out bool acl_defaulted);

        private static SecurityDescriptorSid QuerySid(SafeBuffer buffer, QuerySidFunc func)
        {
            func(buffer, out IntPtr sid, out bool sid_defaulted).ToNtException();
            if (sid != IntPtr.Zero)
            {
                return new SecurityDescriptorSid(new Sid(sid), sid_defaulted);
            }
            return null;
        }

        private static Acl QueryAcl(SafeBuffer buffer, QueryAclFunc func)
        {
            func(buffer, out bool acl_present, out IntPtr acl, out bool acl_defaulted).ToNtException();
            if (!acl_present)
            {
                return null;
            }

            return new Acl(acl, acl_defaulted);
        }

        private NtStatus ParseSecurityDescriptor(SafeBuffer buffer)
        {
            if (!NtRtl.RtlValidSecurityDescriptor(buffer))
            {
                return NtStatus.STATUS_INVALID_SECURITY_DESCR;
            }

            Owner = QuerySid(buffer, NtRtl.RtlGetOwnerSecurityDescriptor);
            Group = QuerySid(buffer, NtRtl.RtlGetGroupSecurityDescriptor);
            Dacl = QueryAcl(buffer, NtRtl.RtlGetDaclSecurityDescriptor);
            Sacl = QueryAcl(buffer, NtRtl.RtlGetSaclSecurityDescriptor);
            NtStatus status = NtRtl.RtlGetControlSecurityDescriptor(buffer,
                out SecurityDescriptorControl control, out uint revision);
            if (!status.IsSuccess())
            {
                return status;
            }
            Control = control;
            Revision = revision;

            return NtStatus.STATUS_SUCCESS;
        }

        private static IntPtr UpdateBuffer<T>(SafeStructureInOutBuffer<T> buffer, byte[] data, ref int current_ofs) where T : new()
        {
            if (data == null)
            {
                return IntPtr.Zero;
            }

            IntPtr ptr = buffer.Data.DangerousGetHandle() + current_ofs;
            buffer.Data.WriteBytes((ulong)current_ofs, data);
            current_ofs += data.Length;
            return ptr;
        }

        private static int GetLength(byte[] data)
        {
            return data?.Length ?? 0;
        }

        private SafeHGlobalBuffer CreateAbsoluteSecurityDescriptor()
        {
            SafeStructureInOutBuffer<SecurityDescriptorStructure> sd_buffer = null;
            try
            {
                byte[] dacl = Dacl?.ToByteArray();
                byte[] sacl = Sacl?.ToByteArray();
                byte[] owner = Owner?.Sid.ToArray();
                byte[] group = Group?.Sid.ToArray();
                int total_size = GetLength(dacl) + GetLength(sacl) + GetLength(owner) + GetLength(group);
                sd_buffer = new SafeStructureInOutBuffer<SecurityDescriptorStructure>(total_size, true);
                NtRtl.RtlCreateSecurityDescriptor(sd_buffer, Revision).ToNtException();
                SecurityDescriptorControl control = Control & SecurityDescriptorControl.ValidControlSetMask;
                NtRtl.RtlSetControlSecurityDescriptor(sd_buffer, control, control).ToNtException();
                int current_ofs = 0;
                if (Dacl != null)
                {
                    IntPtr ptr = UpdateBuffer(sd_buffer, Dacl.NullAcl ? null : dacl, ref current_ofs);
                    NtRtl.RtlSetDaclSecurityDescriptor(sd_buffer, true, ptr, Dacl.Defaulted).ToNtException();
                }
                if (Sacl != null)
                {
                    IntPtr ptr = UpdateBuffer(sd_buffer, Sacl.NullAcl ? null : sacl, ref current_ofs);
                    NtRtl.RtlSetSaclSecurityDescriptor(sd_buffer, true, ptr, Sacl.Defaulted).ToNtException();
                }
                if (Owner != null)
                {
                    IntPtr ptr = UpdateBuffer(sd_buffer, owner, ref current_ofs);
                    NtRtl.RtlSetOwnerSecurityDescriptor(sd_buffer, ptr, Owner.Defaulted);
                }
                if (Group != null)
                {
                    IntPtr ptr = UpdateBuffer(sd_buffer, group, ref current_ofs);
                    NtRtl.RtlSetGroupSecurityDescriptor(sd_buffer, ptr, Group.Defaulted);
                }

                return Interlocked.Exchange(ref sd_buffer, null);
            }
            finally
            {
                sd_buffer?.Close();
            }
        }

        private SafeHGlobalBuffer CreateRelativeSecurityDescriptor()
        {
            using (var sd_buffer = CreateAbsoluteSecurityDescriptor())
            {
                int total_length = 0;
                NtStatus status = NtRtl.RtlAbsoluteToSelfRelativeSD(sd_buffer, new SafeHGlobalBuffer(IntPtr.Zero, 0, false), ref total_length);
                if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
                {
                    status.ToNtException();
                }

                var relative_sd = new SafeHGlobalBuffer(total_length);
                try
                {
                    NtRtl.RtlAbsoluteToSelfRelativeSD(sd_buffer, relative_sd, ref total_length).ToNtException();
                    return Interlocked.Exchange(ref relative_sd, null);
                }
                finally
                {
                    relative_sd?.Close();
                }
            }
        }

        private void AddAce(AceType type, AccessMask mask, AceFlags flags, Sid sid)
        {
            AddAce(new Ace(type, flags, mask, sid));
        }

        private void AddAccessDeniedAceInternal(AccessMask mask, AceFlags flags, Sid sid)
        {
            AddAce(AceType.Denied, mask, flags, sid);
        }

        private void AddAccessDeniedAceInternal(AccessMask mask, AceFlags flags, string sid)
        {
            AddAce(AceType.Denied, mask, flags, NtSecurity.SidFromSddl(sid));
        }

        private void AddAccessAllowedAceInternal(AccessMask mask, AceFlags flags, Sid sid)
        {
            AddAce(AceType.Allowed, mask, flags, sid);
        }

        private void AddAccessAllowedAceInternal(AccessMask mask, AceFlags flags, string sid)
        {
            AddAce(AceType.Allowed, mask, flags, NtSecurity.SidFromSddl(sid));
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Discretionary access control list (can be null)
        /// </summary>
        public Acl Dacl { get; set; }
        /// <summary>
        /// System access control list (can be null)
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
        /// <summary>
        /// Get or set an associated NT type for this security descriptor.
        /// </summary>
        public NtType NtType { get; set; }
        /// <summary>
        /// Get or set mandatory label. Returns a medium label if it doesn't exist.
        /// </summary>
        public Ace MandatoryLabel
        {
            get
            {
                return GetMandatoryLabel()
                    ?? new MandatoryLabelAce(AceFlags.None, MandatoryLabelPolicy.NoWriteUp,
                        TokenIntegrityLevel.Medium);
            }

            set
            {
                Ace label = GetMandatoryLabel();
                if (label != null)
                {
                    Sacl.Remove(label);
                }

                if (Sacl == null)
                {
                    Sacl = new Acl();
                }
                Sacl.NullAcl = false;
                MandatoryLabelAce ace = value as MandatoryLabelAce;
                if (ace == null)
                {
                    ace = new MandatoryLabelAce(value.Flags, value.Mask.ToMandatoryLabelPolicy(), value.Sid);
                }
                Sacl.Add(ace);
            }
        }

        /// <summary>
        /// Get the process trust label.
        /// </summary>
        public Ace ProcessTrustLabel
        {
            get
            {
                return FindSaclAce(AceType.ProcessTrustLabel);
            }
        }

        /// <summary>
        /// Get or set the integrity level
        /// </summary>
        public TokenIntegrityLevel IntegrityLevel
        {
            get
            {
                return NtSecurity.GetIntegrityLevel(MandatoryLabel.Sid);
            }
            set
            {
                Ace label = MandatoryLabel;
                label.Sid = NtSecurity.GetIntegritySid(value);
                MandatoryLabel = label;
            }
        }

        /// <summary>
        /// Get or set the DACL protected flag.
        /// </summary>
        public bool DaclProtected
        {
            get => Control.HasFlag(SecurityDescriptorControl.DaclProtected);
            set
            {
                if (value)
                {
                    Control |= SecurityDescriptorControl.DaclProtected;
                }
                else
                {
                    Control &= ~SecurityDescriptorControl.DaclProtected;
                }
            }
        }

        /// <summary>
        /// Get or set the SACL protected flag.
        /// </summary>
        public bool SaclProtected
        {
            get => Control.HasFlag(SecurityDescriptorControl.SaclProtected);
            set
            {
                if (value)
                {
                    Control |= SecurityDescriptorControl.SaclProtected;
                }
                else
                {
                    Control &= ~SecurityDescriptorControl.SaclProtected;
                }
            }
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Get the mandatory label. Returns null if it doesn't exist.
        /// </summary>
        /// <returns></returns>
        public Ace GetMandatoryLabel()
        {
            return FindSaclAce(AceType.MandatoryLabel);
        }

        /// <summary>
        /// Convert security descriptor to a byte array
        /// </summary>
        /// <returns>The binary security descriptor</returns>
        public byte[] ToByteArray()
        {
            using (var sd_buffer = CreateRelativeSecurityDescriptor())
            {
                return sd_buffer.ToArray();
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
            return ToSddl(SecurityInformation.AllBasic);
        }

        /// <summary>
        /// Convert security descriptor to a safe buffer.
        /// </summary>
        /// <param name="absolute">True to return an absolute security descriptor, false for self-relative.</param>
        /// <returns>A safe buffer for the security descriptor.</returns>
        public SafeBuffer ToSafeBuffer(bool absolute)
        {
            return absolute ? CreateAbsoluteSecurityDescriptor() : CreateRelativeSecurityDescriptor();
        }

        /// <summary>
        /// Convert security descriptor to a safe buffer.
        /// </summary>
        /// <returns>A safe buffer for the security descriptor.</returns>
        /// <remarks>This returns a self-relative security descriptor.</remarks>
        public SafeBuffer ToSafeBuffer()
        {
            return ToSafeBuffer(false);
        }

        /// <summary>
        /// Add an ACE to the DACL, creating the DACL if needed.
        /// </summary>
        /// <param name="ace">The ACE to add to the DACL.</param>
        public void AddAce(Ace ace)
        {
            if (Dacl == null)
            {
                Dacl = new Acl();
            }
            Dacl.NullAcl = false;
            Dacl.Add(ace);
        }

        /// <summary>
        /// Add an access allowed ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The SID in SDDL form</param>
        public void AddAccessAllowedAce(AccessMask mask, AceFlags flags, string sid)
        {
            AddAccessAllowedAceInternal(mask, flags, sid);
        }

        /// <summary>
        /// Add an access allowed ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="sid">The SID in SDDL form</param>
        public void AddAccessAllowedAce(AccessMask mask, string sid)
        {
            AddAccessAllowedAceInternal(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access allowed ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The SID</param>
        public void AddAccessAllowedAce(AccessMask mask, AceFlags flags, Sid sid)
        {
            AddAccessAllowedAceInternal(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access allowed ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="sid">The SID</param>
        public void AddAccessAllowedAce(AccessMask mask, Sid sid)
        {
            AddAccessAllowedAceInternal(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access denied ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The SID in SDDL form</param>
        public void AddAccessDeniedAce(AccessMask mask, AceFlags flags, string sid)
        {
            AddAccessDeniedAceInternal(mask, flags, sid);
        }

        /// <summary>
        /// Add an access denied ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="sid">The SID in SDDL form</param>
        public void AddAccessDeniedAce(AccessMask mask, string sid)
        {
            AddAccessDeniedAceInternal(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access denied ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="sid">The SID</param>
        public void AddAccessDeniedAce(AccessMask mask, Sid sid)
        {
            AddAccessDeniedAceInternal(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access denied ACE to the DACL
        /// </summary>
        /// <param name="mask">The access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The SID</param>
        public void AddAccessDeniedAce(AccessMask mask, AceFlags flags, Sid sid)
        {
            AddAccessDeniedAceInternal(mask, flags, sid);
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
            MandatoryLabel = new Ace(AceType.MandatoryLabel, flags, policy, label);
        }

        /// <summary>
        /// Map all generic access in this security descriptor to the default type specified by NtType.
        /// </summary>
        public void MapGenericAccess()
        {
            if (NtType == null)
                return;
            MapGenericAccess(NtType);
        }

        /// <summary>
        /// Map all generic access in this security descriptor to a specific type.
        /// </summary>
        /// <param name="type">The type to get the generic mapping from.</param>
        public void MapGenericAccess(NtType type)
        {
            MapGenericAccess(type.GenericMapping);
        }

        /// <summary>
        /// Map all generic access in this security descriptor to a specific type.
        /// </summary>
        /// <param name="generic_mapping">The generic mapping.</param>
        public void MapGenericAccess(GenericMapping generic_mapping)
        {
            if (Dacl != null)
            {
                foreach (Ace ace in Dacl)
                {
                    ace.Mask = generic_mapping.MapMask(ace.Mask);
                }
            }

            if (ProcessTrustLabel != null)
            {
                ProcessTrustLabel.Mask = generic_mapping.MapMask(ProcessTrustLabel.Mask);
            }
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The security descriptor as an SDDL string.</returns>
        public override string ToString()
        {
            return ToSddl();
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="ptr">Native pointer to security descriptor.</param>
        public SecurityDescriptor(IntPtr ptr)
        {
            ParseSecurityDescriptor(new SafeHGlobalBuffer(ptr, 0, false)).ToNtException();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="process">The process containing the security descriptor.</param>
        /// <param name="ptr">Native pointer to security descriptor.</param>
        public SecurityDescriptor(NtProcess process, IntPtr ptr)
        {
            ParseSecurityDescriptor(process, ptr.ToInt64());
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
        /// <param name="type">Optional NT type for security descriptor.</param>
        public SecurityDescriptor(byte[] security_descriptor, NtType type)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(security_descriptor))
            {
                ParseSecurityDescriptor(buffer).ToNtException();
            }
            NtType = type;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="security_descriptor">Binary form of security descriptor</param>
        public SecurityDescriptor(byte[] security_descriptor) 
            : this(security_descriptor, null)
        {
        }

        /// <summary>
        /// Constructor from a token default DACL and ownership values.
        /// </summary>
        /// <param name="token">The token to use for its default DACL</param>
        public SecurityDescriptor(NtToken token) : this()
        {
            Owner = new SecurityDescriptorSid(token.Owner, true);
            Group = new SecurityDescriptorSid(token.PrimaryGroup, true);
            Dacl = token.DefaultDacl;
            if (token.IntegrityLevel < TokenIntegrityLevel.Medium)
            {
                Sacl = new Acl
                {
                    new Ace(AceType.MandatoryLabel, AceFlags.None, 1, token.IntegrityLevelSid.Sid)
                };
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
                creator_sd = new SecurityDescriptor
                {
                    Owner = new SecurityDescriptorSid(token.Owner, false),
                    Group = new SecurityDescriptorSid(token.PrimaryGroup, false),
                    Dacl = token.DefaultDacl
                };
            }

            NtType type = base_object.NtType;
            NtType = type;

            SafeBuffer parent_sd_buffer = SafeHGlobalBuffer.Null;
            SafeBuffer creator_sd_buffer = SafeHGlobalBuffer.Null;
            SafeSecurityObjectBuffer security_obj = null;
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
                    token.GetHandle(), ref mapping).ToNtException();
                ParseSecurityDescriptor(security_obj).ToNtException();
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
            : this(sddl, null)
        {
        }

        /// <summary>
        /// Constructor from an SDDL string
        /// </summary>
        /// <param name="sddl">The SDDL string</param>
        /// <param name="type">Optional NT type for security descriptor.</param>
        /// <exception cref="NtException">Thrown if invalid SDDL</exception>
        public SecurityDescriptor(string sddl, NtType type)
            : this(NtSecurity.SddlToSecurityDescriptor(sddl) ,type)
        {
        }

        #endregion

        #region Static Methods

        /// <summary>
        /// Parse a security descriptor.
        /// </summary>
        /// <param name="ptr">Native pointer to security descriptor.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        public static NtResult<SecurityDescriptor> Parse(IntPtr ptr, bool throw_on_error)
        {
            return Parse(new SafeHGlobalBuffer(ptr, 0, false), throw_on_error);
        }

        /// <summary>
        /// Parse a security descriptor.
        /// </summary>
        /// <param name="buffer">Safe buffer to security descriptor.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        public static NtResult<SecurityDescriptor> Parse(SafeBuffer buffer, bool throw_on_error)
        {
            SecurityDescriptor sd = new SecurityDescriptor();
            return sd.ParseSecurityDescriptor(buffer).CreateResult(throw_on_error, () => sd);
        }

        /// <summary>
        /// Parse a security descriptor.
        /// </summary>
        /// <param name="security_descriptor">Binary form of security descriptor</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        public static NtResult<SecurityDescriptor> Parse(byte[] security_descriptor, bool throw_on_error)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(security_descriptor))
            {
                return Parse(buffer, throw_on_error);
            }
        }

        #endregion
    }
}
