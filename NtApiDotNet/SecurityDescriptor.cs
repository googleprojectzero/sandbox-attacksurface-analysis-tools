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

using NtApiDotNet.Utilities.SafeBuffers;
using System;
using System.Collections.Generic;
using System.Linq;
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
        None = 0,
        OwnerDefaulted = 0x0001,
        GroupDefaulted = 0x0002,
        DaclPresent = 0x0004,
        DaclDefaulted = 0x0008,
        SaclPresent = 0x0010,
        SaclDefaulted = 0x0020,
        DaclUntrusted = 0x0040,
        ServerSecurity = 0x0080,
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
        | DaclUntrusted | ServerSecurity
#pragma warning restore 1591
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

        private static Acl ReadAcl(NtProcess process, long address, SecurityDescriptorControl control, bool dacl)
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

            bool acl_defaulted = control.HasFlagSet(dacl ? SecurityDescriptorControl.DaclDefaulted : SecurityDescriptorControl.SaclDefaulted);

            return UpdateAclFlags(new Acl(process.ReadMemory(address, header.AclSize, true), acl_defaulted), control, dacl);
        }

        private void ParseSecurityDescriptor(NtProcess process, long address)
        {
            SecurityDescriptorHeader header = process.ReadMemory<SecurityDescriptorHeader>(address);
            if (header.Revision != 1)
            {
                throw new NtException(NtStatus.STATUS_INVALID_SECURITY_DESCR);
            }
            Revision = header.Revision;
            SelfRelative = header.HasFlag(SecurityDescriptorControl.SelfRelative);
            if (header.Control.HasFlag(SecurityDescriptorControl.RmControlValid))
            {
                RmControl = header.Sbz1;
            }

            ISecurityDescriptor sd;
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
                Dacl = ReadAcl(process, sd.GetDacl(address), header.Control, true);
            }
            if (header.HasFlag(SecurityDescriptorControl.SaclPresent))
            {
                Sacl = ReadAcl(process, sd.GetSacl(address), header.Control, false);
            }
        }

        private Ace FindSaclAce(AceType type, bool include_inherit_only)
        {
            if (Sacl != null && !Sacl.NullAcl)
            {
                return Sacl.FindAce(type, include_inherit_only);
            }
            return null;
        }

        private IEnumerable<Ace> FindAllSaclAce(AceType type, bool include_inherit_only)
        {
            if (Sacl != null && !Sacl.NullAcl)
            {
                return Sacl.FindAllAce(type, include_inherit_only).ToList().AsReadOnly();
            }
            return new Ace[0];
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

        private static Acl UpdateAclFlags(Acl acl, SecurityDescriptorControl control, bool dacl)
        {
            acl.Protected = control.HasFlagSet(dacl ?
                    SecurityDescriptorControl.DaclProtected : SecurityDescriptorControl.SaclProtected);
            acl.AutoInherited = control.HasFlagSet(dacl ?
                    SecurityDescriptorControl.DaclAutoInherited : SecurityDescriptorControl.SaclAutoInherited);
            acl.AutoInheritReq = control.HasFlagSet(dacl ?
                    SecurityDescriptorControl.DaclAutoInheritReq : SecurityDescriptorControl.SaclAutoInheritReq);
            return acl;
        }

        private static Acl QueryAcl(SafeBuffer buffer, QueryAclFunc func, SecurityDescriptorControl control, bool dacl)
        {
            func(buffer, out bool acl_present, out IntPtr acl, out bool acl_defaulted).ToNtException();
            if (!acl_present)
            {
                return null;
            }

            return UpdateAclFlags(new Acl(acl, acl_defaulted), control, dacl);
        }

        private SecurityDescriptorControl ComputeControl()
        {
            SecurityDescriptorControl control = 0;
            if (Owner?.Defaulted ?? false)
            {
                control |= SecurityDescriptorControl.OwnerDefaulted;
            }
            if (Group?.Defaulted ?? false)
            {
                control |= SecurityDescriptorControl.GroupDefaulted;
            }
            if (Dacl != null)
            {
                control |= SecurityDescriptorControl.DaclPresent;
                if (Dacl.Defaulted)
                {
                    control |= SecurityDescriptorControl.DaclDefaulted;
                }
                if (Dacl.Protected)
                {
                    control |= SecurityDescriptorControl.DaclProtected;
                }
                if (Dacl.AutoInherited)
                {
                    control |= SecurityDescriptorControl.DaclAutoInherited;
                }
                if (Dacl.AutoInheritReq)
                {
                    control |= SecurityDescriptorControl.DaclAutoInheritReq;
                }
            }
            if (Sacl != null)
            {
                control |= SecurityDescriptorControl.SaclPresent;
                if (Sacl.Defaulted)
                {
                    control |= SecurityDescriptorControl.SaclDefaulted;
                }
                if (Sacl.Protected)
                {
                    control |= SecurityDescriptorControl.SaclProtected;
                }
                if (Sacl.AutoInherited)
                {
                    control |= SecurityDescriptorControl.SaclAutoInherited;
                }
                if (Sacl.AutoInheritReq)
                {
                    control |= SecurityDescriptorControl.SaclAutoInheritReq;
                }
            }

            if (ServerSecurity)
            {
                control |= SecurityDescriptorControl.ServerSecurity;
            }
            if (DaclUntrusted)
            {
                control |= SecurityDescriptorControl.DaclUntrusted;
            }
            if (RmControl.HasValue)
            {
                control |= SecurityDescriptorControl.RmControlValid;
            }

            return control;
        }

        private NtStatus ParseSecurityDescriptor(SafeBuffer buffer)
        {
            if (!NtRtl.RtlValidSecurityDescriptor(buffer))
            {
                return NtStatus.STATUS_INVALID_SECURITY_DESCR;
            }

            NtStatus status = NtRtl.RtlGetControlSecurityDescriptor(buffer,
                out SecurityDescriptorControl control, out uint revision);
            if (!status.IsSuccess())
            {
                return status;
            }

            Owner = QuerySid(buffer, NtRtl.RtlGetOwnerSecurityDescriptor);
            Group = QuerySid(buffer, NtRtl.RtlGetGroupSecurityDescriptor);
            Dacl = QueryAcl(buffer, NtRtl.RtlGetDaclSecurityDescriptor, control, true);
            Sacl = QueryAcl(buffer, NtRtl.RtlGetSaclSecurityDescriptor, control, false);

            if (NtRtl.RtlGetSecurityDescriptorRMControl(buffer, out byte rm_control))
            {
                RmControl = rm_control;
            }

            SelfRelative = control.HasFlagSet(SecurityDescriptorControl.SelfRelative);
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

        private NtResult<SafeHGlobalBuffer> CreateAbsoluteSecurityDescriptor(bool throw_on_error)
        {
            byte[] dacl = Dacl?.ToByteArray();
            byte[] sacl = Sacl?.ToByteArray();
            byte[] owner = Owner?.Sid.ToArray();
            byte[] group = Group?.Sid.ToArray();
            int total_size = GetLength(dacl) + GetLength(sacl) + GetLength(owner) + GetLength(group);
            using (var sd_buffer = new SafeStructureInOutBuffer<SecurityDescriptorStructure>(total_size, true))
            {
                NtStatus status = NtRtl.RtlCreateSecurityDescriptor(sd_buffer, Revision);
                if (!status.IsSuccess())
                {
                    return status.CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
                }

                SecurityDescriptorControl control = ComputeControl() & SecurityDescriptorControl.ValidControlSetMask;
                status = NtRtl.RtlSetControlSecurityDescriptor(sd_buffer, control, control);
                if (!status.IsSuccess())
                {
                    return status.CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
                }

                if (RmControl.HasValue)
                {
                    byte rm_control = RmControl.Value;
                    NtRtl.RtlSetSecurityDescriptorRMControl(sd_buffer, ref rm_control);
                }

                int current_ofs = 0;
                if (Dacl != null)
                {
                    IntPtr ptr = UpdateBuffer(sd_buffer, Dacl.NullAcl ? null : dacl, ref current_ofs);
                    status = NtRtl.RtlSetDaclSecurityDescriptor(sd_buffer, true, ptr, Dacl.Defaulted);
                    if (!status.IsSuccess())
                    {
                        return status.CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
                    }
                }

                if (Sacl != null)
                {
                    IntPtr ptr = UpdateBuffer(sd_buffer, Sacl.NullAcl ? null : sacl, ref current_ofs);
                    status = NtRtl.RtlSetSaclSecurityDescriptor(sd_buffer, true, ptr, Sacl.Defaulted);
                    if (!status.IsSuccess())
                    {
                        return status.CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
                    }
                }

                if (Owner != null)
                {
                    IntPtr ptr = UpdateBuffer(sd_buffer, owner, ref current_ofs);
                    status = NtRtl.RtlSetOwnerSecurityDescriptor(sd_buffer, ptr, Owner.Defaulted);
                    if (!status.IsSuccess())
                    {
                        return status.CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
                    }
                }

                if (Group != null)
                {
                    IntPtr ptr = UpdateBuffer(sd_buffer, group, ref current_ofs);
                    status = NtRtl.RtlSetGroupSecurityDescriptor(sd_buffer, ptr, Group.Defaulted);
                    if (!status.IsSuccess())
                    {
                        return status.CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
                    }
                }

                return status.CreateResult<SafeHGlobalBuffer>(throw_on_error, () => sd_buffer.Detach());
            }
        }

        private NtResult<SafeHGlobalBuffer> CreateRelativeSecurityDescriptor(bool throw_on_error)
        {
            using (var sd_buffer = CreateAbsoluteSecurityDescriptor(throw_on_error))
            {
                if (!sd_buffer.IsSuccess)
                {
                    return sd_buffer;
                }

                int total_length = 0;
                NtStatus status = NtRtl.RtlAbsoluteToSelfRelativeSD(sd_buffer.Result, SafeHGlobalBuffer.Null, ref total_length);
                if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
                {
                    return status.CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
                }

                using (var relative_sd = new SafeHGlobalBuffer(total_length))
                {
                    return NtRtl.RtlAbsoluteToSelfRelativeSD(sd_buffer.Result, relative_sd, ref total_length)
                        .CreateResult(throw_on_error, () => relative_sd.Detach());
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

        private static SafeBuffer BuildObjectTypeList(DisposableList list, Guid[] object_types)
        {
            int total_size = object_types.Length * (IntPtr.Size + 16);
            int guid_base = object_types.Length * IntPtr.Size;
            var buffer = list.AddResource(new SafeHGlobalBuffer(total_size));
            IntPtr[] ptrs = Enumerable.Range(0, object_types.Length).Select(i => buffer.DangerousGetHandle() + (i * 16 + guid_base)).ToArray();
            buffer.WriteArray(0, ptrs, 0, ptrs.Length);
            buffer.WriteArray((ulong)guid_base, object_types, 0, object_types.Length);
            return buffer;
        }

        private static NtResult<SafeProcessHeapBuffer> CreateBuffer(
            SecurityDescriptor parent,
            SecurityDescriptor creator,
            Guid[] object_types,
            bool is_directory,
            SecurityAutoInheritFlags flags,
            NtToken token,
            GenericMapping generic_mapping,
            bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var parent_buffer = list.AddResource(parent?.ToSafeBuffer() ?? SafeProcessHeapBuffer.Null);
                var creator_buffer = list.AddResource(creator?.ToSafeBuffer() ?? SafeProcessHeapBuffer.Null);
                if (object_types?.Length > 0)
                {
                    var guids = list.AddResource(new SafeGuidArrayBuffer(object_types));
                    return NtRtl.RtlNewSecurityObjectWithMultipleInheritance(
                        parent_buffer, creator_buffer, out SafeProcessHeapBuffer new_descriptor,
                        guids, guids.Count, is_directory, flags, token.GetHandle(),
                        ref generic_mapping).CreateResult(throw_on_error, () => new_descriptor);
                }
                else
                {
                    return NtRtl.RtlNewSecurityObjectEx(
                        parent_buffer, creator_buffer, out SafeProcessHeapBuffer new_descriptor,
                        null, is_directory, flags, token.GetHandle(),
                        ref generic_mapping).CreateResult(throw_on_error, () => new_descriptor);
                }
            }
        }

        private void UpdateControl(SecurityDescriptorControl control)
        {
            if (Owner != null)
            {
                Owner.Defaulted = control.HasFlag(SecurityDescriptorControl.OwnerDefaulted);
            }

            if (Group != null)
            {
                Group.Defaulted = control.HasFlag(SecurityDescriptorControl.GroupDefaulted);
            }

            if (Dacl != null)
            {
                Dacl.Defaulted = control.HasFlag(SecurityDescriptorControl.DaclDefaulted);
                Dacl.Protected = control.HasFlag(SecurityDescriptorControl.DaclProtected);
                Dacl.AutoInherited = control.HasFlag(SecurityDescriptorControl.DaclAutoInherited);
                Dacl.AutoInheritReq = control.HasFlag(SecurityDescriptorControl.DaclAutoInheritReq);
            }
            if (Sacl != null)
            {
                Sacl.Defaulted = control.HasFlag(SecurityDescriptorControl.SaclDefaulted);
                Sacl.Protected = control.HasFlag(SecurityDescriptorControl.SaclProtected);
                Sacl.AutoInherited = control.HasFlag(SecurityDescriptorControl.SaclAutoInherited);
                Sacl.AutoInheritReq = control.HasFlag(SecurityDescriptorControl.SaclAutoInheritReq);
            }
            ServerSecurity = control.HasFlag(SecurityDescriptorControl.ServerSecurity);
            DaclUntrusted = control.HasFlag(SecurityDescriptorControl.DaclUntrusted);
        }

        private static void MapAcl(Acl acl, GenericMapping generic_mapping)
        {
            if (acl == null)
                return;
            foreach (Ace ace in acl)
            {
                if (!ace.IsInheritOnly && !ace.IsMandatoryLabel)
                {
                    ace.Mask = generic_mapping.MapMask(ace.Mask);
                }
            }
        }

        private void MoveFrom(SecurityDescriptor sd, bool clone)
        {
            if (clone)
            {
                Dacl = sd.Dacl?.Clone();
                Sacl = sd.Sacl?.Clone();
                Owner = sd.Owner?.Clone();
                Group = sd.Group?.Clone();
            }
            else
            {
                Dacl = sd.Dacl;
                Sacl = sd.Sacl;
                Owner = sd.Owner;
                Group = sd.Group;
            }
            Control = sd.Control;
            Revision = sd.Revision;
            RmControl = sd.RmControl;
            NtType = sd.NtType;
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
        /// Get or set Control flags. This is computed based on the current state of the SD.
        /// </summary>
        public SecurityDescriptorControl Control
        {
            get => ComputeControl();
            set => UpdateControl(value);
        }
        /// <summary>
        /// Revision value
        /// </summary>
        public uint Revision { get; set; }
        /// <summary>
        /// The resource manager control flags.
        /// </summary>
        public byte? RmControl { get; set; }
        /// <summary>
        /// Get or set an associated NT type for this security descriptor.
        /// </summary>
        public NtType NtType { get; set; }
        /// <summary>
        /// Get or set mandatory label. Returns a medium label if it doesn't exist.
        /// </summary>
        public Ace MandatoryLabel
        {
            // TODO: Remove this fallback at some point.
            get => GetMandatoryLabel()
                    ?? new MandatoryLabelAce(AceFlags.None, MandatoryLabelPolicy.NoWriteUp,
                        TokenIntegrityLevel.Medium);

            set
            {
                RemoveMandatoryLabel();
                if (value == null)
                {
                    return;
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
        public Ace ProcessTrustLabel => FindSaclAce(AceType.ProcessTrustLabel, false);

        /// <summary>
        /// Get list of access filters.
        /// </summary>
        public IEnumerable<Ace> AccessFilters => FindAllSaclAce(AceType.AccessFilter, false);

        /// <summary>
        /// Get list of resource attributes.
        /// </summary>
        public IEnumerable<Ace> ResourceAttributes => FindAllSaclAce(AceType.ResourceAttribute, false);

        /// <summary>
        /// Get the scoped policy ID.
        /// </summary>
        public Ace ScopedPolicyId => FindSaclAce(AceType.ScopedPolicyId, false);

        /// <summary>
        /// Get or set the integrity level
        /// </summary>
        public TokenIntegrityLevel IntegrityLevel
        {
            get => NtSecurity.GetIntegrityLevel(MandatoryLabel.Sid);
            set
            {
                Ace label = MandatoryLabel;
                label.Sid = NtSecurity.GetIntegritySid(value);
                MandatoryLabel = label;
            }
        }

        /// <summary>
        /// Get or set the server security flag.
        /// </summary>
        public bool ServerSecurity { get; set; }

        /// <summary>
        /// Get or set the DACL untrusted flag.
        /// </summary>
        public bool DaclUntrusted { get; set; }

        /// <summary>
        /// Get whether the DACL is present.
        /// </summary>
        public bool DaclPresent => Dacl != null;

        /// <summary>
        /// Get count of ACEs in DACL.
        /// </summary>
        public int DaclAceCount => Dacl?.Count ?? 0;

        /// <summary>
        /// Get whether the SACL is present.
        /// </summary>
        public bool SaclPresent => Sacl != null;

        /// <summary>
        /// Get count of ACEs in DACL.
        /// </summary>
        public int SaclAceCount => Sacl?.Count ?? 0;

        /// <summary>
        /// Indicates if the security descriptor was constructed from a self relative format.
        /// </summary>
        public bool SelfRelative { get; private set; }

        /// <summary>
        /// Indicates if the SD's DACL is canonical.
        /// </summary>
        public bool DaclCanonical => Dacl?.IsCanonical(true) ?? true;

        /// <summary>
        /// Indicates if the SD's SACL is canonical.
        /// </summary>
        public bool SaclCanonical => Sacl?.IsCanonical(false) ?? true;

        /// <summary>
        /// Indicates if the SD's DACL is defaulted.
        /// </summary>
        public bool DaclDefaulted => Dacl?.Defaulted ?? false;

        /// <summary>
        /// Indicates if the SD's SACL is defaulted.
        /// </summary>
        public bool SaclDefaulted => Sacl?.Defaulted ?? false;

        /// <summary>
        /// Indicates if the SD's DACL is auto-inherited.
        /// </summary>
        public bool DaclAutoInherited => Dacl?.AutoInherited ?? false;

        /// <summary>
        /// Indicates if the SD's SACL is auto-inherited.
        /// </summary>
        public bool SaclAutoInherited => Sacl?.AutoInherited ?? false;

        /// <summary>
        /// Indicates if the SD came from a container.
        /// </summary>
        public bool Container { get; set; }

        /// <summary>
        /// Indicates the SD has audit ACEs present.
        /// </summary>
        public bool HasAuditAce => Sacl?.Find(a => a.IsAuditAce) != null;

        /// <summary>
        /// Indicates the SD has a mandatory label ACE present.
        /// </summary>
        public bool HasMandatoryLabelAce => GetMandatoryLabel() != null;

        /// <summary>
        /// Indicates the SD has a NULL DACL.
        /// </summary>
        public bool DaclNull => Dacl?.NullAcl ?? false;

        /// <summary>
        /// Indicates the SD has a NULL SACL.
        /// </summary>
        public bool SaclNull => Sacl?.NullAcl ?? false;

        /// <summary>
        /// Get the access rights enum type for this SD based on the NT Type property.
        /// </summary>
        public Type AccessRightsType
        {
            get
            {
                if (NtType == null)
                {
                    return typeof(GenericAccessRights);
                }

                return Container ? NtType.ContainerAccessRightsType : NtType.AccessRightsType;
            }
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Get the mandatory label. Returns null if it doesn't exist.
        /// </summary>
        /// <param name="include_inherit_only">True to include InheritOnly ACEs in the search.</param>
        /// <returns>The valid mandatory ACE for this security descriptor. Or null if it doesn't exist.</returns>
        public Ace GetMandatoryLabel(bool include_inherit_only)
        {
            return FindSaclAce(AceType.MandatoryLabel, include_inherit_only);
        }

        /// <summary>
        /// Get the mandatory label. Returns null if it doesn't exist.
        /// </summary>
        /// <returns>The valid mandatory ACE for this security descriptor. Or null if it doesn't exist.</returns>
        public Ace GetMandatoryLabel()
        {
            return GetMandatoryLabel(false);
        }

        /// <summary>
        /// Convert security descriptor to a byte array
        /// </summary>
        /// <returns>The binary security descriptor</returns>
        public byte[] ToByteArray()
        {
            using (var sd_buffer = CreateRelativeSecurityDescriptor(true))
            {
                return sd_buffer.Result.ToArray();
            }
        }

        /// <summary>
        /// Convert security descriptor to SDDL string
        /// </summary>
        /// <param name="security_information">The parts of the security descriptor to return</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SDDL string</returns>
        public NtResult<string> ToSddl(SecurityInformation security_information, bool throw_on_error)
        {
            using (var buffer = ToSafeBuffer(true))
            {
                return NtSecurity.SecurityDescriptorToSddl(buffer, security_information, throw_on_error);
            }
        }

        /// <summary>
        /// Convert security descriptor to SDDL string
        /// </summary>
        /// <param name="security_information">The parts of the security descriptor to return</param>
        /// <returns>The SDDL string</returns>
        public string ToSddl(SecurityInformation security_information)
        {
            using (var buffer = ToSafeBuffer(true))
            {
                return NtSecurity.SecurityDescriptorToSddl(buffer, security_information, true).Result;
            }
        }

        /// <summary>
        /// Convert security descriptor to SDDL string
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SDDL string</returns>
        public NtResult<string> ToSddl(bool throw_on_error)
        {
            return ToSddl(SecurityInformation.AllBasic, throw_on_error);
        }

        /// <summary>
        /// Convert security descriptor to SDDL string
        /// </summary>
        /// <returns>The SDDL string</returns>
        public string ToSddl()
        {
            return ToSddl(true).Result;
        }

        /// <summary>
        /// Converts the security to a base64 string.
        /// </summary>
        /// <param name="insert_line_breaks">True to insert line breaks in the base64.</param>
        /// <returns>The relative SD as a base64 string.</returns>
        public string ToBase64(bool insert_line_breaks)
        {
            return Convert.ToBase64String(ToByteArray(), insert_line_breaks ? Base64FormattingOptions.InsertLineBreaks : 0);
        }

        /// <summary>
        /// Converts the security to a base64 string.
        /// </summary>
        /// <returns>The relative SD as a base64 string.</returns>
        public string ToBase64()
        {
            return ToBase64(false);
        }

        /// <summary>
        /// Convert security descriptor to a safe buffer.
        /// </summary>
        /// <param name="absolute">True to return an absolute security descriptor, false for self-relative.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>A safe buffer for the security descriptor.</returns>
        public NtResult<SafeBuffer> ToSafeBuffer(bool absolute, bool throw_on_error)
        {
            var buffer = absolute ? CreateAbsoluteSecurityDescriptor(throw_on_error) : CreateRelativeSecurityDescriptor(throw_on_error);
            return buffer.Cast<SafeBuffer>();
        }

        /// <summary>
        /// Convert security descriptor to a safe buffer.
        /// </summary>
        /// <param name="absolute">True to return an absolute security descriptor, false for self-relative.</param>
        /// <returns>A safe buffer for the security descriptor.</returns>
        public SafeBuffer ToSafeBuffer(bool absolute)
        {
            return ToSafeBuffer(absolute, true).Result;
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
        /// Removes the mandatory label if it exists.
        /// </summary>
        public void RemoveMandatoryLabel()
        {
            Ace label = GetMandatoryLabel();
            if (label != null)
            {
                Sacl.Remove(label);
            }
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
            MapAcl(Dacl, generic_mapping);
            MapAcl(Sacl, generic_mapping);
        }

        /// <summary>
        /// Modifies a security descriptor from a new descriptor.
        /// </summary>
        /// <param name="security_descriptor">The security descriptor to update with.</param>
        /// <param name="security_information">The parts of the security descriptor to update.</param>
        /// <param name="flags">Auto inherit flags.</param>
        /// <param name="token">Optional token for the security descriptor.</param>
        /// <param name="generic_mapping">Generic mapping.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Modify(
            SecurityDescriptor security_descriptor,
            SecurityInformation security_information,
            SecurityAutoInheritFlags flags,
            NtToken token,
            GenericMapping generic_mapping,
            bool throw_on_error)
        {
            if (security_descriptor == null)
            {
                throw new ArgumentNullException(nameof(security_descriptor));
            }

            using (var list = new DisposableList())
            {
                var object_sd = list.AddResource(new SafeProcessHeapBuffer(ToByteArray()));
                var modify_sd = list.AddResource(security_descriptor.ToSafeBuffer());

                IntPtr ptr = object_sd.DangerousGetHandle();
                try
                {
                    NtStatus status = NtRtl.RtlSetSecurityObjectEx(security_information,
                        modify_sd, ref ptr, flags, ref generic_mapping, token.GetHandle());
                    if (status.IsSuccess())
                    {
                        MoveFrom(new SecurityDescriptor(ptr) { NtType = NtType }, false);
                    }
                    return status.ToNtException(throw_on_error);
                }
                finally
                {
                    if (ptr != object_sd.DangerousGetHandle())
                    {
                        object_sd.SetHandleAsInvalid();
                        NtHeap.Current.Free(HeapAllocFlags.None, ptr.ToInt64());
                    }
                }
            }
        }

        /// <summary>
        /// Modifies a security descriptor from a new descriptor.
        /// </summary>
        /// <param name="security_descriptor">The security descriptor to update with.</param>
        /// <param name="security_information">The parts of the security descriptor to update.</param>
        /// <param name="flags">Auto inherit flags.</param>
        /// <param name="token">Optional token for the security descriptor.</param>
        /// <param name="generic_mapping">Generic mapping.</param>
        public void Modify(
            SecurityDescriptor security_descriptor,
            SecurityInformation security_information,
            SecurityAutoInheritFlags flags,
            NtToken token,
            GenericMapping generic_mapping)
        {
            Modify(security_descriptor, security_information, 
                flags, token, generic_mapping, true);
        }

        /// <summary>
        /// Converts the SD to an Auto-Inherit security descriptor.
        /// </summary>
        /// <param name="parent_descriptor">The parent security descriptor.</param>
        /// <param name="object_type">Optional object type GUID.</param>
        /// <param name="is_directory">True if a directory.</param>
        /// <param name="generic_mapping">Generic mapping for the object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus ConvertToAutoInherit(
                SecurityDescriptor parent_descriptor,
                Guid? object_type,
                bool is_directory,
                GenericMapping generic_mapping,
                bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var parent = list.AddResource(parent_descriptor?.ToSafeBuffer() ?? SafeHGlobalBuffer.Null);
                var current = list.AddResource(ToSafeBuffer());
                var guid = object_type.HasValue ? new OptionalGuid(object_type.Value) : null;
                NtStatus status = NtRtl.RtlConvertToAutoInheritSecurityObject(parent, current, out SafeProcessHeapBuffer new_sd,
                    guid, is_directory, ref generic_mapping).ToNtException(throw_on_error);
                using (new_sd)
                {
                    if (!status.IsSuccess())
                        return status;
                    var sd = Parse(new_sd, NtType, Container, throw_on_error);
                    if (!sd.IsSuccess)
                        return sd.Status;
                    MoveFrom(sd.Result, false);
                    return NtStatus.STATUS_SUCCESS;
                }
            }
        }

        /// <summary>
        /// Converts the SD to an Auto-Inherit security descriptor.
        /// </summary>
        /// <param name="parent_descriptor">The parent security descriptor.</param>
        /// <param name="object_type">Optional object type GUID.</param>
        /// <param name="is_directory">True if a directory.</param>
        /// <param name="generic_mapping">Generic mapping for the object.</param>
        public void ConvertToAutoInherit(
                SecurityDescriptor parent_descriptor,
                Guid? object_type,
                bool is_directory,
                GenericMapping generic_mapping)
        {
            ConvertToAutoInherit(parent_descriptor, 
                object_type, is_directory, generic_mapping, true);
        }

        /// <summary>
        /// Canonicalize the DACL if it exists.
        /// </summary>
        public void CanonicalizeDacl()
        {
            if (Dacl == null || Dacl.NullAcl)
                return;
            Dacl.Canonicalize(true);
        }

        /// <summary>
        /// Canonicalize the SACL if it exists.
        /// </summary>
        public void CanonicalizeSacl()
        {
            if (Sacl == null || Sacl.NullAcl)
                return;
            Sacl.Canonicalize(false);
        }

        /// <summary>
        /// Clone the security descriptor.
        /// </summary>
        /// <returns>The cloned security descriptor.</returns>
        public SecurityDescriptor Clone()
        {
            SecurityDescriptor ret = new SecurityDescriptor();
            ret.MoveFrom(this, true);
            return ret;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The security descriptor as an SDDL string.</returns>
        public override string ToString()
        {
            return ToSddl(false).GetResultOrDefault(string.Empty);
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
        /// Constructor.
        /// </summary>
        /// <param name="type">The NT type for the security descriptor.</param>
        public SecurityDescriptor(NtType type) : this()
        {
            NtType = type;
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
        /// <param name="token">The token to use for its default DACL.</param>
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
        [Obsolete("Use Create for a New Security Descriptor")]
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
            SafeProcessHeapBuffer security_obj = null;
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
        {
            using (var buffer = NtSecurity.SddlToSecurityDescriptorBuffer(sddl))
            {
                ParseSecurityDescriptor(buffer).ToNtException();
            }
            NtType = type;
        }
        #endregion

        #region Static Methods

        /// <summary>
        /// Parse a security descriptor.
        /// </summary>
        /// <param name="ptr">Native pointer to security descriptor.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The parsed Security Descriptor.</returns>
        public static NtResult<SecurityDescriptor> Parse(IntPtr ptr, bool throw_on_error)
        {
            return Parse(new SafeHGlobalBuffer(ptr, 0, false), throw_on_error);
        }

        /// <summary>
        /// Parse a security descriptor.
        /// </summary>
        /// <param name="buffer">Safe buffer to security descriptor.</param>
        /// <param name="type">The NT type for the security descriptor.</param>
        /// <param name="container">True if the security descriptor is from a container.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The parsed Security Descriptor.</returns>
        public static NtResult<SecurityDescriptor> Parse(SafeBuffer buffer, NtType type, bool container, bool throw_on_error)
        {
            SecurityDescriptor sd = new SecurityDescriptor(type) { Container = container };
            return sd.ParseSecurityDescriptor(buffer).CreateResult(throw_on_error, () => sd);
        }

        /// <summary>
        /// Parse a security descriptor.
        /// </summary>
        /// <param name="buffer">Safe buffer to security descriptor.</param>
        /// <param name="type">The NT type for the security descriptor.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The parsed Security Descriptor.</returns>
        public static NtResult<SecurityDescriptor> Parse(SafeBuffer buffer, NtType type, bool throw_on_error)
        {
            return Parse(buffer, type, false, throw_on_error);
        }

        /// <summary>
        /// Parse a security descriptor.
        /// </summary>
        /// <param name="buffer">Safe buffer to security descriptor.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The parsed Security Descriptor.</returns>
        public static NtResult<SecurityDescriptor> Parse(SafeBuffer buffer, bool throw_on_error)
        {
            return Parse(buffer, null, throw_on_error);
        }

        /// <summary>
        /// Parse a security descriptor.
        /// </summary>
        /// <param name="security_descriptor">Binary form of security descriptor</param>
        /// <param name="type">The NT type for the security descriptor.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The parsed Security Descriptor.</returns>
        public static NtResult<SecurityDescriptor> Parse(byte[] security_descriptor, NtType type, bool throw_on_error)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(security_descriptor))
            {
                return Parse(buffer, type, throw_on_error);
            }
        }

        /// <summary>
        /// Parse a security descriptor.
        /// </summary>
        /// <param name="security_descriptor">Binary form of security descriptor</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The parsed Security Descriptor.</returns>
        public static NtResult<SecurityDescriptor> Parse(byte[] security_descriptor, bool throw_on_error)
        {
            return Parse(security_descriptor, null, throw_on_error);
        }

        /// <summary>
        /// Parse a security descriptor.
        /// </summary>
        /// <param name="sddl">The SDDL form of the security descriptor.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The parsed Security Descriptor.</returns>
        public static NtResult<SecurityDescriptor> Parse(string sddl, bool throw_on_error)
        {
            return NtSecurity.SddlToSecurityDescriptor(sddl, throw_on_error).Map(ba => new SecurityDescriptor(ba));
        }

        /// <summary>
        /// Parse a security descriptor from a base64 string
        /// </summary>
        /// <param name="base64">The base64 string.</param>
        /// <param name="type">The NT type for the security descriptor.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The parsed Security Descriptor.</returns>
        public static NtResult<SecurityDescriptor> ParseBase64(string base64, NtType type, bool throw_on_error)
        {
            try
            {
                return Parse(Convert.FromBase64String(base64), type, throw_on_error);
            }
            catch (FormatException)
            {
                return NtStatus.STATUS_INVALID_SECURITY_DESCR.CreateResultFromError<SecurityDescriptor>(throw_on_error);
            }
        }

        /// <summary>
        /// Parse a security descriptor from a base64 string
        /// </summary>
        /// <param name="base64">The base64 string.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The parsed Security Descriptor.</returns>
        public static NtResult<SecurityDescriptor> ParseBase64(string base64, bool throw_on_error)
        {
            return ParseBase64(base64, null, throw_on_error);
        }

        /// <summary>
        /// Parse a security descriptor from a base64 string
        /// </summary>
        /// <param name="base64">The base64 string.</param>
        /// <returns>The parsed Security Descriptor.</returns>
        public static SecurityDescriptor ParseBase64(string base64)
        {
            return ParseBase64(base64, true).Result;
        }

        /// <summary>
        /// Create a new security descriptor from a parent.
        /// </summary>
        /// <param name="parent">The parent security descriptor. Can be null.</param>
        /// <param name="creator">The creator security descriptor.</param>
        /// <param name="object_types">Optional list of object type GUIDs.</param>
        /// <param name="is_directory">True if the objec to assign is a directory.</param>
        /// <param name="flags">Auto inherit flags.</param>
        /// <param name="token">Optional token for the security descriptor.</param>
        /// <param name="generic_mapping">Generic mapping.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The new security descriptor.</returns>
        public static NtResult<SecurityDescriptor> Create(
            SecurityDescriptor parent,
            SecurityDescriptor creator,
            Guid[] object_types,
            bool is_directory,
            SecurityAutoInheritFlags flags,
            NtToken token,
            GenericMapping generic_mapping,
            bool throw_on_error)
        {
            using (var buffer = CreateBuffer(parent, creator, object_types, is_directory, 
                flags, token, generic_mapping, throw_on_error))
            {
                if (!buffer.IsSuccess)
                {
                    return buffer.Cast<SecurityDescriptor>();
                }
                return Parse(buffer.Result, null, is_directory, throw_on_error);
            }
        }

        /// <summary>
        /// Create a new security descriptor from a parent.
        /// </summary>
        /// <param name="parent">The parent security descriptor. Can be null.</param>
        /// <param name="creator">The creator security descriptor.</param>
        /// <param name="object_types">Optional list of object type GUIDs.</param>
        /// <param name="is_directory">True if the objec to assign is a directory.</param>
        /// <param name="flags">Auto inherit flags.</param>
        /// <param name="token">Optional token for the security descriptor.</param>
        /// <param name="generic_mapping">Generic mapping.</param>
        /// <returns>The new security descriptor.</returns>
        public static SecurityDescriptor Create(
            SecurityDescriptor parent,
            SecurityDescriptor creator,
            Guid[] object_types,
            bool is_directory,
            SecurityAutoInheritFlags flags,
            NtToken token,
            GenericMapping generic_mapping)
        {
            return Create(parent, creator, object_types, is_directory, flags, token, generic_mapping, true).Result;
        }

        /// <summary>
        /// Create a new security descriptor from a parent.
        /// </summary>
        /// <param name="parent">The parent security descriptor. Can be null.</param>
        /// <param name="creator">The creator security descriptor.</param>
        /// <param name="is_directory">True if the objec to assign is a directory.</param>
        /// <param name="flags">Auto inherit flags.</param>
        /// <param name="token">Optional token for the security descriptor.</param>
        /// <param name="generic_mapping">Generic mapping.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The new security descriptor.</returns>
        public static NtResult<SecurityDescriptor> Create(
            SecurityDescriptor parent,
            SecurityDescriptor creator,
            bool is_directory,
            SecurityAutoInheritFlags flags,
            NtToken token,
            GenericMapping generic_mapping,
            bool throw_on_error)
        {
            return Create(parent, creator, null, is_directory, flags, token, generic_mapping, throw_on_error);
        }

        /// <summary>
        /// Create a new security descriptor from a parent.
        /// </summary>
        /// <param name="parent">The parent security descriptor. Can be null.</param>
        /// <param name="creator">The creator security descriptor.</param>
        /// <param name="is_directory">True if the objec to assign is a directory.</param>
        /// <param name="flags">Auto inherit flags.</param>
        /// <param name="token">Optional token for the security descriptor.</param>
        /// <param name="generic_mapping">Generic mapping.</param>
        /// <returns>The new security descriptor.</returns>
        public static SecurityDescriptor Create(
            SecurityDescriptor parent,
            SecurityDescriptor creator,
            bool is_directory,
            SecurityAutoInheritFlags flags,
            NtToken token,
            GenericMapping generic_mapping)
        {
            return Create(parent, creator, is_directory, flags, token, generic_mapping, true).Result;
        }

        /// <summary>
        /// Create a new security descriptor from a parent.
        /// </summary>
        /// <param name="parent_object">The parent security descriptor. Can be null.</param>
        /// <param name="creator">The creator security descriptor.</param>
        /// <param name="is_directory">True if the objec to assign is a directory.</param>
        /// <param name="flags">Auto inherit flags.</param>
        /// <param name="token">Optional token for the security descriptor.</param>
        /// <param name="generic_mapping">Generic mapping.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The new security descriptor.</returns>
        public static NtResult<SecurityDescriptor> Create(
            NtObject parent_object,
            SecurityDescriptor creator,
            bool is_directory,
            SecurityAutoInheritFlags flags,
            NtToken token,
            GenericMapping generic_mapping,
            bool throw_on_error)
        {
            var parent_sd = parent_object?.GetSecurityDescriptor(SecurityInformation.AllBasic, throw_on_error);
            if (parent_sd.HasValue && !parent_sd.Value.IsSuccess)
            {
                return parent_sd.Value.Cast<SecurityDescriptor>();
            }
            return Create(parent_sd?.Result, creator, null, is_directory, flags, token, generic_mapping, throw_on_error);
        }

        /// <summary>
        /// Create a new security descriptor from a parent.
        /// </summary>
        /// <param name="parent_object">The parent security descriptor. Can be null.</param>
        /// <param name="creator">The creator security descriptor.</param>
        /// <param name="is_directory">True if the objec to assign is a directory.</param>
        /// <param name="flags">Auto inherit flags.</param>
        /// <param name="token">Optional token for the security descriptor.</param>
        /// <param name="generic_mapping">Generic mapping.</param>
        /// <returns>The new security descriptor.</returns>
        public static SecurityDescriptor Create(
            NtObject parent_object,
            SecurityDescriptor creator,
            bool is_directory,
            SecurityAutoInheritFlags flags,
            NtToken token,
            GenericMapping generic_mapping)
        {
            return Create(parent_object, creator, is_directory, flags, token, generic_mapping, true).Result;
        }

        #endregion
    }
}
