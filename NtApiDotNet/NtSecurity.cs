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
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// Access rights generic mapping.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct GenericMapping
    {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;

        /// <summary>
        /// Map a generic access mask to a specific one.
        /// </summary>
        /// <param name="mask">The generic mask to map.</param>
        /// <returns>The mapped mask.</returns>
        public uint MapMask(uint mask)
        {
            NtRtl.RtlMapGenericMask(ref mask, ref this);
            return mask;
        }

        /// <summary>
        /// Convert generic mapping to a string.
        /// </summary>
        /// <returns>The generic mapping as a string.</returns>
        public override string ToString()
        {
            return String.Format("R:{0:X08} W:{1:X08} E:{2:X08} A:{3:X08}",
                GenericRead, GenericWrite, GenericExecute, GenericAll);
        }
    }

    /// <summary>
    /// Security information class for security descriptors.
    /// </summary>
    [Flags]
    public enum SecurityInformation : uint
    {
        Owner = 1,
        Group = 2,
        Dacl = 4,
        Sacl = 8,
        Label = 0x10,
        Attribute = 0x20,
        Scope = 0x40,
        ProcessTrustLabel = 0x80,
        Backup = 0x10000,
        ProtectedDacl = 0x80000000,
        ProtectedSacl = 0x40000000,
        UnprotectedDacl = 0x20000000,
        UnprotectedSacl = 0x1000000,
        AllBasic = Dacl | Owner | Group | Label,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityDescriptorStructure
    {
        public byte Revision;
        public byte Sbz1;
        public ushort Control;
        public IntPtr Owner;
        public IntPtr Group;
        public IntPtr Sacl;
        public IntPtr Dacl;
    }

    public enum AclInformationClass
    {
        AclRevisionInformation = 1,
        AclSizeInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AclRevisionInformation
    {
        public AclRevision AclRevision;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AclSizeInformation
    {
        public int AceCount;
        public int AclBytesInUse;
        public int AclBytesFree;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Privilege")]
    public struct PrivilegeSet
    {
        public int PrivilegeCount;
        public int Control;
        [MarshalAs(UnmanagedType.ByValArray)]
        public LuidAndAttributes[] Privilege;
    }

    public class SafePrivilegeSetBuffer : SafeStructureArrayBuffer<PrivilegeSet>
    {
        public SafePrivilegeSetBuffer(int count)
            : base(new PrivilegeSet() { Privilege = new LuidAndAttributes[1] })
        {
        }

        public SafePrivilegeSetBuffer() : this(1)
        {
        }

        public SafePrivilegeSetBuffer(PrivilegeSet set) : base(set)
        {
        }
    }

    public static partial class NtRtl
    {
        public const uint SecurityDescriptorRevision = 1;

        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlIdentifierAuthoritySid(IntPtr sid);

        [DllImport("ntdll.dll")]
        public static extern int RtlLengthSid(IntPtr sid);

        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlSubAuthorityCountSid(IntPtr sid);

        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlSubAuthoritySid(IntPtr Sid, int SubAuthority);

        [DllImport("ntdll.dll")]
        public static extern int RtlLengthRequiredSid(int SubAuthorityCount);

        [DllImport("ntdll.dll")]
        [return: MarshalAs(UnmanagedType.U1)]
        public static extern bool RtlValidSid(IntPtr Sid);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlInitializeSid(IntPtr Sid, SidIdentifierAuthority IdentifierAuthority, byte SubAuthorityCount);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlAllocateAndInitializeSidEx(SidIdentifierAuthority IdentifierAuthority,
            byte SubAuthorityCount, [Out] uint[] SubAuthorities, out SafeSidBufferHandle Sid);

        [DllImport("ntdll.dll")]
        public static extern void RtlFreeSid(IntPtr sid);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlConvertSidToUnicodeString(ref UnicodeStringOut UnicodeString, IntPtr Sid, bool AllocateString);

        [DllImport("ntdll.dll")]
        [return: MarshalAs(UnmanagedType.U1)]
        public static extern bool RtlEqualPrefixSid(SafeSidBufferHandle Sid1, SafeSidBufferHandle Sid2);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlGetControlSecurityDescriptor(SafeBuffer SecurityDescriptor, out SecurityDescriptorControl Control, out uint Revision);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlCreateSecurityDescriptor(SafeBuffer SecurityDescriptor, uint Revision);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlGetDaclSecurityDescriptor(SafeBuffer SecurityDescriptor, out bool DaclPresent, out IntPtr Dacl, out bool DaclDefaulted);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlGetGroupSecurityDescriptor(SafeBuffer SecurityDescriptor, out IntPtr Group, out bool GroupDefaulted);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlGetOwnerSecurityDescriptor(SafeBuffer SecurityDescriptor, out IntPtr Owner, out bool OwnerDefaulted);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlGetSaclSecurityDescriptor(SafeBuffer SecurityDescriptor, out bool SaclPresent, out IntPtr Sacl, out bool SaclDefaulted);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlGetSecurityDescriptorRMControl(SafeBuffer SecurityDescriptor, out byte RmControl);

        [DllImport("ntdll.dll")]
        public static extern int RtlLengthSecurityDescriptor(SafeBuffer SecurityDescriptor);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlSetDaclSecurityDescriptor(SafeBuffer SecurityDescriptor, bool DaclPresent, IntPtr Dacl, bool DaclDefaulted);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlSetSaclSecurityDescriptor(SafeBuffer SecurityDescriptor, bool SaclPresent, IntPtr Sacl, bool SaclDefaulted);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlSetGroupSecurityDescriptor(SafeBuffer SecurityDescriptor, IntPtr Group, bool GroupDefaulted);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlSetOwnerSecurityDescriptor(SafeBuffer SecurityDescriptor, IntPtr Owner, bool OwnerDefaulted);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlSetControlSecurityDescriptor(SafeBuffer SecurityDescriptor, SecurityDescriptorControl Control, SecurityDescriptorControl ControlMask);

        [DllImport("ntdll.dll")]
        [return: MarshalAs(UnmanagedType.U1)]
        public static extern bool RtlValidRelativeSecurityDescriptor(SafeBuffer SecurityDescriptorInput, int SecurityDescriptorLength, SecurityInformation RequiredInformation);

        [DllImport("ntdll.dll")]
        [return: MarshalAs(UnmanagedType.U1)]
        public static extern bool RtlValidSecurityDescriptor(SafeBuffer SecurityDescriptor);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlQueryInformationAcl(IntPtr Acl, SafeBuffer AclInformation, int Length, AclInformationClass AclInformationClass);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlGetAce(IntPtr Acl, int AceIndex, out IntPtr Ace);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlCreateAcl(SafeBuffer Acl, int AclLength, AclRevision AclRevision);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlAddAce(SafeBuffer Acl, AclRevision AceRevision, uint StartingAceIndex, byte[] AceList, int AceListLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlAbsoluteToSelfRelativeSD(SafeBuffer AbsoluteSecurityDescriptor, SafeBuffer SelfRelativeSecurityDescriptor, ref int BufferLength);

        [DllImport("ntdll.dll")]
        public static extern void RtlMapGenericMask(ref uint AccessMask, ref GenericMapping mapping);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlDeleteSecurityObject(ref IntPtr ObjectDescriptor);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlNewSecurityObject(SafeBuffer ParentDescriptor,
                     SafeBuffer CreatorDescriptor,
                     out SafeSecurityObjectHandle NewDescriptor,
                     bool IsDirectoryObject,
                     SafeKernelObjectHandle Token,
                     ref GenericMapping GenericMapping);
    }

    public static partial class NtSystemCalls
    {

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAccessCheck(
            SafeBuffer SecurityDescriptor,
            SafeHandle ClientToken,
            uint DesiredAccess,
            ref GenericMapping GenericMapping,
            SafePrivilegeSetBuffer RequiredPrivilegesBuffer,
            ref int BufferLength,
            out uint GrantedAccess,
            out NtStatus AccessStatus);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AceHeader
    {
        public AceType AceType;
        public AceFlags AceFlags;
        public ushort AceSize;
    }

    public enum AceType : byte
    {
        Allowed = 0x0,
        Denied = 0x1,
        Audit = 0x2,
        Alerm = 0x3,
        AllowedCompound = 0x4,
        AllowedObject = 0x5,
        DeniedObject = 0x6,
        AuditObject = 0x7,
        AlarmObject = 0x8,
        AllowedCallback = 0x9,
        DeniedCallback = 0xA,
        AllowedCallbackObject = 0xB,
        DeniedCallbackObject = 0xC,
        AuditCallback = 0xD,
        AlarmCallback = 0xE,
        AuditCallbackObject = 0xF,
        AlarmCallbackObject = 0x10,
        MandatoryLabel = 0x11,
        ResourceAttribute = 0x12,
        ScopedPolicyId = 0x13,
        ProcessTrustLabel = 0x14,
    }

    [Flags]
    public enum AceFlags : byte
    {
        None = 0,
        ObjectInherit = 0x1,
        ContainerInherit = 0x2,
        NoPropagateInherit = 0x4,
        InheritOnly = 0x8,
        Inherited = 0x10,
        SuccessfulAccess = 0x40,
        FailedAccess = 0x80,
    }

    [Flags]
    public enum MandatoryLabelPolicy : uint
    {
        NoWriteUp = 0x1,
        NoReadUp = 0x2,
        NoExecuteUp = 0x4,
    }

    [Flags]
    public enum ObjectAceFlags : uint
    {
        None = 0,
        ObjectTypePresent = 0x1,
        InheritedObjectTypePresent = 0x2,
    }

    public sealed class Ace
    {
        public bool IsObjectAce()
        {
            switch (AceType)
            {
                case AceType.AlarmCallbackObject:
                case AceType.AllowedCallbackObject:
                case AceType.AllowedObject:
                case AceType.AuditCallbackObject:
                case AceType.AuditObject:
                case AceType.DeniedCallbackObject:
                    return true;
            }
            return false;
        }

        internal Ace(BinaryReader reader)
        {
            long current_position = reader.BaseStream.Position;
            AceType = (AceType)reader.ReadByte();
            AceFlags = (AceFlags)reader.ReadByte();
            int ace_size = reader.ReadUInt16();
            Mask = reader.ReadUInt32();
            if (IsObjectAce())
            {
                ObjectAceFlags flags = (ObjectAceFlags)reader.ReadUInt32();
                if ((flags & ObjectAceFlags.ObjectTypePresent) != 0)
                {
                    ObjectType = new Guid(reader.ReadAllBytes(16));
                }
                if ((flags & ObjectAceFlags.InheritedObjectTypePresent) != 0)
                {
                    InheritedObjectType = new Guid(reader.ReadAllBytes(16));
                }
            }
            int bytes_used = (int)(reader.BaseStream.Position - current_position);
            Sid = new Sid(reader.ReadAllBytes(ace_size - bytes_used));
            // Also RM additional data?
        }

        internal void Serialize(BinaryWriter writer)
        {
            // Length = sizeof(AceHeader) + sizeof(Mask) + ObjectAceData + Sid
            byte[] sid_data = Sid.ToArray();
            int total_length = 4 + 4 + sid_data.Length;
            ObjectAceFlags flags = ObjectAceFlags.None;
            if (IsObjectAce())
            {
                // For Flags
                total_length += 4;
                if (ObjectType.HasValue)
                {
                    total_length += 16;
                    flags |= ObjectAceFlags.ObjectTypePresent;
                }
                if (InheritedObjectType.HasValue)
                {
                    total_length += 16;
                    flags |= ObjectAceFlags.InheritedObjectTypePresent;
                }
            }
            if (total_length > ushort.MaxValue)
            {
                throw new ArgumentOutOfRangeException("Total ACE length greater than maximum");
            }

            writer.Write((byte)AceType);
            writer.Write((byte)AceFlags);
            writer.Write((ushort)total_length);
            writer.Write(Mask);
            if (IsObjectAce())
            {
                writer.Write((uint)flags);
                if (ObjectType.HasValue)
                {
                    writer.Write(ObjectType.Value.ToByteArray());
                }
                if (InheritedObjectType.HasValue)
                {
                    writer.Write(InheritedObjectType.Value.ToByteArray());
                }
            }
            writer.Write(sid_data);
        }

        public AceType AceType { get; set; }
        public AceFlags AceFlags { get; set; }
        public uint Mask { get; set; }
        public Sid Sid { get; set; }
        public Guid? ObjectType { get; set; }
        public Guid? InheritedObjectType { get; set; }

        public override string ToString()
        {
            return String.Format("Type {0} - Flags {1} - Mask {2:X08} - Sid {3}",
                AceType, AceFlags, Mask, Sid);
        }

        public string ToString(Type access_rights_type, bool resolve_sid)
        {
            object mask = Enum.ToObject(access_rights_type, Mask);
            string account = Sid.ToString();
            if (resolve_sid)
            {
                account = NtSecurity.LookupAccountSid(Sid) ?? Sid.ToString();
            }
            return String.Format("Type {0} - Flags {1} - Mask {2} - Sid {3}",
                AceType, AceFlags, mask, account);
        }

        public override bool Equals(object obj)
        {
            if (Object.ReferenceEquals(obj, this))
            {
                return true;
            }

            Ace ace = obj as Ace;
            if (ace == null)
            {
                return false;
            }

            return ace.AceType == AceType && ace.AceFlags == AceFlags && ace.Sid == Sid && ace.Mask == Mask
                && ace.ObjectType == ObjectType && ace.InheritedObjectType == InheritedObjectType;
        }

        public override int GetHashCode()
        {
            return AceType.GetHashCode() ^ AceFlags.GetHashCode() ^ Mask.GetHashCode() ^ Sid.GetHashCode() ^ ObjectType.GetHashCode() ^ InheritedObjectType.GetHashCode();
        }

        public static bool operator ==(Ace a, Ace b)
        {
            if (Object.ReferenceEquals(a, b))
            {
                return true;
            }

            if (Object.ReferenceEquals(a, null))
            {
                return false;
            }

            if (Object.ReferenceEquals(b, null))
            {
                return false;
            }

            return a.Equals(b);
        }

        public static bool operator !=(Ace a, Ace b)
        {
            return !(a == b);
        }

        public Ace(AceType type, AceFlags flags, uint mask, Sid sid)
        {
            AceType = type;
            AceFlags = flags;
            Mask = mask;
            Sid = sid;
        }

        public Ace(AceType type, AceFlags flags, GenericAccessRights mask, Sid sid)
            : this(type, flags, (uint)mask, sid)
        {
        }
    }

    public enum AclRevision
    {
        Revision = 2,
        RevisionDS = 4,
    }

    public struct AclStructure
    {
        public byte AclRevision;
        public byte Sbz1;
        public ushort AclSize;
        public ushort AceCount;
        public ushort Sbz2;
    }

    public sealed class Acl : List<Ace>
    {
        static T GetAclInformation<T>(IntPtr acl, AclInformationClass info_class) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                NtRtl.RtlQueryInformationAcl(acl, buffer, buffer.Length, info_class).ToNtException();
                return buffer.Result;
            }
        }

        private void ParseAcl(IntPtr acl)
        {
            AclSizeInformation size_info = GetAclInformation<AclSizeInformation>(acl, AclInformationClass.AclSizeInformation);
            using (SafeBuffer buffer = new SafeHGlobalBuffer(acl, size_info.AclBytesInUse, false))
            {
                using (BinaryReader reader = new BinaryReader(new UnmanagedMemoryStream(buffer, 0, size_info.AclBytesInUse)))
                {
                    for (int i = 0; i < size_info.AceCount; ++i)
                    {
                        IntPtr ace;
                        NtRtl.RtlGetAce(acl, i, out ace).ToNtException();
                        reader.BaseStream.Position = ace.ToInt64() - acl.ToInt64();
                        Add(new Ace(reader));
                    }
                }
            }
            Revision = GetAclInformation<AclRevisionInformation>(acl, AclInformationClass.AclRevisionInformation).AclRevision;
        }

        public Acl(IntPtr acl, bool defaulted)
        {
            if (acl != IntPtr.Zero)
            {
                ParseAcl(acl);
            }
            else
            {
                NullAcl = true;
            }

            Defaulted = defaulted;
        }

        public Acl(bool defaulted) : this(IntPtr.Zero, defaulted)
        {
            Defaulted = defaulted;
        }

        public Acl() : this(new Ace[0], false)
        {
        }

        public Acl(IEnumerable<Ace> aces, bool defaulted) : base(aces)
        {
            Defaulted = defaulted;
        }

        public Acl(IEnumerable<Ace> aces) : this(aces, false)
        {
        }

        public bool Defaulted { get; set; }
        public bool NullAcl { get; set; }
        public AclRevision Revision { get; set; }

        public byte[] ToByteArray()
        {
            MemoryStream ace_stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(ace_stm);
            AclRevision revision = Revision;
            if (revision != AclRevision.Revision || revision != AclRevision.RevisionDS)
            {
                revision = AclRevision.Revision;
            }
            foreach (Ace ace in this)
            {
                ace.Serialize(writer);
                if (ace.IsObjectAce())
                {
                    revision = AclRevision.RevisionDS;
                }
            }
            byte[] aces = ace_stm.ToArray();

            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(Marshal.SizeOf(typeof(AclStructure)) + aces.Length))
            {
                NtRtl.RtlCreateAcl(buffer, buffer.Length, revision).ToNtException();
                NtRtl.RtlAddAce(buffer, revision, uint.MaxValue, aces, aces.Length).ToNtException();
                return buffer.ToArray();
            }
        }

        public SafeHGlobalBuffer ToSafeBuffer()
        {
            if (!NullAcl)
            {
                return new SafeHGlobalBuffer(ToByteArray());
            }
            else
            {
                return SafeHGlobalBuffer.Null;
            }
        }

        public void AddAccessAllowedAce(GenericAccessRights mask, AceFlags flags, string sid)
        {
            AddAccessAllowedAce((uint)mask, flags, sid);
        }

        public void AddAccessAllowedAce(uint mask, AceFlags flags, string sid)
        {
            Add(new Ace(AceType.Allowed, flags, mask, new Sid(sid)));
        }

        public void AddAccessAllowedAce(uint mask, string sid)
        {
            AddAccessAllowedAce(mask, AceFlags.None, sid);
        }

        public void AddAccessAllowedAce(GenericAccessRights mask, string sid)
        {
            AddAccessAllowedAce(mask, AceFlags.None, sid);
        }

        public void AddAccessDeniedAce(uint mask, AceFlags flags, string sid)
        {
            Add(new Ace(AceType.Denied, flags, mask, new Sid(sid)));
        }

        public void AddAccessDeniedAce(GenericAccessRights mask, AceFlags flags, string sid)
        {
            AddAccessDeniedAce((uint)mask, flags, sid);
        }

        public void AddAccessDeniedAce(uint mask, string sid)
        {
            AddAccessDeniedAce(mask, AceFlags.None, sid);
        }

        public void AddAccessDeniedAce(GenericAccessRights mask, string sid)
        {
            AddAccessDeniedAce(mask, AceFlags.None, sid);
        }

        public void AddAccessAllowedAce(GenericAccessRights mask, AceFlags flags, Sid sid)
        {
            AddAccessAllowedAce((uint)mask, flags, sid);
        }

        public void AddAccessAllowedAce(uint mask, AceFlags flags, Sid sid)
        {
            Add(new Ace(AceType.Allowed, flags, mask, sid));
        }

        public void AddAccessAllowedAce(uint mask, Sid sid)
        {
            AddAccessAllowedAce(mask, AceFlags.None, sid);
        }

        public void AddAccessAllowedAce(GenericAccessRights mask, Sid sid)
        {
            AddAccessAllowedAce(mask, AceFlags.None, sid);
        }

        public void AddAccessDeniedAce(uint mask, AceFlags flags, Sid sid)
        {
            Add(new Ace(AceType.Denied, flags, mask, sid));
        }

        public void AddAccessDeniedAce(GenericAccessRights mask, AceFlags flags, Sid sid)
        {
            AddAccessDeniedAce((uint)mask, flags, sid);
        }

        public void AddAccessDeniedAce(uint mask, Sid sid)
        {
            AddAccessDeniedAce(mask, AceFlags.None, sid);
        }

        public void AddAccessDeniedAce(GenericAccessRights mask, Sid sid)
        {
            AddAccessDeniedAce(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Gets an indication if this ACL is canonical.
        /// </summary>
        /// <returns>True if the ACL is canonical.</returns>
        public bool IsCanonical()
        {
            Acl acl = Canonicalize();
            if (acl.Count != Count)
            {
                return false;
            }

            for (int i = 0; i < acl.Count; ++i)
            {
                if (this[i] != acl[i])
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Canonicalize the ACL (for use on DACLs only).
        /// </summary>
        /// <remarks>This isn't a general purpose algorithm, for example it doesn't worry much about object ordering.
        /// Also it can be lossy, if it doesn't understand an ACE type it will drop it.</remarks>
        /// <returns>The canonical ACL.</returns>
        public Acl Canonicalize()
        {
            List<Ace> access_denied = new List<Ace>();
            List<Ace> access_allowed = new List<Ace>();
            List<Ace> inherited = new List<Ace>();

            foreach (Ace ace in this)
            {
                if ((ace.AceFlags & AceFlags.Inherited) == AceFlags.Inherited)
                {
                    inherited.Add(ace);
                }
                else
                {
                    switch (ace.AceType)
                    {
                        case AceType.Allowed:
                        case AceType.AllowedObject:
                            access_allowed.Add(ace);
                            break;
                        case AceType.Denied:
                        case AceType.DeniedObject:
                            access_denied.Add(ace);
                            break;
                    }
                }
            }

            Acl ret = new Acl();
            ret.AddRange(access_denied);
            ret.AddRange(access_allowed);
            ret.AddRange(inherited);
            return ret;
        }
    }

    public static class NtSecurity
    {
        enum SidNameUse
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer,
            SidTypeLabel
        }

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool LookupAccountSid(string lpSystemName, SafeSidBufferHandle lpSid, StringBuilder lpName,
                ref int cchName, StringBuilder lpReferencedDomainName, ref int cchReferencedDomainName, out SidNameUse peUse);

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool LookupAccountName(string lpSystemName, string lpAccountName,
            SafeBuffer Sid,
            ref int cbSid,
            SafeBuffer ReferencedDomainName,
            ref int cchReferencedDomainName,
            out SidNameUse peUse
        );

        /// <summary>
        /// Looks up the account name of a SID. 
        /// </summary>
        /// <param name="sid">The SID to lookup</param>
        /// <returns>The name, or null if the lookup failed</returns>
        public static string LookupAccountSid(Sid sid)
        {
            using (SafeSidBufferHandle sid_buffer = sid.ToSafeBuffer())
            {
                StringBuilder name = new StringBuilder(1024);
                int length = name.Capacity;
                StringBuilder domain = new StringBuilder(1024);
                int domain_length = domain.Capacity;
                SidNameUse name_use;
                if (!LookupAccountSid(null, sid_buffer, name, ref length, domain, ref domain_length, out name_use))
                {
                    return null;
                }

                if (domain_length == 0)
                {
                    return name.ToString();
                }
                else
                {
                    return String.Format("{0}\\{1}", domain, name);
                }
            }
        }

        /// <summary>
        /// Lookup a SID from a username.
        /// </summary>
        /// <param name="username">The username, can be in the form domain\account.</param>
        /// <returns>The Security Identifier.</returns>
        /// <exception cref="NtException">Thrown if account cannot be found.</exception>
        public static Sid LookupAccountName(string username)
        {
            int sid_length = 0;
            int domain_length = 0;
            SidNameUse name;
            if (!LookupAccountName(null, username, SafeHGlobalBuffer.Null, ref sid_length, 
                SafeHGlobalBuffer.Null, ref domain_length, out name))
            {
                if (sid_length <= 0)
                {
                    throw new NtException(NtStatus.STATUS_INVALID_USER_PRINCIPAL_NAME);
                }
            }

            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(sid_length), domain = new SafeHGlobalBuffer(domain_length * 2))
            {
                if (!LookupAccountName(null, username, buffer, ref sid_length, domain, ref domain_length, out name))
                {
                    throw new NtException(NtStatus.STATUS_INVALID_USER_PRINCIPAL_NAME);
                }

                return new Sid(buffer);
            }
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            byte[] SecurityDescriptor,
            int RequestedStringSDRevision,
            SecurityInformation SecurityInformation,
            out SafeLocalAllocHandle StringSecurityDescriptor,
            out int StringSecurityDescriptorLen);

        public static string SecurityDescriptorToSddl(byte[] sd, SecurityInformation security_information)
        {
            SafeLocalAllocHandle handle;
            int return_length;
            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(sd, 1, security_information, out handle, out return_length))
            {
                throw new NtException(NtStatus.STATUS_INVALID_SID);
            }

            using (handle)
            {
                return Marshal.PtrToStringUni(handle.DangerousGetHandle());
            }
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string StringSecurityDescriptor,
            int StringSDRevision,
            out SafeLocalAllocHandle SecurityDescriptor,
            out int SecurityDescriptorSize);

        public static byte[] SddlToSecurityDescriptor(string sddl)
        {
            SafeLocalAllocHandle handle;
            int return_length;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out handle, out return_length))
            {
                throw new NtException(NtStatus.STATUS_INVALID_SID);
            }

            using (handle)
            {
                byte[] ret = new byte[return_length];
                Marshal.Copy(handle.DangerousGetHandle(), ret, 0, return_length);
                return ret;
            }
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ConvertStringSidToSid(
            string StringSid,
            out SafeLocalAllocHandle Sid);

        public static Sid SidFromSddl(string sddl)
        {
            SafeLocalAllocHandle handle;
            if (!ConvertStringSidToSid(sddl, out handle))
            {
                throw new NtException(NtStatus.STATUS_INVALID_SID);
            }
            using (handle)
            {
                return new Sid(handle.DangerousGetHandle());
            }
        }

        public static uint GetAllowedAccess(SecurityDescriptor sd, NtToken token, GenericAccessRights access_rights, GenericMapping generic_mapping)
        {
            using (var sd_buffer = sd.ToSafeBuffer())
            {
                using (NtToken imp_token = token.DuplicateToken(SecurityImpersonationLevel.Identification))
                {
                    uint granted_access;
                    NtStatus result_status;
                    using (var privs = new SafePrivilegeSetBuffer())
                    {
                        int buffer_length = privs.Length;

                        NtSystemCalls.NtAccessCheck(sd_buffer, imp_token.Handle, (uint)access_rights,
                            ref generic_mapping, privs, ref buffer_length, out granted_access, out result_status).ToNtException();
                        if (result_status.IsSuccess())
                        {
                            return granted_access;
                        }
                        return 0;
                    }
                }
            }
        }

        public static uint GetMaximumAccess(SecurityDescriptor sd, NtToken token, GenericMapping generic_mapping)
        {
            return GetAllowedAccess(sd, token, GenericAccessRights.MaximumAllowed, generic_mapping);
        }

        public static uint GetAllowedAccess(SafeHandle token, NtType type, uint allowed_access, byte[] sd)
        {
            if (sd == null || sd.Length == 0)
            {
                return 0;
            }

            using (NtToken token_obj = NtToken.FromHandle(NtObject.DuplicateHandle(token)))
            {
                return GetAllowedAccess(new SecurityDescriptor(sd), token_obj, (GenericAccessRights)allowed_access, type.GenericMapping);
            }
        }

        public static uint GetAllowedAccess(NtToken token, NtType type, uint allowed_access, byte[] sd)
        {
            return GetAllowedAccess(token.Handle, type, allowed_access, sd);
        }

        public static uint GetMaximumAccess(SafeHandle token, NtType type, byte[] sd)
        {
            return GetAllowedAccess(token, type, (uint)GenericAccessRights.MaximumAllowed, sd);
        }

        public static uint GetMaximumAccess(NtToken token, NtType type, byte[] sd)
        {
            return GetMaximumAccess(token.Handle, type, sd);
        }

        public static SecurityDescriptor FromNamedResource(string name, string type)
        {
            try
            {
                using (NtObject obj = NtObject.OpenWithType(type, name, null, GenericAccessRights.ReadControl))
                {
                    return obj.GetSecurityDescriptor();
                }
            }
            catch
            {
            }

            return null;
        }

        public static Sid GetIntegritySid(int level)
        {
            return new Sid(SecurityAuthority.Label, (uint)level);
        }

        public static bool IsIntegritySid(Sid sid)
        {
            return GetIntegritySid(TokenIntegrityLevel.Untrusted).EqualPrefix(sid);
        }

        public static Sid GetIntegritySid(TokenIntegrityLevel level)
        {
            return GetIntegritySid((int)level);
        }
    }
}
