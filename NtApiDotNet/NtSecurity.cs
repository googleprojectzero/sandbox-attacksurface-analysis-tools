using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// Predefined security authorities
    /// </summary>
    public enum SecurityAuthority : byte
    {
        Null = 0,
        World = 1,
        Local = 2,
        Creator = 3,
        NonUnique = 4,
        Nt = 5,
        ResourceManager = 9,
        Package = 15,
        Label = 16,
        ScopedPolicyId = 17,
        Authentication = 18,
        ProcessTrust = 19,
    }

    [StructLayout(LayoutKind.Sequential)]
    public sealed class SidIdentifierAuthority
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        private byte[] _value;

        /// <summary>
        /// Get a reference to the identifier authority. This can be used to modify the value
        /// </summary>
        public byte[] Value
        {
            get
            {
                return _value;
            }
        }

        public SidIdentifierAuthority()
        {
            _value = new byte[6];
        }

        public SidIdentifierAuthority(byte[] authority)
        {
            if (authority.Length != 6)
            {
                throw new ArgumentOutOfRangeException("authority", "Authority must be 6 bytes in size");
            }

            _value = (byte[])authority.Clone();
        }

        public SidIdentifierAuthority(SecurityAuthority authority)
            : this(new byte[6] { 0, 0, 0, 0, 0, (byte)authority })
        {
        }

        public override bool Equals(object obj)
        {
            SidIdentifierAuthority auth = obj as SidIdentifierAuthority;
            if (auth == null)
                return false;

            if (!base.Equals(obj))
            {
                return false;
            }

            for (int i = 0; i < 6; i++)
            {
                if (_value[i] != auth._value[i])
                {
                    return false;
                }
            }

            return true;
        }

        public override int GetHashCode()
        {
            int result = 0;
            foreach (byte b in _value)
            {
                result += b;
            }
            return result;
        }
    }

    public sealed class Sid
    {
        public SidIdentifierAuthority Authority { get; private set; }
        public List<uint> SubAuthorities { get; private set; }

        private void InitializeFromPointer(IntPtr sid)
        {
            if (!NtRtl.RtlValidSid(sid))
                throw new NtException(NtStatus.STATUS_INVALID_SID);

            IntPtr authority = NtRtl.RtlIdentifierAuthoritySid(sid);
            Authority = (SidIdentifierAuthority)Marshal.PtrToStructure(authority, typeof(SidIdentifierAuthority));
            int sub_authority_count = Marshal.ReadByte(NtRtl.RtlSubAuthorityCountSid(sid));
            SubAuthorities = new List<uint>();
            for (int i = 0; i < sub_authority_count; ++i)
            {
                SubAuthorities.Add((uint)Marshal.ReadInt32(NtRtl.RtlSubAuthoritySid(sid, i), 0));
            }
        }

        public Sid(SidIdentifierAuthority authority, params uint[] sub_authorities)
        {
            Authority = new SidIdentifierAuthority(authority.Value);
            SubAuthorities = new List<uint>(sub_authorities);
        }

        public Sid(SecurityAuthority authority, params uint[] sub_authorities)
            : this(new SidIdentifierAuthority(authority), sub_authorities)
        {
        }

        public Sid(IntPtr sid)
        {
            InitializeFromPointer(sid);
        }

        public Sid(byte[] sid)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(sid))
            {
                InitializeFromPointer(buffer.DangerousGetHandle());
            }
        }

        private static byte[] SidToArray(SecurityIdentifier sid)
        {
            byte[] ret = new byte[sid.BinaryLength];
            sid.GetBinaryForm(ret, 0);
            return ret;
        }

        public Sid(SecurityIdentifier sid) : this(SidToArray(sid))
        {
        }

        public Sid(string sid) : this(new SecurityIdentifier(sid))
        {
        }

        public SafeSidBufferHandle ToSafeBuffer()
        {
            SafeSidBufferHandle sid;
            NtObject.StatusToNtException(NtRtl.RtlAllocateAndInitializeSidEx(Authority,
                (byte)SubAuthorities.Count, SubAuthorities.ToArray(), out sid));
            return sid;
        }

        public byte[] ToArray()
        {
            using (SafeSidBufferHandle handle = ToSafeBuffer())
            {
                return Utils.SafeHandleToArray(handle, handle.Length);
            }
        }

        /// <summary>
        /// Compares two sids to see if their prefixes are the same.
        /// </summary>
        /// <param name="sid">The sid to compare against</param>
        /// <returns>True if the sids share a prefix.</returns>
        public bool EqualPrefix(Sid sid)
        {
            using (SafeSidBufferHandle sid1 = ToSafeBuffer(), sid2 = sid.ToSafeBuffer())
            {
                return NtRtl.RtlEqualPrefixSid(sid1, sid2);
            }
        }

        public override bool Equals(object obj)
        {
            Sid sid = obj as Sid;
            if (sid == null)
            {
                return false;
            }

            if (Authority.Equals(sid.Authority))
            {
                return false;
            }

            if (SubAuthorities.Count != sid.SubAuthorities.Count)
            {
                return false;
            }

            for (int i = 0; i < this.SubAuthorities.Count; ++i)
            {
                if (SubAuthorities[i] != sid.SubAuthorities[i])
                {
                    return false;
                }
            }

            return true;
        }

        public static bool operator ==(Sid a, Sid b)
        {
            if (System.Object.ReferenceEquals(a, b))
            {
                return true;
            }

            if (System.Object.ReferenceEquals(a, null))
            {
                return false;
            }

            if (System.Object.ReferenceEquals(b, null))
            {
                return false;
            }

            return a.Equals(b);
        }

        public static bool operator !=(Sid a, Sid b)
        {
            return !(a == b);
        }

        public override int GetHashCode()
        {
            int sub_hash_code = 0;
            foreach (uint sub_auth in SubAuthorities)
            {
                sub_hash_code ^= sub_auth.GetHashCode();
            }
            return Authority.GetHashCode() ^ sub_hash_code;
        }

        public override string ToString()
        {
            using (SafeSidBufferHandle sid = ToSafeBuffer())
            {
                UnicodeStringOut str = new UnicodeStringOut();
                NtObject.StatusToNtException(NtRtl.RtlConvertSidToUnicodeString(ref str, sid.DangerousGetHandle(), true));
                try
                {
                    return str.ToString();
                }
                finally
                {
                    NtRtl.RtlFreeUnicodeString(ref str);
                }
            }
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

        public string GetName()
        {
            return NtSecurity.LookupAccountSid(this) ?? ToString();
        }
    }

    public static class KnownSids
    {
        public static Sid Null { get { return new Sid(SecurityAuthority.Null, 0); } }
        public static Sid World { get { return new Sid(SecurityAuthority.World, 0); } }
        public static Sid Local { get { return new Sid(SecurityAuthority.Local, 0); } }
        public static Sid CreatorOwner { get { return new Sid(SecurityAuthority.Creator, 0); } }
        public static Sid CreatorGroup { get { return new Sid(SecurityAuthority.Creator, 1); } }
        public static Sid Service { get { return new Sid(SecurityAuthority.Nt, 6); } }
        public static Sid Anonymous { get { return new Sid(SecurityAuthority.Nt, 7); } }
        public static Sid AuthenticatedUsers { get { return new Sid(SecurityAuthority.Nt, 11); } }
        public static Sid Restricted { get { return new Sid(SecurityAuthority.Nt, 12); } }
        public static Sid LocalSystem { get { return new Sid(SecurityAuthority.Nt, 18); } }
        public static Sid LocalService { get { return new Sid(SecurityAuthority.Nt, 19); } }
        public static Sid NetworkService { get { return new Sid(SecurityAuthority.Nt, 20); } }
    }

    public sealed class SafeSidBufferHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSidBufferHandle(IntPtr sid, bool owns_handle) : base(owns_handle)
        {
            SetHandle(sid);
        }

        public SafeSidBufferHandle() : base(true)
        {
        }

        public int Length
        {
            get { return NtRtl.RtlLengthSid(handle); }
        }

        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                NtRtl.RtlFreeSid(handle);
                handle = IntPtr.Zero;
            }
            return true;
        }
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
        }

        public Acl() : this(false)
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

        public void AddAccessAllowedAce(Enum mask, AceFlags flags, Sid sid)
        {
            IConvertible conv = mask;
            Add(new Ace(AceType.Allowed, flags, conv.ToUInt32(null), sid));
        }

        public void AddAccessAllowedAce(Enum mask, Sid sid)
        {
            AddAccessAllowedAce(mask, AceFlags.None, sid);
        }

        public void AddAccessDeniedAce(Enum mask, AceFlags flags, Sid sid)
        {
            IConvertible conv = mask;
            Add(new Ace(AceType.Denied, flags, conv.ToUInt32(null), sid));
        }

        public void AddAccessDeniedAce(Enum mask, Sid sid)
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

    [Flags]
    public enum SecurityDescriptorControl : ushort
    {
        OwnerDefaulted    = 0x0001,
        GroupDefaulted    = 0x0002,
        DaclPresent       = 0x0004,
        DaclDefaulted     = 0x0008,
        SaclPresent       = 0x0010,
        SaclDefaulted     = 0x0020,
        DaclAutoInheritReq= 0x0100,
        SaclAutoInheritReq= 0x0200,
        DaclAutoInherited = 0x0400,
        SaclAutoInherited = 0x0800,
        DaclProtected     = 0x1000,
        SaclProtected     = 0x2000,
        RmControlValid    = 0x4000,
        SelfRelative      = 0x8000,
        ValidControlSetMask = DaclAutoInheritReq | SaclAutoInheritReq
        | DaclAutoInherited | SaclAutoInherited | DaclProtected | SaclProtected
    }
    
    public sealed class SecurityDescriptorSid
    {
        public Sid Sid { get; private set; }
        public bool Defaulted { get; private set; }

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
            Dacl = QueryAcl(buffer, NtRtl.RtlGetDaclSecurityDescriptor);
            Sacl = QueryAcl(buffer, NtRtl.RtlGetSaclSecurityDescriptor);
        }

        public SecurityDescriptor()
        {
        }

        public SecurityDescriptor(byte[] security_descriptor)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(security_descriptor))
            {
                ParseSecurityDescriptor(buffer);
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

        [DllImport("Advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern bool LookupAccountSid(string lpSystemName, SafeSidBufferHandle lpSid, StringBuilder lpName, 
                ref int cchName, StringBuilder lpReferencedDomainName, ref int cchReferencedDomainName, out SidNameUse peUse);

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
                throw new Win32Exception();
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
                throw new Win32Exception();
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
                throw new Win32Exception();
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

        public static uint GetAllowedAccess(SafeHandle token, ObjectTypeInfo type, uint allowed_access, byte[] sd)
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

        public static uint GetAllowedAccess(NtToken token, ObjectTypeInfo type, uint allowed_access, byte[] sd)
        {
            return GetAllowedAccess(token.Handle, type, allowed_access, sd);
        }

        public static uint GetMaximumAccess(SafeHandle token, ObjectTypeInfo type, byte[] sd)
        {
            return GetAllowedAccess(token, type, (uint)GenericAccessRights.MaximumAllowed, sd);
        }

        public static uint GetMaximumAccess(NtToken token, ObjectTypeInfo type, byte[] sd)
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
    }
}
