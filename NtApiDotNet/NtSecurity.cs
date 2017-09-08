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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet
{
#pragma warning disable 1591
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

    public class CachedSigningLevel
    {
        public int Flags { get; private set; }
        public SigningLevel SigningLevel { get; private set; }
        public byte[] Thumbprint { get; private set; }
        public int ThumbprintAlgorithm { get; private set; }

        internal CachedSigningLevel(int flags, SigningLevel signing_level, byte[] thumb_print, int thumb_print_algo)
        {
            Flags = flags;
            SigningLevel = signing_level;
            Thumbprint = thumb_print;
            ThumbprintAlgorithm = thumb_print_algo;
        }
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Privilege")]
    public struct PrivilegeSet
    {
        public int PrivilegeCount;
        public int Control;
        [MarshalAs(UnmanagedType.ByValArray)]
        public LuidAndAttributes[] Privilege;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class CachedSigningLevelInformation
    {
        int Size;
        UnicodeStringIn Name;

        public CachedSigningLevelInformation(string name)
        {
            Size = Marshal.SizeOf(this);
            Name.SetString(name);
        }
    }

    public enum SigningLevel
    {
        Unchecked = 0,
        Unsigned = 1,
        DeviceGuard = 2,
        Custom1 = 3,
        Authenticode = 4,
        Custom2 = 5,
        Store = 6,
        Antimalware = 7,
        Microsoft = 8,
        Custom4 = 9,
        Custom5 = 10,
        DynamicCodeGeneration = 12,
        Windows = 13,
        WindowsProtectedProcessLight = 14,
        WindowsTCB = 15,
        Custom6 = 16
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
        public static extern NtStatus RtlAllocateAndInitializeSid(SidIdentifierAuthority IdentifierAuthority,
            byte SubAuthorityCount, uint SubAuthority0, uint SubAuthority1, uint SubAuthority2, uint SubAuthority3,
            uint SubAuthority4, uint SubAuthority5, uint SubAuthority6, uint SubAuthority7, out SafeSidBufferHandle Sid);

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
        public static extern void RtlMapGenericMask(ref AccessMask AccessMask, ref GenericMapping mapping);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlDeleteSecurityObject(ref IntPtr ObjectDescriptor);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlNewSecurityObject(SafeBuffer ParentDescriptor,
                     SafeBuffer CreatorDescriptor,
                     out SafeSecurityObjectHandle NewDescriptor,
                     bool IsDirectoryObject,
                     SafeKernelObjectHandle Token,
                     ref GenericMapping GenericMapping);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlCreateServiceSid([In] UnicodeString pServiceName, 
            SafeBuffer pServiceSid, [In, Out] ref int cbServiceSid);

        // Group SID needs 9 RIDS (0x2C bytes), Capability SID needs 10 (0x30 bytes)
        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlDeriveCapabilitySidsFromName(
            UnicodeString CapabilityName, SafeBuffer CapabilityGroupSid, SafeBuffer CapabilitySid);
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAccessCheck(
            SafeBuffer SecurityDescriptor,
            SafeKernelObjectHandle ClientToken,
            AccessMask DesiredAccess,
            ref GenericMapping GenericMapping,
            SafePrivilegeSetBuffer RequiredPrivilegesBuffer,
            ref int BufferLength,
            out AccessMask GrantedAccess,
            out NtStatus AccessStatus);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAccessCheckByType(
            SafeBuffer SecurityDescriptor,
            SafeHandle PrincipalSelfSid,
            SafeKernelObjectHandle ClientToken,
            AccessMask DesiredAccess,
            SafeBuffer ObjectTypeList,
            int ObjectTypeListLength,
            ref GenericMapping GenericMapping,
            SafePrivilegeSetBuffer RequiredPrivilegesBuffer,
            ref int BufferLength,
            out AccessMask GrantedAccess,
            out NtStatus AccessStatus);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetCachedSigningLevel(
          int  Flags, 
          SigningLevel SigningLevel,
          [In] IntPtr[] SourceFiles,
          int SourceFileCount,
          SafeKernelObjectHandle TargetFile
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetCachedSigningLevel2(
          int Flags,
          SigningLevel SigningLevel,
          [In] IntPtr[] SourceFiles,
          int SourceFileCount,
          SafeKernelObjectHandle TargetFile,
          CachedSigningLevelInformation Information
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtGetCachedSigningLevel(
          SafeKernelObjectHandle File,
          out int Flags,
          out SigningLevel SigningLevel,
          [Out] byte[] Thumbprint,
          ref int ThumbprintSize,
          out int ThumbprintAlgorithm
        );
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

    public enum PackageSidType
    {
        Unknown,
        Parent,
        Child
    }

#pragma warning restore 1591

    /// <summary>
    /// Structure for an NT access mask.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct AccessMask : IFormattable, IEquatable<AccessMask>, IComparable<AccessMask>
    {
        /// <summary>
        /// The access mask's access bits.
        /// </summary>
        public uint Access;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="access">Access bits to use</param>
        public AccessMask(uint access)
        {
            Access = access;
        }

        /// <summary>
        /// Implicit conversion from Int32.
        /// </summary>
        /// <param name="access">The access enumeration.</param>
        public static implicit operator AccessMask(int access)
        {
            return new AccessMask((uint)access);
        }

        /// <summary>
        /// Implicit conversion from UInt32.
        /// </summary>
        /// <param name="access">The access enumeration.</param>
        public static implicit operator AccessMask(uint access)
        {
            return new AccessMask(access);
        }

        /// <summary>
        /// Implicit conversion from enumerations.
        /// </summary>
        /// <param name="access">The access enumeration.</param>
        public static implicit operator AccessMask(Enum access)
        {
            return new AccessMask(((IConvertible)access).ToUInt32(null));
        }

        /// <summary>
        /// Convert access mask to a generic access object.
        /// </summary>
        /// <returns>The generic access mask</returns>
        public GenericAccessRights ToGenericAccess()
        {
            return (GenericAccessRights)Access;
        }

        /// <summary>
        /// Convert access mask to a mandatory label policy
        /// </summary>
        /// <returns>The mandatory label policy</returns>
        public MandatoryLabelPolicy ToMandatoryLabelPolicy()
        {
            return (MandatoryLabelPolicy)Access;
        }

        /// <summary>
        /// Convert to a specific access right.
        /// </summary>
        /// <typeparam name="A">The specific access right.</typeparam>
        /// <returns>The converted value.</returns>
        public A ToSpecificAccess<A>()
        {
            return (A)(object)Access;
        }

        /// <summary>
        /// Convert to a specific access right.
        /// </summary>
        /// <param name="enum_type">The type of enumeration to convert to.</param>
        /// <returns>The converted value.</returns>
        public object ToSpecificAccess(Type enum_type)
        {
            if(!enum_type.IsEnum)
                throw new ArgumentException("Type must be an Enum", "enum_type");
            return Enum.ToObject(enum_type, Access);
        }

        /// <summary>
        /// Get whether this access mask is empty (i.e. it's 0)
        /// </summary>
        public bool IsEmpty
        {
            get { return Access == 0; }
        }

        /// <summary>
        /// Get whether this access mask has not access rights, i.e. not empty.
        /// </summary>
        public bool HasAccess
        {
            get { return !IsEmpty; }
        }

        /// <summary>
        /// Get whether the current access mask is granted specific permissions.
        /// </summary>
        /// <param name="mask">The access mask to check</param>
        /// <returns>True one or more access granted.</returns>
        public bool IsAccessGranted(AccessMask mask)
        {
            return (Access & mask.Access) != 0;
        }

        /// <summary>
        /// Get whether the current access mask is granted all specific permissions.
        /// </summary>
        /// <param name="mask">The access mask to check</param>
        /// <returns>True access all is granted.</returns>
        public bool IsAllAccessGranted(AccessMask mask)
        {
            return (Access & mask.Access) == mask;
        }

        /// <summary>
        /// Bitwise AND operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <param name="mask2">Access mask 2</param>
        /// <returns>The new access mask.</returns>
        public static AccessMask operator&(AccessMask mask1, AccessMask mask2)
        {
            return new AccessMask(mask1.Access & mask2.Access);
        }

        /// <summary>
        /// Bitwise OR operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <param name="mask2">Access mask 2</param>
        /// <returns>The new access mask.</returns>
        public static AccessMask operator |(AccessMask mask1, AccessMask mask2)
        {
            return new AccessMask(mask1.Access | mask2.Access);
        }

        /// <summary>
        /// Bitwise AND operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <param name="mask2">Access mask 2</param>
        /// <returns>The new access mask.</returns>
        public static AccessMask operator &(AccessMask mask1, uint mask2)
        {
            return new AccessMask(mask1.Access & mask2);
        }

        /// <summary>
        /// Bitwise OR operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <param name="mask2">Access mask 2</param>
        /// <returns>The new access mask.</returns>
        public static AccessMask operator |(AccessMask mask1, uint mask2)
        {
            return new AccessMask(mask1.Access | mask2);
        }

        /// <summary>
        /// Equality operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <param name="mask2">Access mask 2</param>
        /// <returns>True if equal.</returns>
        public static bool operator ==(AccessMask mask1, AccessMask mask2)
        {
            return mask1.Access == mask2.Access;
        }

        /// <summary>
        /// Inequality operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <param name="mask2">Access mask 2</param>
        /// <returns>True if equal.</returns>
        public static bool operator !=(AccessMask mask1, AccessMask mask2)
        {
            return mask1.Access != mask2.Access;
        }

        /// <summary>
        /// Bitwise NOT operator.
        /// </summary>
        /// <param name="mask1">Access mask 1</param>
        /// <returns>The new access mask.</returns>
        public static AccessMask operator ~(AccessMask mask1)
        {
            return new AccessMask(~mask1.Access);
        }

        /// <summary>
        /// Overridden GetHashCode.
        /// </summary>
        /// <returns>The hash code.</returns>
        public override int GetHashCode()
        {
            return Access.GetHashCode();
        }

        /// <summary>
        /// Overridden Equals.
        /// </summary>
        /// <param name="obj">The object to compare against.</param>
        /// <returns>True if equal.</returns>
        public override bool Equals(object obj)
        {
            if (!(obj is AccessMask))
            {
                return false;
            }
            AccessMask mask = (AccessMask)obj;
            return Access == mask.Access;
        }

        /// <summary>
        /// Get an empty access mask.
        /// </summary>
        public static AccessMask Empty { get { return new AccessMask(); } }

        string IFormattable.ToString(string format, IFormatProvider formatProvider)
        {
            return Access.ToString(format, formatProvider);
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The access mask.</returns>
        public override string ToString()
        {
            return String.Format("{0:X08}", Access);
        }

        bool IEquatable<AccessMask>.Equals(AccessMask other)
        {
            return Access == other.Access;
        }

        int IComparable<AccessMask>.CompareTo(AccessMask other)
        {
            return Access.CompareTo(other.Access);
        }
    }

    /// <summary>
    /// Access rights generic mapping.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct GenericMapping
    {
        /// <summary>
        /// Mapping for Generic Read
        /// </summary>
        public AccessMask GenericRead;
        /// <summary>
        /// Mapping for Generic Write
        /// </summary>
        public AccessMask GenericWrite;
        /// <summary>
        /// Mapping for Generic Execute
        /// </summary>
        public AccessMask GenericExecute;
        /// <summary>
        /// Mapping for Generic All
        /// </summary>
        public AccessMask GenericAll;

        /// <summary>
        /// Map a generic access mask to a specific one.
        /// </summary>
        /// <param name="mask">The generic mask to map.</param>
        /// <returns>The mapped mask.</returns>
        public AccessMask MapMask(AccessMask mask)
        {
            NtRtl.RtlMapGenericMask(ref mask, ref this);
            return mask;
        }

        /// <summary>
        /// Get whether this generic mapping gives read access.
        /// </summary>
        /// <param name="mask">The mask to check against.</param>
        /// <returns>True if we have read access.</returns>
        public bool HasRead(AccessMask mask)
        {
            return (MapMask(mask) & GenericRead).HasAccess;
        }

        /// <summary>
        /// Get whether this generic mapping gives write access.
        /// </summary>
        /// <param name="mask">The mask to check against.</param>
        /// <returns>True if we have write access.</returns>
        public bool HasWrite(AccessMask mask)
        {
            return (MapMask(mask) & ~GenericRead & 
                ~GenericExecute & GenericWrite).HasAccess;
        }

        /// <summary>
        /// Get whether this generic mapping gives execute access.
        /// </summary>
        /// <param name="mask">The mask to check against.</param>
        /// <returns>True if we have execute access.</returns>
        public bool HasExecute(AccessMask mask)
        {
            return (MapMask(mask) & ~GenericRead & GenericExecute).HasAccess;
        }

        /// <summary>
        /// Get whether this generic mapping gives all access.
        /// </summary>
        /// <param name="mask">The mask to check against.</param>
        /// <returns>True if we have all access.</returns>
        public bool HasAll(AccessMask mask)
        {
            return MapMask(mask) == GenericAll;
        }

        /// <summary>
        /// Try and unmap access mask to generic rights.
        /// </summary>
        /// <param name="mask">The mask to unmap.</param>
        /// <returns>The unmapped mask. Any access which can be generic mapped is left in the mask as specific rights.</returns>
        public AccessMask UnmapMask(AccessMask mask)
        {
            AccessMask remaining = mask;
            AccessMask result = 0;
            if (mask == GenericAll)
            {
                return GenericAccessRights.GenericAll;
            }
            if ((mask & GenericRead) == GenericRead)
            {
                result |= GenericAccessRights.GenericRead;
                remaining &= ~GenericRead;
            }            
            if ((mask & GenericWrite) == GenericWrite)
            {
                result |= GenericAccessRights.GenericWrite;
                remaining &= ~GenericWrite;
            }
            if ((mask & GenericExecute) == GenericExecute)
            {
                result |= GenericAccessRights.GenericExecute;
                remaining &= ~GenericExecute;
            }

            return result | remaining;
        }

        /// <summary>
        /// Convert generic mapping to a string.
        /// </summary>
        /// <returns>The generic mapping as a string.</returns>
        public override string ToString()
        {
            return String.Format("R:{0:X08} W:{1:X08} E:{2:X08} A:{3:X08}",
                GenericRead, GenericWrite, 
                GenericExecute, GenericAll);
        }
    }

    /// <summary>
    /// Class to represent an Access Control Entry (ACE)
    /// </summary>
    public sealed class Ace
    {
        /// <summary>
        /// Check if the ACE is an Object ACE
        /// </summary>
        public bool IsObjectAce
        {
            get
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
        }

        /// <summary>
        /// Check if the ACE is a callback ACE
        /// </summary>
        public bool IsCallbackAce
        {
            get
            {
                switch (AceType)
                {
                    case AceType.AlarmCallbackObject:
                    case AceType.AllowedCallbackObject:
                    case AceType.AuditCallbackObject:
                    case AceType.DeniedCallbackObject:
                    case AceType.AlarmCallback:
                    case AceType.AllowedCallback:
                    case AceType.AuditCallback:
                    case AceType.DeniedCallback:
                        return true;
                }
                return false;
            }
        }

        /// <summary>
        /// Check if ACE is a conditional ACE
        /// </summary>
        public bool IsConditionalAce
        {
            get
            {
                if (!IsCallbackAce)
                {
                    return false;
                }

                if (ApplicationData.Length < 4)
                {
                    return false;
                }

                return BitConverter.ToUInt32(ApplicationData, 0) == 0x78747261;
            }
        }

        internal Ace(BinaryReader reader)
        {
            long current_position = reader.BaseStream.Position;
            AceType = (AceType)reader.ReadByte();
            AceFlags = (AceFlags)reader.ReadByte();
            int ace_size = reader.ReadUInt16();
            Mask = reader.ReadUInt32();
            if (IsObjectAce)
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
            
            Sid = new Sid(reader);
            int bytes_used = (int)(reader.BaseStream.Position - current_position);
            ApplicationData = reader.ReadAllBytes(ace_size - bytes_used);
        }

        internal void Serialize(BinaryWriter writer)
        {
            // Length = sizeof(AceHeader) + sizeof(Mask) + ObjectAceData + Sid
            byte[] sid_data = Sid.ToArray();
            int total_length = 4 + 4 + sid_data.Length + ApplicationData.Length;
            ObjectAceFlags flags = ObjectAceFlags.None;
            if (IsObjectAce)
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
            writer.Write(Mask.Access);
            if (IsObjectAce)
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
            writer.Write(ApplicationData ?? new byte[0]);
        }

        /// <summary>
        /// Get ACE type
        /// </summary>
        public AceType AceType { get; set; }

        /// <summary>
        /// Get ACE flags
        /// </summary>
        public AceFlags AceFlags { get; set; }

        /// <summary>
        /// Get ACE access mask
        /// </summary>
        public AccessMask Mask { get; set; }

        /// <summary>
        /// Get ACE Security Identifier
        /// </summary>
        public Sid Sid { get; set; }

        /// <summary>
        /// Get optional Object Type
        /// </summary>
        public Guid? ObjectType { get; set; }

        /// <summary>
        /// Get optional Inherited Object Type
        /// </summary>
        public Guid? InheritedObjectType { get; set; }

        /// <summary>
        /// Optional application data.
        /// </summary>
        public byte[] ApplicationData { get; set; }

        /// <summary>
        /// Convert ACE to a string
        /// </summary>
        /// <returns>The ACE as a string</returns>
        public override string ToString()
        {
            return String.Format("Type {0} - Flags {1} - Mask {2:X08} - Sid {3}",
                AceType, AceFlags, Mask, Sid);
        }

        /// <summary>
        /// Convert ACE to a string
        /// </summary>
        /// <param name="access_rights_type">An enumeration type to format the access mask</param>
        /// <param name="resolve_sid">True to try and resolve SID to a name</param>
        /// <returns>The ACE as a string</returns>
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

        /// <summary>
        /// Compare ACE to another object.
        /// </summary>
        /// <param name="obj">The other object.</param>
        /// <returns>True if the other object equals this ACE</returns>
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

        /// <summary>
        /// Get hash code.
        /// </summary>
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            return AceType.GetHashCode() ^ AceFlags.GetHashCode() ^ Mask.GetHashCode() ^ Sid.GetHashCode() ^ ObjectType.GetHashCode() ^ InheritedObjectType.GetHashCode();
        }

        /// <summary>
        /// Equality operator
        /// </summary>
        /// <param name="a">Left ACE</param>
        /// <param name="b">Right ACE</param>
        /// <returns>True if the ACEs are equal</returns>
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

        /// <summary>
        /// Not Equal operator
        /// </summary>
        /// <param name="a">Left ACE</param>
        /// <param name="b">Right ACE</param>
        /// <returns>True if the ACEs are not equal</returns>
        public static bool operator !=(Ace a, Ace b)
        {
            return !(a == b);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="type">ACE type</param>
        /// <param name="flags">ACE flags</param>
        /// <param name="mask">ACE access mask</param>
        /// <param name="sid">ACE sid</param>
        public Ace(AceType type, AceFlags flags, AccessMask mask, Sid sid)
        {
            AceType = type;
            AceFlags = flags;
            Mask = mask;
            Sid = sid;
            ApplicationData = new byte[0];
        }
    }

    /// <summary>
    /// Class to represent an Access Control List (ACL)
    /// </summary>
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

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="acl">Pointer to a raw ACL in memory</param>
        /// <param name="defaulted">True if the ACL was defaulted</param>
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

        /// <summary>
        /// Constructor for a NULL ACL
        /// </summary>
        /// <param name="defaulted">True if the ACL was defaulted</param>
        public Acl(bool defaulted) : this(IntPtr.Zero, defaulted)
        {
            Defaulted = defaulted;
        }

        /// <summary>
        /// Constructor for an empty ACL
        /// </summary>
        public Acl() : this(new Ace[0], false)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="aces">List of ACEs to add to ACL</param>
        /// <param name="defaulted">True if the ACL was defaulted</param>
        public Acl(IEnumerable<Ace> aces, bool defaulted) : base(aces)
        {
            Defaulted = defaulted;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="aces">List of ACEs to add to ACL</param>
        public Acl(IEnumerable<Ace> aces) : this(aces, false)
        {
        }

        /// <summary>
        /// Get or set whether the ACL was defaulted
        /// </summary>
        public bool Defaulted { get; set; }
        /// <summary>
        /// Get or set whether the ACL is NULL (no security)
        /// </summary>
        public bool NullAcl { get; set; }
        /// <summary>
        /// Get or set the ACL revision
        /// </summary>
        public AclRevision Revision { get; set; }

        /// <summary>
        /// Convert the ACL to a byte array
        /// </summary>
        /// <returns>The ACL as a byte array</returns>
        public byte[] ToByteArray()
        {
            AclRevision revision;
            byte[] aces;
            using (MemoryStream ace_stm = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(ace_stm))
                {
                    revision = Revision;
                    if (revision != AclRevision.Revision || revision != AclRevision.RevisionDS)
                    {
                        revision = AclRevision.Revision;
                    }
                    foreach (Ace ace in this)
                    {
                        ace.Serialize(writer);
                        if (ace.IsObjectAce)
                        {
                            revision = AclRevision.RevisionDS;
                        }
                    }
                }
                aces = ace_stm.ToArray();
            }

            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(Marshal.SizeOf(typeof(AclStructure)) + aces.Length))
            {
                NtRtl.RtlCreateAcl(buffer, buffer.Length, revision).ToNtException();
                NtRtl.RtlAddAce(buffer, revision, uint.MaxValue, aces, aces.Length).ToNtException();
                return buffer.ToArray();
            }
        }

        /// <summary>
        /// Convert the ACL to a safe buffer
        /// </summary>
        /// <returns>The safe buffer</returns>
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

        /// <summary>
        /// Add an access allowed ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessAllowedAce(AccessMask mask, AceFlags flags, string sid)
        {
            Add(new Ace(AceType.Allowed, flags, mask, new Sid(sid)));
        }

        /// <summary>
        /// Add an access allowed ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessAllowedAce(AccessMask mask, string sid)
        {
            AddAccessAllowedAce(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access allowed ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessAllowedAce(AccessMask mask, AceFlags flags, Sid sid)
        {
            Add(new Ace(AceType.Allowed, flags, mask, sid));
        }

        /// <summary>
        /// Add an access allowed ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessAllowedAce(AccessMask mask, Sid sid)
        {
            AddAccessAllowedAce(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access denied ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessDeniedAce(AccessMask mask, AceFlags flags, string sid)
        {
            Add(new Ace(AceType.Denied, flags, mask, new Sid(sid)));
        }

        /// <summary>
        /// Add an access denied ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessDeniedAce(AccessMask mask, string sid)
        {
            AddAccessDeniedAce(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Add an access denied ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="flags">The ACE flags</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessDeniedAce(AccessMask mask, AceFlags flags, Sid sid)
        {
            Add(new Ace(AceType.Denied, flags, mask, sid));
        }

        /// <summary>
        /// Add an access denied ace to the ACL
        /// </summary>
        /// <param name="mask">The ACE access mask</param>
        /// <param name="sid">The ACE SID</param>
        public void AddAccessDeniedAce(AccessMask mask, Sid sid)
        {
            AddAccessDeniedAce(mask, AceFlags.None, sid);
        }

        /// <summary>
        /// Gets an indication if this ACL is canonical.
        /// </summary>
        /// <remarks>Canonical basically means that deny ACEs are before allow ACEs.</remarks>
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

    /// <summary>
    /// Static class to access NT security manager routines.
    /// </summary>
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

        private static Dictionary<Sid, string> _known_capabilities = null;

        private static string[] _known_capability_names = {
                "activitySystem",
                "allJoyn",
                "appBroadcast",
                "appBroadcastServices",
                "appBroadcastSettings",
                "appCaptureServices",
                "appCaptureSettings",
                "appLicensing",
                "applicationDefaults",
                "appointments",
                "appointmentsSystem",
                "backgroundMediaPlayback",
                "biometricSystem",
                "cellularDeviceControl",
                "cellularDeviceIdentity",
                "cellularMessaging",
                "chat",
                "chatSystem",
                "childWebContent",
                "cloudExperienceHost",
                "cloudStore",
                "confirmAppClose",
                "contacts",
                "contactsSystem",
                "contentDeliveryManagerSettings",
                "cortanaSettings",
                "cortanaPermissions",
                "curatedTileCollections",
                "deviceManagementAdministrator",
                "deviceManagementEmailAccount",
                "deviceManagementFoundation",
                "documentsLibrary",
                "dualSimTiles",
                "emailSystem",
                "enterpriseAuthentication",
                "enterpriseDataPolicy",
                "extendedExecutionBackgroundAudio",
                "extendedExecutionUnconstrained",
                "featureStagingInfo",
                "feedbackLogCollection",
                "firstSignInSettings",
                "gameBarServices",
                "gameList",
                "hfxSystem",
                "hidTelephony",
                "holographicCompositor",
                "holographicCompositorSystem",
                "inputForegroundObservation",
                "inputInjection",
                "inputInjectionBrokered",
                "internetClient",
                "internetClientServer",
                "liveIdService",
                "locationHistory",
                "locationSystem",
                "lockScreenCreatives",
                "lpacAppExperience",
                "lpacCom",
                "lpacCryptoServices",
                "lpacEnterprisePolicyChangeNotifications",
                "lpacIdentityServices",
                "lpacInstrumentation",
                "lpacMedia",
                "lpacPayments",
                "lpacPnPNotifications",
                "lpacPrinting",
                "lpacServicesManagement",
                "lpacSessionManagement",
                "lpacWebPlatform",
                "microsoftEdgeRemoteDebugging",
                "musicLibrary",
                "networkConnectionManagerProvisioning",
                "objects3D",
                "oemPublicDirectory",
                "packageContents",
                "packageManagement",
                "packageQuery",
                "perceptionSystem",
                "phoneCall",
                "phoneCallHistory",
                "phoneCallHistorySystem",
                "picturesLibrary",
                "previewHfx",
                "previewPenWorkspace",
                "previewStore",
                "privateNetworkClientServer",
                "recordedCallsFolder",
                "registryRead",
                "remotePassportAuthentication",
                "remoteSystem",
                "removableStorage",
                "runFullTrust",
                "screenDuplication",
                "secondaryAuthenticationFactor",
                "secureAssessment",
                "settingSyncConfiguration",
                "sharedUserCertificates",
                "shellExperience",
                "slapiQueryLicenseValue",
                "smsSend",
                "spatialPerception",
                "startScreenManagement",
                "storeAppInstall",
                "storeAppInstallation",
                "storeConfiguration",
                "storeLicenseManagement",
                "targetedContent",
                "targetedContentSubscription",
                "teamEditionExperience",
                "uiAutomationSystem",
                "unzipFile",
                "userAccountInformation",
                "userDataAccountSetup",
                "userDataAccountsProvider",
                "userDataSystem",
                "userPrincipalName",
                "userSigninSupport",
                "userWebAccounts",
                "videosLibrary",
                "visualElementsSystem",
                "voipCall",
                "walletSystem",
                "windowsHelloCredentialAccess",
                "xboxGameSpeechWindow",
                "xboxLiveAuthenticationProvider",
                "xboxTrackingStream",
        };

        private static Dictionary<Sid, string> GetKnownCapabilitySids()
        {
            if (_known_capabilities == null)
            {
                Dictionary<Sid, string> known_capabilities = new Dictionary<Sid, string>();
                try
                {
                    foreach (string name in _known_capability_names)
                    {
                        Sid sid = GetCapabilitySid(name);
                        known_capabilities.Add(sid, name);
                    }
                }
                catch (EntryPointNotFoundException)
                {
                    // Catch here in case the RtlDeriveCapabilitySid function isn't supported.
                }
                _known_capabilities = known_capabilities;
            }
            return _known_capabilities;
        }

        /// <summary>
        /// Looks up a capability SID to see if it's already known.
        /// </summary>
        /// <param name="sid">The capability SID to lookup</param>
        /// <returns>The name of the capability, null if not found.</returns>
        public static string LookupKnownCapabilityName(Sid sid)
        {
            var known_caps = GetKnownCapabilitySids();
            if (known_caps.ContainsKey(sid))
            {
                return known_caps[sid];
            }
            return null;
        }

        /// <summary>
        /// Lookup a SID from a username.
        /// </summary>
        /// <param name="username">The username, can be in the form domain\account.</param>
        /// <returns>The Security Identifier</returns>
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

        private static string ReadMoniker(NtKey rootkey, Sid sid)
        {
            string path = string.Format(@"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\{0}", sid);
            using (ObjectAttributes obj_attr = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, rootkey))
            {
                using (var key = NtKey.Open(obj_attr, KeyAccessRights.QueryValue, KeyCreateOptions.NonVolatile, false))
                {
                    if (key.IsSuccess)
                    {
                        var value = key.Result.QueryValue("Moniker", false);
                        if (value.IsSuccess)
                            return value.Result.ToString();
                    }
                }
            }
            return null;
        }

        /// <summary>
        /// Try and lookup the moniker associated with a package sid.
        /// </summary>
        /// <param name="sid">The package sid.</param>
        /// <returns>Returns the moniker name. If not found returns null.</returns>
        /// <exception cref="ArgumentException">Thrown if SID is not a package sid.</exception>
        public static string LookupPackageSid(Sid sid)
        {
            if (!IsPackageSid(sid))
            {
                throw new ArgumentException("Sid not a package sid", "sid");
            }

            string ret = null;
            try
            {
                using (NtKey key = NtKey.GetCurrentUserKey())
                {
                    ret = ReadMoniker(key, sid);
                }
            }
            catch (NtException)
            {
            }

            if (ret == null)
            {
                try
                {
                    using (NtKey key = NtKey.GetMachineKey())
                    {
                        ret = ReadMoniker(key, sid);
                    }
                }
                catch (NtException)
                {
                }
            }

            return ret;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            byte[] SecurityDescriptor,
            int RequestedStringSDRevision,
            SecurityInformation SecurityInformation,
            out SafeLocalAllocHandle StringSecurityDescriptor,
            out int StringSecurityDescriptorLen);

        /// <summary>
        /// Convert a security descriptor to SDDL string
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="security_information">Indicates what parts of the security descriptor to include</param>
        /// <returns>The SDDL string</returns>
        /// <exception cref="NtException">Thrown if cannot convert to a SDDL string.</exception>
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

        /// <summary>
        /// Convert an SDDL string to a binary security descriptor
        /// </summary>
        /// <param name="sddl">The SDDL string</param>
        /// <returns>The binary security descriptor</returns>
        /// <exception cref="NtException">Thrown if cannot convert from a SDDL string.</exception>
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

        /// <summary>
        /// Convert an SDDL SID string to a Sid
        /// </summary>
        /// <param name="sddl">The SDDL SID string</param>
        /// <returns>The converted Sid</returns>
        /// <exception cref="NtException">Thrown if cannot convert from a SDDL string.</exception>
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

        private static NtToken DuplicateForAccessCheck(NtToken token)
        {
            if (token.TokenType == TokenType.Primary)
            {
                return token.DuplicateToken(TokenType.Impersonation, SecurityImpersonationLevel.Identification, TokenAccessRights.Query);
            }
            else if (!token.IsAccessGranted(TokenAccessRights.Query))
            {
                return token.Duplicate(TokenAccessRights.Query);
            }
            else
            {
                // If we've got query access rights already just create a shallow clone.
                return token.ShallowClone();
            }
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="access_rights">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <returns>The allowed access mask as a unsigned integer.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessMask GetAllowedAccess(SecurityDescriptor sd, NtToken token,
            AccessMask access_rights, Sid principal, GenericMapping generic_mapping)
        {
            if (sd == null)
            {
                throw new ArgumentNullException("sd");
            }

            if (token == null)
            {
                throw new ArgumentNullException("token");
            }

            if (access_rights.IsEmpty)
            {
                return AccessMask.Empty;
            }

            using (SafeBuffer sd_buffer = sd.ToSafeBuffer())
            {
                using (NtToken imp_token = DuplicateForAccessCheck(token))
                {
                    AccessMask granted_access;
                    NtStatus result_status;
                    using (var privs = new SafePrivilegeSetBuffer())
                    {
                        int buffer_length = privs.Length;

                        using (var self_sid = principal != null ? principal.ToSafeBuffer() : SafeSidBufferHandle.Null)
                        {
                            NtSystemCalls.NtAccessCheckByType(sd_buffer, self_sid, imp_token.Handle, access_rights,
                                SafeHGlobalBuffer.Null, 0, ref generic_mapping, privs, 
                                ref buffer_length, out granted_access, out result_status).ToNtException();
                            if (result_status.IsSuccess())
                            {
                                return granted_access;
                            }
                            return AccessMask.Empty;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="access_rights">The set of access rights to check against</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <returns>The allowed access mask as a unsigned integer.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessMask GetAllowedAccess(SecurityDescriptor sd, NtToken token,
            AccessMask access_rights, GenericMapping generic_mapping)
        {
            return GetAllowedAccess(sd, token, access_rights, null, generic_mapping);
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the maximum allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <returns>The maximum allowed access mask as a unsigned integer.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessMask GetMaximumAccess(SecurityDescriptor sd, NtToken token, GenericMapping generic_mapping)
        {
            return GetAllowedAccess(sd, token, GenericAccessRights.MaximumAllowed, generic_mapping);
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the maximum allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <returns>The maximum allowed access mask as a unsigned integer.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessMask GetMaximumAccess(SecurityDescriptor sd, NtToken token, Sid principal, GenericMapping generic_mapping)
        {
            return GetAllowedAccess(sd, token, GenericAccessRights.MaximumAllowed, principal, generic_mapping);
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="access_rights">The set of access rights to check against</param>
        /// <param name="type">The type used to determine generic access mapping..</param>
        /// <returns>The allowed access mask as a unsigned integer.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessMask GetAllowedAccess(NtToken token, NtType type, AccessMask access_rights, byte[] sd)
        {
            if (sd == null || sd.Length == 0)
            {
                return AccessMask.Empty;
            }

            return GetAllowedAccess(new SecurityDescriptor(sd), token, access_rights, type.GenericMapping);
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the maximum allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="type">The type used to determine generic access mapping..</param>
        /// <returns>The allowed access mask as a unsigned integer.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessMask GetMaximumAccess(NtToken token, NtType type, byte[] sd)
        {
            return GetAllowedAccess(token, type, GenericAccessRights.MaximumAllowed, sd);
        }

        /// <summary>
        /// Get a security descriptor from a named object.
        /// </summary>
        /// <param name="name">The path to the resource (such as \BaseNamedObejct\ABC)</param>
        /// <param name="type">The type of resource, can be null to get the method to try and discover the correct type.</param>
        /// <returns>The named resource security descriptor.</returns>
        /// <exception cref="NtException">Thrown if an error occurred opening the object.</exception>
        /// <exception cref="ArgumentException">Thrown if type of resource couldn't be found.</exception>
        public static SecurityDescriptor FromNamedObject(string name, string type)
        {
            try
            {
                using (NtObject obj = NtObject.OpenWithType(type, name, null, GenericAccessRights.ReadControl))
                {
                    return obj.SecurityDescriptor;
                }
            }
            catch
            {
            }

            return null;
        }

        /// <summary>
        /// Get a SID for a specific mandatory integrity level.
        /// </summary>
        /// <param name="level">The mandatory integrity level.</param>
        /// <returns>The integrity SID</returns>
        public static Sid GetIntegritySidRaw(int level)
        {
            return new Sid(SecurityAuthority.Label, (uint)level);
        }

        /// <summary>
        /// Get a SID for a specific mandatory integrity level.
        /// </summary>
        /// <param name="level">The mandatory integrity level.</param>
        /// <returns>The integrity SID</returns>
        public static Sid GetIntegritySid(TokenIntegrityLevel level)
        {
            return GetIntegritySidRaw((int)level);
        }

        /// <summary>
        /// Checks if a SID is an integrity level SID
        /// </summary>
        /// <param name="sid">The SID to check</param>
        /// <returns>True if an integrity SID</returns>
        public static bool IsIntegritySid(Sid sid)
        {
            return GetIntegritySid(TokenIntegrityLevel.Untrusted).EqualPrefix(sid);
        }

        /// <summary>
        /// Get the integrity level from an integrity SID
        /// </summary>
        /// <param name="sid">The integrity SID</param>
        /// <returns>The token integrity level.</returns>
        public static TokenIntegrityLevel GetIntegrityLevel(Sid sid)
        {
            if (!IsIntegritySid(sid))
            {
                throw new ArgumentException("Must specify an integrity SID", "sid");
            }
            return (TokenIntegrityLevel)sid.SubAuthorities[sid.SubAuthorities.Count - 1];
        }

        /// <summary>
        /// Gets the SID for a service name.
        /// </summary>
        /// <param name="service_name">The service name.</param>
        /// <returns>The service SID.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static Sid GetServiceSid(string service_name)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(1024))
            {
                int sid_length = buffer.Length;
                NtRtl.RtlCreateServiceSid(new UnicodeString(service_name), buffer, ref sid_length).ToNtException();
                return new Sid(buffer);
            }
        }

        /// <summary>
        /// Checks if a SID is a service SID.
        /// </summary>
        /// <param name="sid">The sid to check.</param>
        /// <returns>True if a service sid.</returns>
        public static bool IsServiceSid(Sid sid)
        {
            return sid.Authority.IsAuthority(SecurityAuthority.Nt) && sid.SubAuthorities.Count > 0 && sid.SubAuthorities[0] == 80;
        }

        /// <summary>
        /// Checks if a SID is a capability SID.
        /// </summary>
        /// <param name="sid">The sid to check.</param>
        /// <returns>True if a capability sid.</returns>
        public static bool IsCapabilitySid(Sid sid)
        {
            return sid.Authority.IsAuthority(SecurityAuthority.Package) &&
                sid.SubAuthorities.Count > 0 &&
                (sid.SubAuthorities[0] == 3);
        }

        private static int GetSidSize(int rids)
        {
            return 8 + rids * 4;
        }

        /// <summary>
        /// Get a capability sid by name.
        /// </summary>
        /// <param name="capability_name">The name of the capability.</param>
        /// <returns>The capability SID.</returns>
        public static Sid GetCapabilitySid(string capability_name)
        {
            using (SafeHGlobalBuffer cap_sid = new SafeHGlobalBuffer(GetSidSize(9)), 
                cap_group_sid = new SafeHGlobalBuffer(GetSidSize(10)))
            {
                NtRtl.RtlDeriveCapabilitySidsFromName(
                    new UnicodeString(capability_name),
                    cap_group_sid, cap_sid).ToNtException();
                return new Sid(cap_sid);
            }
        }

        /// <summary>
        /// Get a capability group sid by name.
        /// </summary>
        /// <param name="capability_name">The name of the capability.</param>
        /// <returns>The capability SID.</returns>
        public static Sid GetCapabilityGroupSid(string capability_name)
        {
            using (SafeHGlobalBuffer cap_sid = new SafeHGlobalBuffer(GetSidSize(9)),
                cap_group_sid = new SafeHGlobalBuffer(GetSidSize(10)))
            {
                NtRtl.RtlDeriveCapabilitySidsFromName(
                    new UnicodeString(capability_name),
                    cap_group_sid, cap_sid).ToNtException();
                return new Sid(cap_group_sid);
            }
        }

        /// <summary>
        /// Get the type of package sid.
        /// </summary>
        /// <param name="sid">The sid to get type.</param>
        /// <returns>The package sid type, Unknown if invalid.</returns>
        public static PackageSidType GetPackageSidType(Sid sid)
        {
            if (IsPackageSid(sid))
            {
                return sid.SubAuthorities.Count == 8 ? PackageSidType.Parent : PackageSidType.Child;
            }
            return PackageSidType.Unknown;
        }

        /// <summary>
        /// Checks if a SID is a valid package SID.
        /// </summary>
        /// <param name="sid">The sid to check.</param>
        /// <returns>True if a capability sid.</returns>
        public static bool IsPackageSid(Sid sid)
        {
            return sid.Authority.IsAuthority(SecurityAuthority.Package) &&
                (sid.SubAuthorities.Count == 8 || sid.SubAuthorities.Count == 12) &&
                (sid.SubAuthorities[0] == 2);
        }

        /// <summary>
        /// Converts a conditional ACE to an SDDL string
        /// </summary>
        /// <param name="conditional_data">The conditional application data.</param>
        /// <returns>The conditional ACE string.</returns>
        public static string ConditionalAceToString(byte[] conditional_data)
        {
            SecurityDescriptor sd = new SecurityDescriptor();
            sd.Dacl.NullAcl = false;
            sd.Dacl.Add(new Ace(AceType.AllowedCallback, AceFlags.None, 0, KnownSids.World) { ApplicationData = conditional_data });
            string sddl = sd.ToSddl();
            int last_semi = sddl.LastIndexOf(";(");
            if (last_semi < 0)
            {
                throw new ArgumentException("Invalid condition data");
            }

            return sddl.Substring(last_semi + 1);
        }

        /// <summary>
        /// Get the cached signing level for a file.
        /// </summary>
        /// <param name="handle">The handle to the file to query.</param>
        /// <returns>The cached signing level.</returns>
        public static CachedSigningLevel GetCachedSigningLevel(SafeKernelObjectHandle handle)
        {
            int flags;
            SigningLevel signing_level;
            byte[] thumb_print = new byte[0x68];
            int thumb_print_size = thumb_print.Length;
            int thumb_print_algo = 0;

            NtSystemCalls.NtGetCachedSigningLevel(handle, out flags,
                out signing_level, thumb_print, ref thumb_print_size, out thumb_print_algo).ToNtException();
            Array.Resize(ref thumb_print, thumb_print_size);
            return new CachedSigningLevel(flags, signing_level, thumb_print, thumb_print_algo);
        }

        /// <summary>
        /// Set the cached signing level for a file.
        /// </summary>
        /// <param name="handle">The handle to the file to set the cache on.</param>
        /// <param name="flags">Flags to set for the cache.</param>
        /// <param name="signing_level">The signing level to cache</param>
        /// <param name="source_files">A list of source file for the cache.</param>
        /// <param name="name">Optional name for the cache.</param>
        public static void SetCachedSigningLevel(SafeKernelObjectHandle handle, 
                                                 int flags, SigningLevel signing_level,
                                                 IEnumerable<SafeKernelObjectHandle> source_files,
                                                 string name)
        {
            IntPtr[] handles = source_files == null ? null 
                : source_files.Select(f => f.DangerousGetHandle()).ToArray();
            int handles_count = handles == null ? 0 : handles.Length;
            if (name != null)
            {
                CachedSigningLevelInformation info = new CachedSigningLevelInformation(name);
                NtSystemCalls.NtSetCachedSigningLevel2(flags, signing_level, handles, handles_count, handle, info).ToNtException();
            }
            else
            {
                NtSystemCalls.NtSetCachedSigningLevel(flags, signing_level, handles, handles_count, handle).ToNtException();
            }
        }
    }
}
