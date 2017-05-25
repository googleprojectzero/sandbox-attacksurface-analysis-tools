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
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet
{
#pragma warning disable 1591
    public enum TokenType
    {
        Primary = 1,
        Impersonation = 2
    }

    public enum TokenInformationClass
    {
        TokenUser = 1,
        TokenGroups = 2,
        TokenPrivileges = 3,
        TokenOwner = 4,
        TokenPrimaryGroup = 5,
        TokenDefaultDacl = 6,
        TokenSource = 7,
        TokenType = 8,
        TokenImpersonationLevel = 9,
        TokenStatistics = 10,
        TokenRestrictedSids = 11,
        TokenSessionId = 12,
        TokenGroupsAndPrivileges = 13,
        TokenSessionReference = 14,
        TokenSandBoxInert = 15,
        TokenAuditPolicy = 16,
        TokenOrigin = 17,
        TokenElevationType = 18,
        TokenLinkedToken = 19,
        TokenElevation = 20,
        TokenHasRestrictions = 21,
        TokenAccessInformation = 22,
        TokenVirtualizationAllowed = 23,
        TokenVirtualizationEnabled = 24,
        TokenIntegrityLevel = 25,
        TokenUIAccess = 26,
        TokenMandatoryPolicy = 27,
        TokenLogonSid = 28,
        TokenIsAppContainer = 29,
        TokenCapabilities = 30,
        TokenAppContainerSid = 31,
        TokenAppContainerNumber = 32,
        TokenUserClaimAttributes = 33,
        TokenDeviceClaimAttributes = 34,
        TokenRestrictedUserClaimAttributes = 35,
        TokenRestrictedDeviceClaimAttributes = 36,
        TokenDeviceGroups = 37,
        TokenRestrictedDeviceGroups = 38,
        TokenSecurityAttributes = 39,
        TokenIsRestricted = 40,
        TokenProcessTrustLevel = 41,
        MaxTokenInfoClass = 42
    }

    public enum TokenPrivilegeValue : uint
    {
        SeCreateTokenPrivilege = 2,
        SeAssignPrimaryTokenPrivilege,
        SeLockMemoryPrivilege,
        SeIncreaseQuotaPrivilege,
        SeMachineAccountPrivilege,
        SeTcbPrivilege,
        SeSecurityPrivilege,
        SeTakeOwnershipPrivilege,
        SeLoadDriverPrivilege,
        SeSystemProfilePrivilege,
        SeSystemTimePrivilege,
        SeProfileSingleProcessPrivilege,
        SeIncreaseBasePriorityPrivilege,
        SeCreatePageFilePrivilege,
        SeCreatePermanentPrivilege,
        SeBackupPrivilege,
        SeRestorePrivilege,
        SeShutdownPrivilege,
        SeDebugPrivilege,
        SeAuditPrivilege,
        SeSystemEnvironmentPrivilege,
        SeChangeNotifyPrivilege,
        SeRemoteShutdownPrivilege,
        SeUndockPrivilege,
        SeSyncAgentPrivilege,
        SeEnableDelegationPrivilege,
        SeManageVolumePrivilege,
        SeImpersonatePrivilege,
        SeCreateGlobalPrivilege,
        SeTrustedCredmanAccessPrivilege,
        SeRelabelPrivilege,
        SeIncreaseWorkingSetPrivilege,
        SeTimeZonePrivilege,
        SeCreateSymbolicLinkPrivilege, // 35
    }

    [Flags]
    public enum TokenAccessRights : uint
    {
        AssignPrimary = 0x0001,
        Duplicate = 0x0002,
        Impersonate = 0x0004,
        Query = 0x0008,
        QuerySource = 0x0010,
        AdjustPrivileges = 0x0020,
        AdjustGroups = 0x0040,
        AdjustDefault = 0x0080,
        AdjustSessionId = 0x0100,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    public enum TokenIntegrityLevel
    {
        Untrusted = 0,
        Low = 0x1000,
        Medium = 0x2000,
        High = 0x3000,
        System = 0x4000,
    };

    public enum TokenElevationType {
        Default = 1,
        Full,
        Limited
    }

    [Flags]
    public enum TokenMandatoryPolicy
    {
        Off = 0,
        NoWriteUp = 1,
        NewProcessMin = 2,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;

        public UserGroup ToUserGroup()
        {
            return new UserGroup(new Sid(Sid), (GroupAttributes)Attributes);
        }
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenUser
    {
        public SidAndAttributes User;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenOwner
    {
        public IntPtr Owner;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenPrimaryGroup
    {
        public IntPtr PrimaryGroup;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenDefaultDacl
    {
        public IntPtr DefaultDacl;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenMandatoryLabel
    {
        public SidAndAttributes Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenAppContainerInformation
    {
        public IntPtr TokenAppContainer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class TokenSource
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        private byte[] _sourcename;
        private Luid _sourceidentifier;

        public TokenSource()
        {
            _sourcename = new byte[8];
        }        

        public Luid SourceIdentifier { get { return _sourceidentifier; } }

        public string SourceName { get { return Encoding.ASCII.GetString(_sourcename).TrimEnd('\0'); } }

        public override string ToString()
        {
            return String.Format("Identifier = {0} - Name = {1}", SourceIdentifier, SourceName);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Luid
    {
        public uint LowPart;
        public int HighPart;

        public Luid(uint lowpart, int highpart)
        {
            LowPart = lowpart;
            HighPart = highpart;
        }

        public Luid(long quadpart)
        {
            LargeInteger li = new LargeInteger(quadpart);
            LowPart = li.LowPart;
            HighPart = li.HighPart;
        }

        public override string ToString()
        {
            return String.Format("{0:X08}-{1:X08}", HighPart, LowPart);
        }
        
        public override bool Equals(object obj)
        {
            if (obj is Luid)
            {
                Luid luid = (Luid)obj;
                return LowPart == luid.LowPart && HighPart == luid.HighPart;
            }
            return false;
        }

        public override int GetHashCode()
        {
            return (int)LowPart ^ HighPart;
        }

        public long ToInt64()
        {
            LargeInteger li = new LargeInteger();
            li.LowPart = LowPart;
            li.HighPart = HighPart;
            return li.QuadPart;
        }        
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Privileges")]
    public class TokenPrivileges
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray)]
        public LuidAndAttributes[] Privileges;
    }

    public enum ClaimSecurityValueType : ushort
    {
        Int64 = 0x0001,
        Uint64 = 0x0002,
        String = 0x0003,
        Fqbn = 0x0004,
        Sid = 0x0005, // CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE 
        Boolean = 0x0006, // Actually UInt64
        OctetString = 0x0010,
    }

    [Flags]
    public enum ClaimSecurityFlags
    {
        NonInheritable = 0x0001,
        CaseSensitive = 0x0002,
        UseForDenyOnly = 0x0004,
        DisabledByDefault = 0x0008,
        Disabled = 0x0010,
        Mandatory = 0x0020,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ClaimSecurityAttributeOctetStringValue
    {
        public IntPtr pValue;
        public int ValueLength;

        public byte[] ToArray()
        {
            if (pValue != IntPtr.Zero || ValueLength == 0)
            {
                return new byte[0];
            }
            byte[] ret = new byte[ValueLength];
            Marshal.Copy(pValue, ret, 0, ValueLength);
            return ret;
        }

        public Sid ToSid()
        {
            return new Sid(ToArray());
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ClaimSecurityAttributeFqbnValue
    {
        public ulong Version;
        public IntPtr Name;
    }

    public class ClaimSecurityAttributeFqbn
    {
        public ulong Version { get; private set; }
        public string Name { get; private set; }

        public ClaimSecurityAttributeFqbn(ClaimSecurityAttributeFqbnValue value)
        {
            Version = value.Version;
            Name = Marshal.PtrToStringUni(value.Name);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ClaimSecurityAttributeV1_NT
    {
        public UnicodeStringOut Name;
        public ClaimSecurityValueType ValueType;
        public ushort Reserved;
        public ClaimSecurityFlags Flags;
        public int ValueCount;
        public IntPtr Values;
        //union {
        //PLONG64 pInt64;
        //PDWORD64 pUint64;
        //UNICODE_STRING* ppString;
        //PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
        //PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ClaimSecurityAttributeV1
    {
        public IntPtr Name;
        public ClaimSecurityValueType ValueType;
        public ushort Reserved;
        public ClaimSecurityFlags Flags;
        public int ValueCount;
        public IntPtr Values;
        //union {
        //PLONG64 pInt64;
        //PDWORD64 pUint64;
        //PWSTR* ppString;
        //PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
        //PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
    }    

    [StructLayout(LayoutKind.Sequential)]
    public class ClaimSecurityAttributesInformation
    {
        public ushort Version;
        public ushort Reserved;
        public int AttributeCount;
        public IntPtr pAttributeV1;
    }

    [Flags]
    public enum PrivilegeAttributes : uint
    {
        Disabled = 0,
        EnabledByDefault = 1,
        Enabled = 2,
        Removed = 4,
        UsedForAccess = 0x80000000U,
    }

    [Flags]
    public enum GroupAttributes : uint
    {
        None = 0,
        Mandatory = 0x00000001,
        EnabledByDefault = 0x00000002,
        Enabled = 0x00000004,
        Owner = 0x00000008,
        UseForDenyOnly = 0x00000010,
        Integrity = 0x00000020,
        IntegrityEnabled = 0x00000040,
        LogonId = 0xC0000000,
        Resource = 0x20000000,
    };

    [Flags]
    public enum FilterTokenFlags
    {
        None = 0,
        DisableMaxPrivileges = 0x1,
        SandboxInert = 0x2,
        LuaToken = 0x4,
        WriteRestricted = 0x8,
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus NtCreateLowBoxToken(
          out SafeKernelObjectHandle token,
          SafeHandle original_token,
          TokenAccessRights access,
          ObjectAttributes object_attribute,
          byte[] appcontainer_sid,
          int capabilityCount,
          SidAndAttributes[] capabilities,
          int handle_count,
          IntPtr[] handles);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus NtOpenProcessTokenEx(
          SafeKernelObjectHandle ProcessHandle,
          TokenAccessRights DesiredAccess,
          AttributeFlags HandleAttributes,
          out SafeKernelObjectHandle TokenHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenThreadTokenEx(
          SafeKernelObjectHandle ThreadHandle,
          TokenAccessRights DesiredAccess,
          [MarshalAs(UnmanagedType.U1)] bool OpenAsSelf,
          AttributeFlags HandleAttributes,
          out SafeKernelObjectHandle TokenHandle
        );

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus NtDuplicateToken(
            SafeKernelObjectHandle ExistingTokenHandle,
            TokenAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes,
            bool EffectiveOnly,
            TokenType TokenType,
            out SafeKernelObjectHandle NewTokenHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationToken(
          SafeKernelObjectHandle TokenHandle,
          TokenInformationClass TokenInformationClass,
          SafeBuffer TokenInformation,
          int TokenInformationLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationToken(
          SafeKernelObjectHandle TokenHandle,
          TokenInformationClass TokenInformationClass,
          IntPtr TokenInformation,
          int TokenInformationLength,
          out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAdjustPrivilegesToken(
           SafeHandle TokenHandle,
           bool DisableAllPrivileges,
           SafeTokenPrivilegesBuffer NewState,
           int BufferLength,
           IntPtr PreviousState,
           IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAdjustGroupsToken(
            SafeHandle TokenHandle,
            bool ResetToDefault,
            SafeTokenGroupsBuffer TokenGroups,
            int PreviousGroupsLength,
            IntPtr PreviousGroups,
            IntPtr RequiredLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtFilterToken(SafeKernelObjectHandle ExistingTokenHandle,
            FilterTokenFlags Flags, SafeTokenGroupsBuffer SidsToDisable, SafeTokenPrivilegesBuffer PrivilegesToDelete,
            SafeTokenGroupsBuffer RestrictedSids, out SafeKernelObjectHandle NewTokenHandle);
    }


    internal class TokenPrivilegesBuilder
    {
        private List<LuidAndAttributes> _privs;

        public TokenPrivilegesBuilder()
        {
            _privs = new List<LuidAndAttributes>();
        }

        public void AddPrivilege(Luid luid, PrivilegeAttributes attributes)
        {
            LuidAndAttributes priv = new LuidAndAttributes();
            priv.Luid = luid;
            priv.Attributes = (uint)attributes;
            _privs.Add(priv);
        }

        public void AddPrivilege(TokenPrivilegeValue name, PrivilegeAttributes attributes)
        {
            Luid luid = new Luid();
            luid.LowPart = (uint)name;
            AddPrivilege(luid, attributes);
        }

        public void AddPrivilege(string name, bool enable)
        {
            AddPrivilege(new TokenPrivilege(name, enable ? PrivilegeAttributes.Enabled : PrivilegeAttributes.Disabled));
        }

        public void AddPrivilege(TokenPrivilege privilege)
        {
            AddPrivilege(privilege.Luid, privilege.Attributes);
        }

        public void AddPrivilegeRange(IEnumerable<TokenPrivilege> privileges)
        {
            _privs.AddRange(privileges.Select(p => new LuidAndAttributes() { Luid = p.Luid, Attributes = (uint)p.Attributes }));
        }

        public SafeTokenPrivilegesBuffer ToBuffer()
        {
            TokenPrivileges privs = new TokenPrivileges();
            privs.PrivilegeCount = _privs.Count;
            privs.Privileges = _privs.ToArray();
            return new SafeTokenPrivilegesBuffer(privs);
        }
    }

    public class SafeTokenPrivilegesBuffer : SafeStructureArrayBuffer<TokenPrivileges>
    {
        public SafeTokenPrivilegesBuffer(TokenPrivileges privs) : base(privs)
        {
        }

        private SafeTokenPrivilegesBuffer() : base(0)
        {
        }

        new public static SafeTokenPrivilegesBuffer Null { get { return new SafeTokenPrivilegesBuffer(); } }
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Groups")]
    public class TokenGroups
    {
        public int GroupCount;
        [MarshalAs(UnmanagedType.ByValArray)]
        public SidAndAttributes[] Groups;
    }

    public class SafeTokenGroupsBuffer : SafeStructureArrayBuffer<TokenGroups>
    {
        SafeHandleList _sids;
        public SafeTokenGroupsBuffer(TokenGroups groups, SafeHandleList sids) : base(groups)
        {
            _sids = sids;
        }

        private SafeTokenGroupsBuffer() : base(0)
        {
        }

        new public static SafeTokenGroupsBuffer Null { get { return new SafeTokenGroupsBuffer(); } }

        protected override void Dispose(bool disposing)
        {
            if (_sids != null)
            {
                _sids.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    public sealed class TokenGroupsBuilder
    {
        private class InternalSidAndAttributes
        {
            public Sid sid;
            public uint attr;
        }

        private List<InternalSidAndAttributes> _sid_and_attrs;

        public TokenGroupsBuilder()
        {
            _sid_and_attrs = new List<InternalSidAndAttributes>();
        }

        public void AddGroup(Sid sid, GroupAttributes attributes)
        {
            _sid_and_attrs.Add(new InternalSidAndAttributes() { sid = sid, attr = (uint)attributes });
        }

        public SafeTokenGroupsBuffer ToBuffer()
        {
            using (SafeHandleList sids = new SafeHandleList(_sid_and_attrs.Count))
            {
                SidAndAttributes[] result = new SidAndAttributes[_sid_and_attrs.Count];
                for (int i = 0; i < _sid_and_attrs.Count; ++i)
                {
                    sids.Add(_sid_and_attrs[i].sid.ToSafeBuffer());
                    result[i] = new SidAndAttributes();
                    result[i].Sid = sids[i].DangerousGetHandle();
                    result[i].Attributes = _sid_and_attrs[i].attr;
                }
                TokenGroups groups = new TokenGroups();
                groups.GroupCount = result.Length;
                groups.Groups = result;
                return new SafeTokenGroupsBuffer(groups, sids.DangerousMove());
            }
        }
    }


    [StructLayout(LayoutKind.Sequential)]
    public class TokenStatistics
    {
        public Luid TokenId;
        public Luid AuthenticationId;
        public LargeIntegerStruct ExpirationTime;
        public TokenType TokenType;
        public SecurityImpersonationLevel ImpersonationLevel;
        public uint DynamicCharged;
        public uint DynamicAvailable;
        public uint GroupCount;
        public uint PrivilegeCount;
        public Luid ModifiedId;
    }

    public sealed class ClaimSecurityAttribute
    {
        private static T[] ReadTyped<T>(IntPtr buffer, int count) where T : struct
        {
            int type_size = Marshal.SizeOf(typeof(T));
            List<T> res = new List<T>();
            while (count > 0)
            {
                res.Add((T)Marshal.PtrToStructure(buffer, typeof(T)));
                buffer += type_size;
                count--;
            }
            return res.ToArray();
        }

        private IEnumerable<object> ReadValues(IntPtr buffer, int count, ClaimSecurityValueType type)
        {
            if (buffer == IntPtr.Zero || count == 0)
            {
                return new object[0];
            }

            switch (type)
            {
                case ClaimSecurityValueType.Int64:
                    return ReadTyped<long>(buffer, count).Cast<object>();
                case ClaimSecurityValueType.Uint64:
                    return ReadTyped<ulong>(buffer, count).Cast<object>();
                case ClaimSecurityValueType.OctetString:
                    return ReadTyped<ClaimSecurityAttributeOctetStringValue>(buffer, count).Select(v => v.ToArray()).Cast<object>();
                case ClaimSecurityValueType.Sid:
                    return ReadTyped<ClaimSecurityAttributeOctetStringValue>(buffer, count).Select(v => v.ToSid()).Cast<object>();
                case ClaimSecurityValueType.Boolean:
                    return ReadTyped<long>(buffer, count).Select(v => v != 0).Cast<object>();
                case ClaimSecurityValueType.String:
                    return ReadTyped<UnicodeStringOut>(buffer, count).Select(n => n.ToString());
                case ClaimSecurityValueType.Fqbn:
                    return ReadTyped<ClaimSecurityAttributeFqbnValue>(buffer, count).Select(v => new ClaimSecurityAttributeFqbn(v)).Cast<object>();
                default:
                    return new object[0];
            }
        }

        public string Name { get; private set; }
        public ClaimSecurityValueType ValueType { get; private set; }
        public ClaimSecurityFlags Flags { get; private set; }
        public IEnumerable<object> Values { get; private set; }

        internal ClaimSecurityAttribute(IntPtr ptr)
        {
            ClaimSecurityAttributeV1_NT v1 = (ClaimSecurityAttributeV1_NT)Marshal.PtrToStructure(ptr, typeof(ClaimSecurityAttributeV1_NT));
            Name = v1.Name.ToString();
            ValueType = v1.ValueType;
            Flags = v1.Flags;

            Values = ReadValues(v1.Values, v1.ValueCount, v1.ValueType);
        }
    }

#pragma warning restore 1591

    /// <summary>
    /// Class to represent the state of a token privilege
    /// </summary>
    public class TokenPrivilege
    {
        [DllImport("Advapi32.dll", CharSet=CharSet.Unicode, SetLastError =true)]
        static extern bool LookupPrivilegeName(
           string lpSystemName,
           ref Luid lpLuid,
           [Out] StringBuilder lpName,
           ref int cchName);

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool LookupPrivilegeDisplayName(
          string lpSystemName,
          string lpName,
          StringBuilder lpDisplayName,
          ref int cchDisplayName,
          out int lpLanguageId
        );

        // Don't think there's a direct NT equivalent as this talks to LSASS.
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(
          string lpSystemName,
          string lpName,
          out Luid lpLuid
        );

        private static Luid LookupPrivilegeLuid(string name)
        {
            Luid luid;
            if (!LookupPrivilegeValue(".", name, out luid))
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
        public Luid Luid { get; private set; }

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
                    if (LookupPrivilegeName(null, ref luid, builder, ref name_length))
                    {
                        return builder.ToString();
                    }
                    return String.Format("UnknownPrivilege-{0}", luid);
                }
            }
        }

        /// <summary>
        /// Get the display name/description of the privilege
        /// </summary>
        /// <returns>The display name</returns>
        public string DisplayName
        {
            get
            {
                int name_length = 0;
                int lang_id = 0;
                string name = Name;
                LookupPrivilegeDisplayName(null, name, null, ref name_length, out lang_id);
                if (name_length <= 0)
                {
                    return String.Empty;
                }

                StringBuilder builder = new StringBuilder(name_length + 1);
                name_length = builder.Capacity;
                if (LookupPrivilegeDisplayName(null, name, builder, ref name_length, out lang_id))
                {
                    return builder.ToString();
                }
                return String.Empty;
            }
        }

        /// <summary>
        /// Get whether privilege is enabled
        /// </summary>
        public bool Enabled
        {
            get { return (Attributes & PrivilegeAttributes.Enabled) == PrivilegeAttributes.Enabled; }
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


    /// <summary>
    /// Class to represent a user group
    /// </summary>
    public sealed class UserGroup
    {
        /// <summary>
        /// The SID of the user group
        /// </summary>
        public Sid Sid { get; private set; }

        /// <summary>
        /// The attributes of the user group
        /// </summary>
        public GroupAttributes Attributes { get; private set; }

        /// <summary>
        /// Get whether the user group is enabled
        /// </summary>
        public bool Enabled
        {
            get
            {
                return (Attributes & GroupAttributes.Enabled) == GroupAttributes.Enabled;
            }
        }

        /// <summary>
        /// Get whether the user group is mandatory
        /// </summary>
        public bool Mandatory
        {
            get
            {
                return (Attributes & GroupAttributes.Mandatory) == GroupAttributes.Mandatory;
            }
        }

        /// <summary>
        /// Get whether the user group is used for deny only
        /// </summary>
        public bool DenyOnly
        {
            get
            {
                return (Attributes & GroupAttributes.UseForDenyOnly) == GroupAttributes.UseForDenyOnly;
            }
        }

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
            try
            {
                return new Sid(name);
            }
            catch (NtException)
            {
                return NtSecurity.LookupAccountName(name);
            }
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
                ret = NtSecurity.LookupAccountSid(Sid);
            }
            catch
            {
            }

            return ret ?? Sid.ToString();
        }        
    }

    /// <summary>
    /// Class representing a Token object
    /// </summary>
    public sealed class NtToken : NtObjectWithDuplicate<NtToken, TokenAccessRights>
    {
        internal NtToken(SafeKernelObjectHandle handle) : base(handle)
        {
        }
        
        private SafeStructureInOutBuffer<T> QueryToken<T>(TokenInformationClass token_info) where T : new()
        {
            SafeStructureInOutBuffer<T> ret = null;
            NtStatus status = NtStatus.STATUS_BUFFER_TOO_SMALL;
            try
            {
                int return_length;
                status = NtSystemCalls.NtQueryInformationToken(Handle, token_info, IntPtr.Zero, 0, out return_length);
                if ((status != NtStatus.STATUS_BUFFER_TOO_SMALL) && (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH))
                    throw new NtException(status);
                ret = new SafeStructureInOutBuffer<T>(return_length, false);
                status = NtSystemCalls.NtQueryInformationToken(Handle, token_info, ret.DangerousGetHandle(), ret.Length, out return_length).ToNtException();                
            }
            finally
            {
                if (ret != null && !status.IsSuccess())
                {
                    ret.Close();
                    ret = null;
                }
            }
            return ret;
        }

        private void SetToken<T>(TokenInformationClass token_info, T value) where T : new()
        {
            using (var buffer = value.ToBuffer())
            {
                NtSystemCalls.NtSetInformationToken(Handle, token_info, buffer, buffer.Length).ToNtException();
            }
        }

        /// <summary>
        /// Duplicate token as specific type
        /// </summary>
        /// <param name="type">The token type</param>
        /// <param name="level">The impersonation level us type is Impersonation</param>
        /// <param name="desired_access">Open with the desired access.</param>
        /// <returns>The new token</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtToken DuplicateToken(TokenType type, SecurityImpersonationLevel level, TokenAccessRights desired_access)
        {
            using (NtToken token = Duplicate(TokenAccessRights.Duplicate))
            {
                SafeKernelObjectHandle new_token;
                SecurityQualityOfService sqos = null;
                if (type == TokenType.Impersonation)
                {
                    sqos = new SecurityQualityOfService();
                    sqos.ImpersonationLevel = level;
                    sqos.ContextTrackingMode = SecurityContextTrackingMode.Static;
                }

                using (ObjectAttributes obja = new ObjectAttributes(null, AttributeFlags.None, SafeKernelObjectHandle.Null, sqos, null))
                {
                    NtSystemCalls.NtDuplicateToken(token.Handle,
                      desired_access, obja, false, type, out new_token).ToNtException();
                    return new NtToken(new_token);
                }
            }
        }

        /// <summary>
        /// Duplicate the token as a primary token
        /// </summary>
        /// <returns>The new token</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtToken DuplicateToken()
        {
            return DuplicateToken(TokenType.Primary, SecurityImpersonationLevel.Anonymous, TokenAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Duplicate token as an impersonation token with a specific level
        /// </summary>
        /// <param name="level">The token impersonation level</param>
        /// <returns>The new token</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtToken DuplicateToken(SecurityImpersonationLevel level)
        {
            return DuplicateToken(TokenType.Impersonation, level, TokenAccessRights.MaximumAllowed);
        }
        
        private bool SetPrivileges(TokenPrivilegesBuilder tp)
        {
            using (var priv_buffer = tp.ToBuffer())
            {
                NtStatus status = NtSystemCalls.NtAdjustPrivilegesToken(Handle, false, 
                    priv_buffer, priv_buffer.Length, IntPtr.Zero, IntPtr.Zero).ToNtException();
                if (status == NtStatus.STATUS_NOT_ALL_ASSIGNED)
                    return false;
                return true;
            }
        }

        /// <summary>
        /// Set a privilege state
        /// </summary>
        /// <param name="privilege">The name of the privilege (e.g. SeDebugPrivilege)</param>
        /// <param name="enable">True to enable the privilege, false to disable</param>
        /// <returns>True if successfully changed the state of the privilege</returns>
        public bool SetPrivilege(string privilege, bool enable)
        {
            TokenPrivilegesBuilder tp = new TokenPrivilegesBuilder();
            tp.AddPrivilege(privilege, enable);
            return SetPrivileges(tp);
        }

        /// <summary>
        /// Set a privilege state
        /// </summary>
        /// <param name="luid">The luid of the privilege</param>
        /// <param name="attributes">The privilege attributes to set.</param>
        /// <returns>True if successfully changed the state of the privilege</returns>
        public bool SetPrivilege(Luid luid, PrivilegeAttributes attributes)
        {
            TokenPrivilegesBuilder tp = new TokenPrivilegesBuilder();
            tp.AddPrivilege(luid, attributes);
            return SetPrivileges(tp);
        }

        /// <summary>
        /// Set a privilege state
        /// </summary>
        /// <param name="privilege">The value of the privilege</param>
        /// <param name="attributes">The privilege attributes to set.</param>
        /// <returns>True if successfully changed the state of the privilege</returns>
        public bool SetPrivilege(TokenPrivilegeValue privilege, PrivilegeAttributes attributes)
        {
            TokenPrivilegesBuilder tp = new TokenPrivilegesBuilder();
            tp.AddPrivilege(privilege, attributes);
            return SetPrivileges(tp);
        }

        /// <summary>
        /// Remove a privilege.
        /// </summary>
        /// <param name="privilege">The value of the privilege to remove.</param>
        /// <returns>True if successfully removed the privilege.</returns>
        public bool RemovePrivilege(TokenPrivilegeValue privilege)
        {
            return SetPrivilege(privilege, PrivilegeAttributes.Removed);
        }

        /// <summary>
        /// Remove a privilege.
        /// </summary>
        /// <param name="luid">The LUID of the privilege to remove.</param>
        /// <returns>True if successfully removed the privilege.</returns>
        public bool RemovePrivilege(Luid luid)
        {
            return SetPrivilege(luid, PrivilegeAttributes.Removed);
        }

        /// <summary>
        /// Enable debug privilege for the current process token.
        /// </summary>
        /// <returns>True if set the debug privilege</returns>
        public static bool EnableDebugPrivilege()
        {
            using (NtToken token = NtProcess.Current.OpenToken())
            {
                return token.SetPrivilege(TokenPrivilegeValue.SeDebugPrivilege, PrivilegeAttributes.Enabled);
            }
        }

        /// <summary>
        /// Open the process token of another process
        /// </summary>
        /// <param name="process">The process to open the token for</param>
        /// <param name="duplicate">True to duplicate the token before returning</param>
        /// <returns>The opened token</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenProcessToken(NtProcess process, bool duplicate)
        {
            return OpenProcessToken(process, duplicate, TokenAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open the process token of another process
        /// </summary>
        /// <param name="process">The process to open the token for</param>
        /// <param name="duplicate">True to duplicate the token before returning</param>
        /// <param name="desired_access">The desired access for the token</param>
        /// <returns>The opened token</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenProcessToken(NtProcess process, bool duplicate, TokenAccessRights desired_access)
        {
            SafeKernelObjectHandle new_token;
            NtSystemCalls.NtOpenProcessTokenEx(process.Handle,
              desired_access, AttributeFlags.None, out new_token).ToNtException();
            NtToken ret = new NtToken(new_token);
            if (duplicate)
            {
                try
                {
                    return ret.DuplicateToken();
                }
                finally
                {
                    ret.Close();
                }
            }
            return ret;
        }

        /// <summary>
        /// Open the process token of another process
        /// </summary>
        /// <param name="process">The process to open the token for</param>
        /// <returns>The opened token</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenProcessToken(NtProcess process)
        {
            return OpenProcessToken(process, false);
        }

        /// <summary>
        /// Open the process token of the current process
        /// </summary>
        /// <returns>The opened token</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenProcessToken()
        {
            return OpenProcessToken(false);
        }

        /// <summary>
        /// Open the process token of the current process
        /// </summary>        
        /// <param name="duplicate">True to duplicate the token before returning</param>
        /// <returns>The opened token</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenProcessToken(bool duplicate)
        {
            return OpenProcessToken(duplicate, TokenAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open the process token of the current process
        /// </summary>        
        /// <param name="duplicate">True to duplicate the token before returning</param>
        /// <param name="desired_access">The desired access for the token</param>
        /// <returns>The opened token</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenProcessToken(bool duplicate, TokenAccessRights desired_access)
        {
            return OpenProcessToken(NtProcess.Current, duplicate, desired_access);
        }


        /// <summary>
        /// Open the process token of another process
        /// </summary>
        /// <param name="pid">The id of the process to open the token for</param>
        /// <param name="duplicate">True to duplicate the token before returning</param>
        /// <returns>The opened token</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenProcessToken(int pid, bool duplicate)
        {
            return OpenProcessToken(pid, duplicate, TokenAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open the process token of another process
        /// </summary>
        /// <param name="pid">The id of the process to open the token for</param>
        /// <param name="duplicate">True to duplicate the token before returning</param>
        /// <param name="desired_access">The desired access for the token</param>
        /// <returns>The opened token</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenProcessToken(int pid, bool duplicate, TokenAccessRights desired_access)
        {
            using (NtProcess process = NtProcess.Open(pid, ProcessAccessRights.QueryInformation))
            {
                return OpenProcessToken(process, duplicate, desired_access);
            }
        }

        /// <summary>
        /// Open the process token of another process
        /// </summary>
        /// <param name="pid">The id of the process to open the token for</param>
        /// <returns>The opened token</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenProcessToken(int pid)
        {
            return OpenProcessToken(pid, false);
        }

        /// <summary>
        /// Open the thread token
        /// </summary>
        /// <param name="thread">The thread to open the token for</param>
        /// <param name="open_as_self">Open the token as the current identify rather than the impersonated one</param>
        /// <param name="duplicate">True to duplicate the token before returning</param>
        /// <param name="desired_access">The desired access for the token</param>
        /// <returns>The opened token, if no token return null</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenThreadToken(NtThread thread, bool open_as_self, bool duplicate, TokenAccessRights desired_access)
        {
            SafeKernelObjectHandle new_token;
            NtStatus status = NtSystemCalls.NtOpenThreadTokenEx(thread.Handle,
              desired_access, open_as_self, AttributeFlags.None, out new_token);
            if (status == NtStatus.STATUS_NO_TOKEN)
                return null;
            status.ToNtException();
            NtToken ret = new NtToken(new_token);
            if (duplicate)
            {
                try
                {
                    return ret.DuplicateToken();
                }
                finally
                {
                    ret.Close();
                }
            }
            return ret;
        }

        /// <summary>
        /// Open the thread token
        /// </summary>
        /// <param name="tid">The ID of the thread to open the token for</param>
        /// <param name="open_as_self">Open the token as the current identify rather than the impersonated one</param>
        /// <param name="duplicate">True to duplicate the token before returning</param>
        /// <param name="desired_access">The desired access for the token</param>
        /// <returns>The opened token, if no token return null</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenThreadToken(int tid, bool open_as_self, bool duplicate, TokenAccessRights desired_access)
        {
            using (NtThread thread = NtThread.Open(tid, ThreadAccessRights.QueryInformation))
            {
                return OpenThreadToken(thread, open_as_self, duplicate, desired_access);
            }
        }

        /// <summary>
        /// Open the thread token
        /// </summary>
        /// <param name="thread">The thread to open the token for</param>
        /// <param name="open_as_self">Open the token as the current identify rather than the impersonated one</param>
        /// <param name="duplicate">True to duplicate the token before returning</param>
        /// <returns>The opened token, if no token return null</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenThreadToken(NtThread thread, bool open_as_self, bool duplicate)
        {
            return OpenThreadToken(thread, open_as_self, duplicate, TokenAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open the thread token
        /// </summary>
        /// <param name="thread">The thread to open the token for</param>
        /// <returns>The opened token, if no token return null</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenThreadToken(NtThread thread)
        {
            return OpenThreadToken(thread, true, false);
        }

        /// <summary>
        /// Open the current thread token
        /// </summary>
        /// <param name="duplicate">True to duplicate the token before returning</param>
        /// <returns>The opened token, if no token return null</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenThreadToken(bool duplicate)
        {
            return OpenThreadToken(NtThread.Current, true, duplicate);
        }

        /// <summary>
        /// Open the current thread token
        /// </summary>
        /// <returns>The opened token, if no token return null</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenThreadToken()
        {
            return OpenThreadToken(false);
        }

        /// <summary>
        /// Open the effective token, thread if available or process
        /// </summary>
        /// <param name="thread">The thread to open the token for</param>
        /// <param name="duplicate">True to duplicate the token before returning</param>
        /// <returns>The opened token</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenEffectiveToken(NtThread thread, bool duplicate)
        {
            NtToken token = null;
            try
            {
                token = OpenThreadToken(thread, true, duplicate);
            }
            catch (NtException)
            {
            }

            return token ?? OpenProcessToken(thread.ProcessId, duplicate);
        }

        /// <summary>
        /// Open the current effective token, thread if available or process
        /// </summary>
        /// <returns>The opened token</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtToken OpenEffectiveToken()
        {
            return OpenEffectiveToken(NtThread.Current, false);
        }

        /// <summary>
        /// Create a LowBox token from the current token.
        /// </summary>
        /// <param name="package_sid">The package SID</param>
        /// <returns>The created LowBox token.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtToken CreateLowBoxToken(Sid package_sid)
        {
            return CreateLowBoxToken(package_sid, new NtObject[0]);
        }

        /// <summary>
        /// Create a LowBox token from the current token.
        /// </summary>
        /// <param name="package_sid">The package SID</param>
        /// <param name="handles">List of handles to capture with the token</param>
        /// <returns>The created LowBox token.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtToken CreateLowBoxToken(Sid package_sid, params NtObject[] handles)
        {
            return CreateLowBoxToken(package_sid, new Sid[0], handles, TokenAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Create a LowBox token from the current token.
        /// </summary>
        /// <param name="package_sid">The package SID</param>
        /// <param name="handles">List of handles to capture with the token</param>
        /// <param name="capability_sids">List of capability sids to add.</param>
        /// <param name="desired_access">Desired token access.</param>
        /// <returns>The created LowBox token.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtToken CreateLowBoxToken(Sid package_sid, IEnumerable<Sid> capability_sids,
            IEnumerable<NtObject> handles, TokenAccessRights desired_access)
        {
            SafeKernelObjectHandle token;

            IntPtr[] handle_array = handles.Select(h => h.Handle.DangerousGetHandle()).ToArray();

            using (var sids = new DisposableList<SafeSidBufferHandle>())
            {
                SidAndAttributes[] capabilities = capability_sids.Select(s =>
                    {
                        SafeSidBufferHandle sid = s.ToSafeBuffer();
                        sids.Add(sid);
                        return new SidAndAttributes() { Sid = sid.DangerousGetHandle() };
                    }
                    ).ToArray();
                NtSystemCalls.NtCreateLowBoxToken(out token,
                    Handle, TokenAccessRights.MaximumAllowed,
                  new ObjectAttributes(), package_sid.ToArray(), capabilities.Length,
                  capabilities.Length == 0 ? null : capabilities, 
                  handle_array.Length, handle_array.Length == 0 ? null : handle_array).ToNtException();
            }
            return new NtToken(token);
        }

        private static SafeTokenGroupsBuffer BuildGroups(IEnumerable<Sid> sids, GroupAttributes attributes)
        {
            TokenGroupsBuilder builder = new TokenGroupsBuilder();
            foreach (Sid sid in sids)
            {
                builder.AddGroup(sid, attributes);
            }
            return builder.ToBuffer();
        }

        /// <summary>
        /// Filter a token to remove groups/privileges and add restricted SIDs
        /// </summary>
        /// <param name="flags">Filter token flags</param>
        /// <param name="sids_to_disable">List of SIDs to disable</param>
        /// <param name="privileges_to_delete">List of privileges to delete</param>
        /// <param name="restricted_sids">List of restricted SIDs to add</param>
        /// <returns>The new token.</returns>
        public NtToken Filter(FilterTokenFlags flags, IEnumerable<Sid> sids_to_disable, IEnumerable<TokenPrivilegeValue> privileges_to_delete, IEnumerable<Sid> restricted_sids)
        {
            return Filter(flags, sids_to_disable, privileges_to_delete.Select(p => new Luid((uint)p, 0)), restricted_sids);
        }

        /// <summary>
        /// Filter a token to remove groups/privileges and add restricted SIDs
        /// </summary>
        /// <param name="flags">Filter token flags</param>
        /// <param name="sids_to_disable">List of SIDs to disable</param>
        /// <param name="privileges_to_delete">List of privileges to delete</param>
        /// <param name="restricted_sids">List of restricted SIDs to add</param>
        /// <returns>The new token.</returns>
        public NtToken Filter(FilterTokenFlags flags, IEnumerable<Sid> sids_to_disable, IEnumerable<Luid> privileges_to_delete, IEnumerable<Sid> restricted_sids)
        {
            SafeTokenGroupsBuffer sids_to_disable_buffer = SafeTokenGroupsBuffer.Null;
            SafeTokenGroupsBuffer restricted_sids_buffer = SafeTokenGroupsBuffer.Null;
            SafeTokenPrivilegesBuffer privileges_to_delete_buffer = SafeTokenPrivilegesBuffer.Null;

            try
            {
                if (sids_to_disable != null && sids_to_disable.Count() > 0)
                {
                    sids_to_disable_buffer = BuildGroups(sids_to_disable, GroupAttributes.None);
                }
                if (restricted_sids != null && restricted_sids.Count() > 0)
                {
                    restricted_sids_buffer = BuildGroups(restricted_sids, GroupAttributes.None);
                }
                if (privileges_to_delete != null && privileges_to_delete.Count() > 0)
                {
                    TokenPrivilegesBuilder builder = new TokenPrivilegesBuilder();
                    foreach (Luid priv in privileges_to_delete)
                    {
                        builder.AddPrivilege(priv, PrivilegeAttributes.Disabled);
                    }
                    privileges_to_delete_buffer = builder.ToBuffer();
                }

                SafeKernelObjectHandle handle;
                NtSystemCalls.NtFilterToken(Handle, flags, sids_to_disable_buffer, privileges_to_delete_buffer, restricted_sids_buffer, out handle).ToNtException();
                return new NtToken(handle);
            }
            finally
            {
                sids_to_disable_buffer.Close();
                restricted_sids_buffer.Close();
                privileges_to_delete_buffer.Close();
            }
        }

        /// <summary>
        /// Filter a token to remove privileges and groups.
        /// </summary>
        /// <param name="flags">Filter token flags</param>
        /// <returns>The new filtered token.</returns>
        public NtToken Filter(FilterTokenFlags flags)
        {
            return Filter(flags, null, (IEnumerable<Luid>)null, null);
        }

        /// <summary>
        /// Set the state of a group
        /// </summary>
        /// <param name="group">The group SID to set</param>
        /// <param name="attributes">The attributes to set</param>
        public void SetGroup(Sid group, GroupAttributes attributes)
        {
            using (var buffer = BuildGroups(new Sid[] { group }, attributes))
            {
                NtSystemCalls.NtAdjustGroupsToken(Handle, false, buffer, 0, IntPtr.Zero, IntPtr.Zero).ToNtException();
            }
        }
        
        /// <summary>
        /// Set the session ID of a token
        /// </summary>
        /// <param name="session_id">The session ID</param>
        public void SetSessionId(int session_id)
        {
            SetToken(TokenInformationClass.TokenSessionId, session_id);
        }

        /// <summary>
        /// Get token user
        /// </summary>
        public UserGroup User
        {
            get
            {
                using (var user = QueryToken<TokenUser>(TokenInformationClass.TokenUser))
                {
                    return user.Result.User.ToUserGroup();
                }
            }
        }

        private UserGroup[] QueryGroups(TokenInformationClass info_class)
        {
            using (var groups = QueryToken<TokenGroups>(info_class))
            {
                TokenGroups result = groups.Result;
                SidAndAttributes[] sids = new SidAndAttributes[result.GroupCount];
                groups.Data.ReadArray(0, sids, 0, result.GroupCount);
                return sids.Select(s => s.ToUserGroup()).ToArray();
            }
        }

        /// <summary>
        /// Get token groups
        /// </summary>
        public UserGroup[] Groups
        {
            get
            {
                return QueryGroups(TokenInformationClass.TokenGroups);
            }
        }

        /// <summary>
        /// Get list of enabled groups.
        /// </summary>
        public IEnumerable<UserGroup> EnabledGroups
        {
            get
            {
                return Groups.Where(g => g.Enabled);
            }
        }

        /// <summary>
        /// Get list of deny only groups.
        /// </summary>
        public IEnumerable<UserGroup> DenyOnlyGroups
        {
            get
            {
                return Groups.Where(g => g.DenyOnly);
            }
        }

        /// <summary>
        /// Get count of groups in this token.
        /// </summary>
        public int GroupCount
        {
            get { return Groups.Length; }
        }

        /// <summary>
        /// Get the current user.
        /// </summary>
        public static UserGroup CurrentUser
        {
            get
            {
                using (NtToken token = OpenEffectiveToken())
                {
                    return token.User;
                }
            }
        }

        private TokenStatistics _token_stats;

        private TokenStatistics GetTokenStats()
        {
            if (_token_stats == null)
            {
                using (var stats = QueryToken<TokenStatistics>(TokenInformationClass.TokenStatistics))
                {
                    _token_stats = stats.Result;
                }
            }
            return _token_stats;
        }
    
        /// <summary>
        /// Get the authentication ID for the token
        /// </summary>
        public Luid AuthenticationId
        {
            get
            {
                return GetTokenStats().AuthenticationId;
            }
        }

        /// <summary>
        /// Get the token's type
        /// </summary>
        public TokenType TokenType
        {
            get
            {
                return GetTokenStats().TokenType;
            }
        }

        /// <summary>
        /// Get the token's expiration time.
        /// </summary>
        public long ExpirationTime
        {
            get
            {
                return GetTokenStats().ExpirationTime.QuadPart;
            }
        }

        /// <summary>
        /// Get the token's expiration time as a DateTime structure.
        /// </summary>
        public DateTime ExpirationTimeAsDateTime
        {
            get
            {
                return DateTime.FromFileTime(ExpirationTime);
            }
        }

        /// <summary>
        /// Get the Token's Id
        /// </summary>
        public Luid Id
        {
            get
            {
                return GetTokenStats().TokenId;
            }
        }

        /// <summary>
        /// Get the Toen's modified Id.
        /// </summary>
        public Luid ModifiedId
        {
            get
            {
                return GetTokenStats().ModifiedId;
            }
        }

        /// <summary>
        /// Get the token's owner.
        /// </summary>
        public Sid Owner
        {
            get
            {
                using (var owner_buf = QueryToken<TokenOwner>(TokenInformationClass.TokenOwner))
                {
                    return new Sid(owner_buf.Result.Owner);
                }
            }
        }

        /// <summary>
        /// Get the token's primary group
        /// </summary>
        public Sid PrimaryGroup
        {
            get
            {
                using (var owner_buf = QueryToken<TokenPrimaryGroup>(TokenInformationClass.TokenPrimaryGroup))
                {
                    return new Sid(owner_buf.Result.PrimaryGroup);
                }
            }
        }

        /// <summary>
        /// Get the token's default DACL
        /// </summary>
        public Acl DefaultDalc
        {
            get
            {
                using (var dacl_buf = QueryToken<TokenDefaultDacl>(TokenInformationClass.TokenDefaultDacl))
                {
                    return new Acl(dacl_buf.Result.DefaultDacl, false);
                }
            }
        }

        /// <summary>
        /// Set a token's default DACL
        /// </summary>
        /// <param name="dacl">The DACL to set.</param>
        public void SetDefaultDacl(Acl dacl)
        {
            using (var dacl_buf = dacl.ToSafeBuffer())
            {
                TokenDefaultDacl default_dacl = new TokenDefaultDacl();
                default_dacl.DefaultDacl = dacl_buf.DangerousGetHandle();
                SetToken(TokenInformationClass.TokenDefaultDacl, default_dacl);
            }
        }

        /// <summary>
        /// Get the token's source
        /// </summary>
        public TokenSource Source
        {
            get
            {
                using (var source_buf = QueryToken<TokenSource>(TokenInformationClass.TokenSource))
                {
                    return source_buf.Result;
                }
            }
        }

        /// <summary>
        /// Get token's restricted sids
        /// </summary>
        public UserGroup[] RestrictedSids
        {
            get
            {
                return QueryGroups(TokenInformationClass.TokenRestrictedSids);
            }
        }

        /// <summary>
        /// Get count of restricted sids
        /// </summary>
        public int RestrictedSidsCount
        {
            get { return RestrictedSids.Length; }
        }

        /// <summary>
        /// Get token's impersonation level
        /// </summary>
        public SecurityImpersonationLevel ImpersonationLevel
        {
            get
            {
                return GetTokenStats().ImpersonationLevel;
            }
        }

        /// <summary>
        /// Get token's session ID
        /// </summary>
        public int SessionId
        {
            get
            {
                using (var buf = QueryToken<int>(TokenInformationClass.TokenSessionId))
                {
                    return buf.Result;
                }
            }
        }

        /// <summary>
        /// Get whether token has sandbox inert flag set.
        /// </summary>
        public bool SandboxInert
        {
            get
            {
                using (var buf = QueryToken<int>(TokenInformationClass.TokenSandBoxInert))
                {
                    return buf.Result != 0;
                }
            }
        }

        /// <summary>
        /// Get token's origin
        /// </summary>
        public Luid Origin
        {
            get
            {
                using (var buf = QueryToken<Luid>(TokenInformationClass.TokenOrigin))
                {
                    return buf.Result;
                }
            }
        }

        /// <summary>
        /// Get token's elevation type
        /// </summary>
        public TokenElevationType ElevationType
        {
            get
            {
                using (var buf = QueryToken<int>(TokenInformationClass.TokenElevationType))
                {
                    return (TokenElevationType)buf.Result;
                }
            }
        }

        /// <summary>
        /// Get whether token is elevated
        /// </summary>
        public bool Elevated
        {
            get
            {
                using (var buf = QueryToken<int>(TokenInformationClass.TokenElevation))
                {
                    return buf.Result != 0;
                }
            }
        }

        /// <summary>
        /// Get whether token has restrictions
        /// </summary>
        public bool HasRestrictions
        {
            get
            {
                using (var buf = QueryToken<int>(TokenInformationClass.TokenHasRestrictions))
                {
                    return buf.Result != 0;
                }
            }
        }

        /// <summary>
        /// Get whether token has UI access flag set
        /// </summary>
        public bool UiAccess
        {
            get
            {
                using (var buf = QueryToken<int>(TokenInformationClass.TokenUIAccess))
                {
                    return buf.Result != 0;
                }
            }
        }

        /// <summary>
        /// Get whether virtualization is allowed
        /// </summary>
        public bool VirtualizationAllowed
        {
            get
            {
                using (var buf = QueryToken<int>(TokenInformationClass.TokenVirtualizationAllowed))
                {
                    return buf.Result != 0;
                }
            }
        }

        /// <summary>
        /// Get whether virtualization is enabled
        /// </summary>
        public bool VirtualizationEnabled
        {
            get
            {
                using (var buf = QueryToken<int>(TokenInformationClass.TokenVirtualizationEnabled))
                {
                    return buf.Result != 0;
                }
            }
        }

        /// <summary>
        /// Set virtualization enabled
        /// </summary>
        /// <param name="enable">True to enable virtualization</param>
        public void SetVirtualizationEnabled(bool enable)
        {
            SetToken(TokenInformationClass.TokenVirtualizationEnabled, enable ? 1 : 0);
        }

        /// <summary>
        /// Set UI Access flag.
        /// </summary>
        /// <param name="enable">True to enable UI Access.</param>
        public void SetUiAccess(bool enable)
        {
            SetToken(TokenInformationClass.TokenUIAccess, enable ? 1 : 0);
        }

        /// <summary>
        /// Get whether token is stricted
        /// </summary>
        public bool Restricted
        {
            get
            {
                return RestrictedSidsCount > 0;
            }
        }

        /// <summary>
        /// Get the linked token 
        /// </summary>
        /// <returns>The linked token</returns>
        public NtToken GetLinkedToken()
        {
            using (var buf = QueryToken<IntPtr>(TokenInformationClass.TokenLinkedToken))
            {
                return new NtToken(new SafeKernelObjectHandle(buf.Result, true));
            }
        }

        /// <summary>
        /// Get token capacilities
        /// </summary>
        public UserGroup[] Capabilities
        {
            get
            {
                return QueryGroups(TokenInformationClass.TokenCapabilities);
            }
        }

        /// <summary>
        /// Get token mandatory policy
        /// </summary>
        public TokenMandatoryPolicy MandatoryPolicy
        {
            get
            {
                using (var buf = QueryToken<int>(TokenInformationClass.TokenMandatoryPolicy))
                {
                    return (TokenMandatoryPolicy)buf.Result;
                }
            }
        }

        /// <summary>
        /// Get token logon sid
        /// </summary>
        public UserGroup LogonSid
        {
            get
            {
                return QueryGroups(TokenInformationClass.TokenLogonSid).FirstOrDefault();
            }
        }

        /// <summary>
        /// Impersonate the token
        /// </summary>
        /// <returns>An impersonation context, dispose to revert to process token</returns>
        public ThreadImpersonationContext Impersonate()
        {
            return NtThread.Current.Impersonate(this);
        }

        /// <summary>
        /// Impersonate another process' token
        /// </summary>
        /// <param name="impersonation_level">The impersonation level</param>
        /// <param name="pid">Process ID of the other process</param>
        /// <returns>An impersonation context, dispose to revert to process token</returns>
        public static ThreadImpersonationContext Impersonate(int pid, SecurityImpersonationLevel impersonation_level)
        {
            using (NtToken process_token = OpenProcessToken(pid))
            {
                using (NtToken imp_token = process_token.DuplicateToken(impersonation_level))
                {
                    return imp_token.Impersonate();
                }
            }
        }

        /// <summary>
        /// Get token's integrity level sid
        /// </summary>
        public UserGroup IntegrityLevelSid
        {
            get
            {
                using (var label = QueryToken<TokenMandatoryLabel>(TokenInformationClass.TokenIntegrityLevel))
                {
                    return label.Result.Label.ToUserGroup();
                }
            }
        }

        /// <summary>
        /// Get token's App Container number.
        /// </summary>
        public int AppContainerNumber
        {
            get
            {
                using (var buf = QueryToken<int>(TokenInformationClass.TokenAppContainerNumber))
                {
                    return buf.Result;
                }
            }
        }

        /// <summary>
        /// Get token's integrity level.
        /// </summary>
        public TokenIntegrityLevel IntegrityLevel
        {
            get
            {
                UserGroup group = IntegrityLevelSid;
                string[] parts = group.Sid.ToString().Split('-');
                return (TokenIntegrityLevel)int.Parse(parts[parts.Length - 1]);
            }
        }

        /// <summary>
        /// Get token's security attributes
        /// </summary>
        public ClaimSecurityAttribute[] SecurityAttributes
        {
            get
            {
                using (var buf = QueryToken<ClaimSecurityAttributesInformation>(TokenInformationClass.TokenSecurityAttributes))
                {
                    ClaimSecurityAttributesInformation r = buf.Result;
                    List<ClaimSecurityAttribute> attributes = new List<ClaimSecurityAttribute>();
                    if (r.AttributeCount > 0)
                    {
                        int count = r.AttributeCount;
                        IntPtr buffer = r.pAttributeV1;
                        while (count > 0)
                        {
                            attributes.Add(new ClaimSecurityAttribute(buffer));
                            count--;
                            buffer += Marshal.SizeOf(typeof(ClaimSecurityAttributeV1_NT));
                        }
                    }
                    return attributes.ToArray();
                }
            }
        }

        private void SetIntegrityLevel(Sid sid)
        {
            using (SafeSidBufferHandle sid_buffer = sid.ToSafeBuffer())
            {                
                TokenMandatoryLabel label = new TokenMandatoryLabel();
                label.Label.Sid = sid_buffer.DangerousGetHandle();
                SetToken(TokenInformationClass.TokenIntegrityLevel, label);                
            }
        }

        /// <summary>
        /// Set the token's integrity level.
        /// </summary>
        /// <param name="level">The level to set.</param>
        public void SetIntegrityLevel(int level)
        {            
            SetIntegrityLevel(NtSecurity.GetIntegritySid(level));
        }

        /// <summary>
        /// Set the token's integrity level.
        /// </summary>
        /// <param name="level">The level to set.</param>
        public void SetIntegrityLevel(TokenIntegrityLevel level)
        {
            SetIntegrityLevel(NtSecurity.GetIntegritySid(level));
        }

        /// <summary>
        /// Get whether a token is an AppContainer token
        /// </summary>
        public bool AppContainer
        {
            get
            {
                using (var appcontainer = QueryToken<uint>(TokenInformationClass.TokenIsAppContainer))
                {
                    return appcontainer.Result != 0;
                }
            }
        }

        /// <summary>
        /// Get token's AppContainer sid
        /// </summary>
        public Sid AppContainerSid
        {
            get
            {
                using (var acsid = QueryToken<TokenAppContainerInformation>(TokenInformationClass.TokenAppContainerSid))
                {
                    return new Sid(acsid.Result.TokenAppContainer);
                }
            }
        }

        /// <summary>
        /// Get token's device groups
        /// </summary>
        public UserGroup[] DeviceGroups
        {
            get
            {
                return QueryGroups(TokenInformationClass.TokenDeviceGroups);
            }
        }

        /// <summary>
        /// Get token's restricted device groups.
        /// </summary>
        public UserGroup[] RestrictedDeviceGroups
        {
            get
            {
                return QueryGroups(TokenInformationClass.TokenRestrictedDeviceGroups);
            }
        }

        /// <summary>
        /// Get list of privileges for token
        /// </summary>
        /// <returns>The list of privileges</returns>
        /// <exception cref="NtException">Thrown if can't query privileges</exception>
        public TokenPrivilege[] Privileges
        {
            get
            {
                using (var buffer = QueryToken<TokenPrivileges>(TokenInformationClass.TokenPrivileges))
                {
                    int count = buffer.Result.PrivilegeCount;
                    LuidAndAttributes[] attrs = new LuidAndAttributes[count];
                    buffer.Data.ReadArray(0, attrs, 0, count);
                    return attrs.Select(a => new TokenPrivilege(a.Luid, (PrivilegeAttributes)a.Attributes)).ToArray();
                }
            }
        }

        /// <summary>
        /// Get the state of a privilege.
        /// </summary>
        /// <param name="privilege">The privilege to get the state of.</param>
        /// <returns>The privilege, or null if it can't be found</returns>
        /// <exception cref="NtException">Thrown if can't query privileges</exception>
        public TokenPrivilege GetPrivilege(TokenPrivilegeValue privilege)
        {
            Luid priv_value = new Luid((uint)privilege, 0);
            foreach (TokenPrivilege priv in Privileges)
            {
                if (priv.Luid.Equals(priv_value))
                {
                    return priv;
                }
            }
            return null;
        }

        /// <summary>
        /// Get authentication ID for LOCAL SYSTEM
        /// </summary>
        public static Luid LocalSystemAuthId { get { return new Luid(0x3e7, 0); } }
        /// <summary>
        /// Get authentication ID for LOCAL SERVICE
        /// </summary>
        public static Luid LocalServiceAuthId { get { return new Luid(0x3e5, 0); } }
        /// <summary>
        /// Get authentication ID for NETWORK SERVICE
        /// </summary>
        public static Luid NetworkServiceAuthId { get { return new Luid(0x3e4, 0); } }

        /// <summary>
        /// Get full path to token
        /// </summary>
        public override string FullPath
        {
            get
            {
                try
                {
                    return String.Format("{0} - {1}", User.Sid.Name, AuthenticationId);
                }
                catch
                {
                    return String.Empty;
                }
            }
        }
    }
}
