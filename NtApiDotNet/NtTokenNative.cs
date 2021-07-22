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

using NtApiDotNet.Utilities.Reflection;
using System;
using System.Globalization;
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
        TokenPrivateNameSpace = 42,
        TokenSingletonAttributes = 43,
        TokenBnoIsolation = 44,
        TokenChildProcessFlags = 45,
        TokenIsLessPrivilegedAppContainer = 46,
        TokenIsSandboxed = 47,
        TokenOriginatingProcessTrustLevel = 48,
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
        SeCreateSymbolicLinkPrivilege,
        SeDelegateSessionUserImpersonatePrivilege,
    }

    [Flags]
    public enum TokenAccessRights : uint
    {
        None = 0,
        [SDKName("TOKEN_ASSIGN_PRIMARY")]
        AssignPrimary = 0x0001,
        [SDKName("TOKEN_DUPLICATE")]
        Duplicate = 0x0002,
        [SDKName("TOKEN_IMPERSONATE")]
        Impersonate = 0x0004,
        [SDKName("TOKEN_QUERY")]
        Query = 0x0008,
        [SDKName("TOKEN_QUERY_SOURCE")]
        QuerySource = 0x0010,
        [SDKName("TOKEN_ADJUST_PRIVILEGES")]
        AdjustPrivileges = 0x0020,
        [SDKName("TOKEN_ADJUST_GROUPS")]
        AdjustGroups = 0x0040,
        [SDKName("TOKEN_ADJUST_DEFAULT")]
        AdjustDefault = 0x0080,
        [SDKName("TOKEN_ADJUST_SESSIONID")]
        AdjustSessionId = 0x0100,
        [SDKName("GENERIC_READ")]
        GenericRead = GenericAccessRights.GenericRead,
        [SDKName("GENERIC_WRITE")]
        GenericWrite = GenericAccessRights.GenericWrite,
        [SDKName("GENERIC_EXECUTE")]
        GenericExecute = GenericAccessRights.GenericExecute,
        [SDKName("GENERIC_ALL")]
        GenericAll = GenericAccessRights.GenericAll,
        [SDKName("DELETE")]
        Delete = GenericAccessRights.Delete,
        [SDKName("READ_CONTROL")]
        ReadControl = GenericAccessRights.ReadControl,
        [SDKName("WRITE_DAC")]
        WriteDac = GenericAccessRights.WriteDac,
        [SDKName("WRITE_OWNER")]
        WriteOwner = GenericAccessRights.WriteOwner,
        [SDKName("SYNCHRONIZE")]
        Synchronize = GenericAccessRights.Synchronize,
        [SDKName("MAXIMUM_ALLOWED")]
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        [SDKName("ACCESS_SYSTEM_SECURITY")]
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    public enum TokenIntegrityLevel
    {
        Untrusted = 0,
        Low = 0x1000,
        Medium = 0x2000,
        MediumPlus = Medium + 0x100,
        High = 0x3000,
        System = 0x4000,
        ProtectedProcess = 0x5000,
    };

    public enum TokenElevationType
    {
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

    // Not all these flags are accessible from user mode.
    [Flags]
    public enum TokenFlags
    {
        [SDKName("TOKEN_HAS_TRAVERSE_PRIVILEGE")]
        HasTraversePrivilege = 1,
        [SDKName("TOKEN_HAS_BACKUP_PRIVILEGE")]
        HasBackupPrivilege = 2,
        [SDKName("TOKEN_HAS_RESTORE_PRIVILEGE")]
        HasRestorePrivilege = 4,
        [SDKName("TOKEN_WRITE_RESTRICTED")]
        WriteRestricted = 8,
        [SDKName("TOKEN_IS_RESTRICTED")]
        IsRestricted = 0x10,
        [SDKName("TOKEN_SESSION_NOT_REFERENCED")]
        SessionNotReferenced = 0x20,
        [SDKName("TOKEN_SANDBOX_INERT")]
        SandboxInert = 0x40,
        [SDKName("TOKEN_HAS_IMPERSONATE_PRIVILEGE")]
        HasImpersonatePrivilege = 0x80,
        [SDKName("SE_BACKUP_PRIVILEGES_CHECKED")]
        BackupPrivilegesChecked = 0x100,
        [SDKName("TOKEN_VIRTUALIZE_ALLOWED")]
        VirtualizeAllowed = 0x200,
        [SDKName("TOKEN_VIRTUALIZE_ENABLED")]
        VirtualizeEnabled = 0x400,
        [SDKName("TOKEN_IS_FILTERED")]
        IsFiltered = 0x800,
        [SDKName("TOKEN_UIACCESS")]
        UiAccess = 0x1000,
        [SDKName("TOKEN_NOT_LOW")]
        NotLow = 0x2000,
        [SDKName("TOKEN_LOWBOX")]
        LowBox = 0x4000,
        [SDKName("TOKEN_HAS_OWN_CLAIM_ATTRIBUTES")]
        HasOwnClaimAttributes = 0x8000,
        [SDKName("TOKEN_PRIVATE_NAMESPACE")]
        PrivateNamespace = 0x10000,
        [SDKName("TOKEN_DO_NOT_USE_GLOBAL_ATTRIBS_FOR_QUERY")]
        DoNotUseGlobalAttributesForQuery = 0x20000,
        [SDKName("SPECIAL_ENCRYPTED_OPEN")]
        SpecialEncryptedOpen = 0x40000,
        [SDKName("TOKEN_NO_CHILD_PROCESS")]
        NoChildProcess = 0x80000,
        [SDKName("TOKEN_NO_CHILD_PROCESS_UNLESS_SECURE")]
        NoChildProcessUnlessSecure = 0x100000,
        [SDKName("TOKEN_AUDIT_NO_CHILD_PROCESS")]
        AuditNoChildProcess = 0x200000,
        [SDKName("TOKEN_PERMISSIVE_LEARNING_MODE")]
        PermissiveLearningMode = 0x00400000,
        [SDKName("TOKEN_ENFORCE_REDIRECTION_TRUST")]
        EnforceRedirectionTrust = 0x00800000,
        [SDKName("TOKEN_AUDIT_REDIRECTION_TRUST")]
        AuditRedirectionTrust = 0x01000000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SidAndAttributes
    {
        public IntPtr Sid;
        public GroupAttributes Attributes;

        public UserGroup ToUserGroup()
        {
            return new UserGroup(new Sid(Sid), Attributes);
        }
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenAccessInformationTruncated
    {
        public IntPtr SidHash;
        public IntPtr RestrictedSidHash;
        public IntPtr Privileges;
        public Luid AuthenticationId;
        public TokenType TokenType;
        public SecurityImpersonationLevel ImpersonationLevel;
        public TokenMandatoryPolicy MandatoryPolicy;
        public TokenFlags Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenAccessInformation
    {
        public IntPtr SidHash;
        public IntPtr RestrictedSidHash;
        public IntPtr Privileges;
        public Luid AuthenticationId;
        public TokenType TokenType;
        public SecurityImpersonationLevel ImpersonationLevel;
        public TokenMandatoryPolicy MandatoryPolicy;
        public TokenFlags Flags;
        public int AppContainerNumber;
        public IntPtr PackageSid;
        public IntPtr CapabilitiesHash;
        public IntPtr TrustLevelSid;
        public IntPtr SecurityAttributes;
    }

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
        private readonly byte[] _sourcename;
        private Luid _sourceidentifier;

        public TokenSource()
        {
            _sourcename = new byte[8];
        }

        public TokenSource(string source) 
            : this(source, NtSystemInfo.AllocateLocallyUniqueId(false).GetResultOrDefault())
        {
        }

        public TokenSource(string source, Luid identifier)
        {
            _sourcename = Encoding.ASCII.GetBytes(source);
            if (_sourcename.Length != 8)
            {
                Array.Resize(ref _sourcename, 8);
            }
            _sourceidentifier = identifier;
        }

        public Luid SourceIdentifier => _sourceidentifier;

        public string SourceName => Encoding.ASCII.GetString(_sourcename).TrimEnd('\0');

        public override string ToString()
        {
            return $"Identifier = {SourceIdentifier} - Name = {SourceName}";
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenAuditPolicy
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 30)]
        public byte[] PerUserPolicy;
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
            return $"{HighPart:X08}-{LowPart:X08}";
        }

        public override bool Equals(object obj)
        {
            if (obj is Luid luid)
            {
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
            LargeInteger li = new LargeInteger
            {
                LowPart = LowPart,
                HighPart = HighPart
            };
            return li.QuadPart;
        }

        public static Luid Parse(string value)
        {
            string[] parts = value.Split('-');
            if (parts.Length == 1)
                return new Luid(long.Parse(value));
            if (parts.Length != 2)
                throw new FormatException("LUID value must be two hex values separated by a dash or a decimal integer.");
            return new Luid(uint.Parse(parts[1], NumberStyles.HexNumber), 
                int.Parse(parts[0], NumberStyles.HexNumber));
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LuidAndAttributes
    {
        public Luid Luid;
        public PrivilegeAttributes Attributes;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Privileges")]
    public class TokenPrivileges
    {
        public int PrivilegeCount;
        public LuidAndAttributes Privileges;
    }

    public enum ClaimSecurityValueType : ushort
    {
        None = 0,
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64")]
        Int64 = 0x0001,
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64")]
        UInt64 = 0x0002,
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING")]
        String = 0x0003,
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN")]
        Fqbn = 0x0004,
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_TYPE_SID")]
        Sid = 0x0005, // CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN")]
        Boolean = 0x0006, // Actually UInt64
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING")]
        OctetString = 0x0010,
    }

    [Flags]
    public enum ClaimSecurityFlags
    {
        [SDKName("NONE")]
        None = 0,
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE")]
        NonInheritable = 0x0001,
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE")]
        CaseSensitive = 0x0002,
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY")]
        UseForDenyOnly = 0x0004,
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT")]
        DisabledByDefault = 0x0008,
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_DISABLED")]
        Disabled = 0x0010,
        [SDKName("CLAIM_SECURITY_ATTRIBUTE_MANDATORY")]
        Mandatory = 0x0020,
        Unique = 0x0040,
        InheritOnce = 0x0080,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ClaimSecurityAttributeOctetStringValue
    {
        public IntPtr pValue;
        public int ValueLength;

        public byte[] ToArray()
        {
            if (pValue == IntPtr.Zero || ValueLength == 0)
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
    public struct SecurityAttributeFqbnValue
    {
        public ulong Version;
        public UnicodeStringOut Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ClaimSecurityAttributeFqbnValue
    {
        public ulong Version;
        public IntPtr Name;
    }

    public class ClaimSecurityAttributeFqbn
    {
        public Version Version { get; }
        public string Name { get; }

        public ClaimSecurityAttributeFqbn(Version version, string name)
        {
            Version = version;
            Name = name;
        }

        internal ClaimSecurityAttributeFqbn(SecurityAttributeFqbnValue value)
        {
            Version = NtObjectUtils.UnpackVersion(value.Version);
            Name = value.Name.ToString();
        }

        internal ClaimSecurityAttributeFqbn(ClaimSecurityAttributeFqbnValue value)
        {
            Version = NtObjectUtils.UnpackVersion(value.Version);
            Name = Marshal.PtrToStringUni(value.Name);
        }

        internal ClaimSecurityAttributeFqbn Clone()
        {
            return new ClaimSecurityAttributeFqbn((Version)Version.Clone(), Name);
        }

        public override string ToString()
        {
            return $"Version {Version} - {Name}";
        }
    }

    internal interface ISecurityAttributeV1
    {
        string GetName();
        ClaimSecurityValueType GetValueType();
        ClaimSecurityFlags GetFlags();
        int GetValueCount();
        IntPtr GetValues();
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityAttributeV1 : ISecurityAttributeV1
    {
        public UnicodeStringOut Name;
        public ClaimSecurityValueType ValueType;
        public ushort Reserved;
        public ClaimSecurityFlags Flags;
        public int ValueCount;
        public IntPtr Values;

        ClaimSecurityFlags ISecurityAttributeV1.GetFlags()
        {
            return Flags;
        }

        string ISecurityAttributeV1.GetName()
        {
            return Name.ToString();
        }

        int ISecurityAttributeV1.GetValueCount()
        {
            return ValueCount;
        }

        IntPtr ISecurityAttributeV1.GetValues()
        {
            return Values;
        }

        ClaimSecurityValueType ISecurityAttributeV1.GetValueType()
        {
            return ValueType;
        }
        //union {
        //PLONG64 pInt64;
        //PDWORD64 pUint64;
        //UNICODE_STRING* ppString;
        //PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
        //PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ClaimSecurityAttributeV1 : ISecurityAttributeV1
    {
        public IntPtr Name;
        public ClaimSecurityValueType ValueType;
        public ushort Reserved;
        public ClaimSecurityFlags Flags;
        public int ValueCount;
        public IntPtr Values;

        ClaimSecurityFlags ISecurityAttributeV1.GetFlags()
        {
            return Flags;
        }

        string ISecurityAttributeV1.GetName()
        {
            return Marshal.PtrToStringUni(Name);
        }

        int ISecurityAttributeV1.GetValueCount()
        {
            return ValueCount;
        }

        IntPtr ISecurityAttributeV1.GetValues()
        {
            return Values;
        }

        ClaimSecurityValueType ISecurityAttributeV1.GetValueType()
        {
            return ValueType;
        }
        //union {
        //PLONG64 pInt64;
        //PDWORD64 pUint64;
        //LPWSTR* ppString;
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

    public enum TokenSecurityAttributeOperation
    {
        None = 0,
        ReplaceAll = 1,
        Add = 2,
        Delete = 3,
        Replace = 4,
    }

    [StructLayout(LayoutKind.Sequential)]
    public class TokenSecurityAttributesAndOperationInformation
    {
        public IntPtr Attributes; // ClaimSecurityAttributesInformation
        public IntPtr Operations; // TokenSecurityAttributeOperation[]
    }

    [Flags]
    public enum PrivilegeAttributes : uint
    {
        [SDKName("DISABLED")]
        Disabled = 0,
        [SDKName("SE_PRIVILEGE_ENABLED_BY_DEFAULT")]
        EnabledByDefault = 1,
        [SDKName("SE_PRIVILEGE_ENABLED")]
        Enabled = 2,
        [SDKName("SE_PRIVILEGE_REMOVED")]
        Removed = 4,
        [SDKName("SE_PRIVILEGE_USED_FOR_ACCESS")]
        UsedForAccess = 0x80000000U,
    }

    [Flags]
    public enum GroupAttributes : uint
    {
        [SDKName("NONE")]
        None = 0,
        [SDKName("SE_GROUP_MANDATORY")]
        Mandatory = 0x00000001,
        [SDKName("SE_GROUP_ENABLED_BY_DEFAULT")]
        EnabledByDefault = 0x00000002,
        [SDKName("SE_GROUP_ENABLED")]
        Enabled = 0x00000004,
        [SDKName("SE_GROUP_OWNER")]
        Owner = 0x00000008,
        [SDKName("SE_GROUP_USE_FOR_DENY_ONLY")]
        UseForDenyOnly = 0x00000010,
        [SDKName("SE_GROUP_INTEGRITY")]
        Integrity = 0x00000020,
        [SDKName("SE_GROUP_INTEGRITY_ENABLED")]
        IntegrityEnabled = 0x00000040,
        [SDKName("SE_GROUP_LOGON_ID")]
        LogonId = 0xC0000000,
        [SDKName("SE_GROUP_RESOURCE")]
        Resource = 0x20000000,
    };

    [Flags]
    public enum FilterTokenFlags
    {
        [SDKName("NONE")]
        None = 0,
        [SDKName("DISABLE_MAX_PRIVILEGE")]
        DisableMaxPrivileges = 0x1,
        [SDKName("SANDBOX_INERT")]
        SandboxInert = 0x2,
        [SDKName("LUA_TOKEN")]
        LuaToken = 0x4,
        [SDKName("WRITE_RESTRICTED")]
        WriteRestricted = 0x8,
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Sid")]
    public struct TokenProcessTrustLevel
    {
        public int Size;
        public IntPtr Sid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenBnoIsolationInformation
    {
        public IntPtr IsolationPrefix;
        public bool IsolationEnabled;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Groups"), SDKName("TOKEN_GROUPS")]
    public class TokenGroups
    {
        public int GroupCount;
        public SidAndAttributes Groups;
    }

    [StructLayout(LayoutKind.Sequential), SDKName("TOKEN_STATISTICS")]
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
        public static extern NtStatus NtQueryInformationToken(
          SafeKernelObjectHandle TokenHandle,
          TokenInformationClass TokenInformationClass,
          SafeBuffer TokenInformation,
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

        [DllImport("ntdll.dll")]
        [Obsolete("Use version with optional parameters")]
        public static extern NtStatus NtCreateToken(
            out SafeKernelObjectHandle TokenHandle,
            TokenAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            TokenType TokenType,
            [In] ref Luid AuthenticationId,
            [In] LargeInteger ExpirationTime,
            [In] ref TokenUser TokenUser,
            [In] SafeTokenGroupsBuffer TokenGroups,
            [In] SafeTokenPrivilegesBuffer TokenPrivileges,
            [In] ref TokenOwner TokenOwner,
            [In] ref TokenPrimaryGroup TokenPrimaryGroup,
            [In] ref TokenDefaultDacl TokenDefaultDacl,
            [In] TokenSource TokenSource);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateToken(
            out SafeKernelObjectHandle TokenHandle,
            TokenAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            TokenType TokenType,
            [In] ref Luid AuthenticationId,
            [In] ref LargeIntegerStruct ExpirationTime,
            [In] ref TokenUser TokenUser,
            [In] SafeTokenGroupsBuffer TokenGroups,
            [In] SafeTokenPrivilegesBuffer TokenPrivileges,
            [In] OptionalTokenOwner TokenOwner,
            [In] ref TokenPrimaryGroup TokenPrimaryGroup,
            [In] OptionalTokenDefaultDacl TokenDefaultDacl,
            [In] TokenSource TokenSource);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateTokenEx(
            out SafeKernelObjectHandle TokenHandle,
            TokenAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            TokenType TokenType,
            [In] ref Luid AuthenticationId,
            [In] ref LargeIntegerStruct ExpirationTime,
            [In] ref TokenUser TokenUser,
            [In] SafeTokenGroupsBuffer TokenGroups,
            [In] SafeTokenPrivilegesBuffer TokenPrivileges,
            [In] SafeBuffer UserAttributes,
            [In] SafeBuffer DeviceAttributes,
            [In] SafeTokenGroupsBuffer DeviceGroups,
            [In] OptionalTokenMandatoryPolicy TokenMandatoryPolicy,
            [In] OptionalTokenOwner TokenOwner,
            [In] ref TokenPrimaryGroup TokenPrimaryGroup,
            [In] OptionalTokenDefaultDacl TokenDefaultDacl,
            [In] TokenSource TokenSource);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCompareTokens(
            SafeKernelObjectHandle FirstTokenHandle,
            SafeKernelObjectHandle SecondTokenHandle,
            out bool Equal
        );
    }
#pragma warning restore 1591
}
