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
using System.Threading;

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

        public TokenSource(string source)
        {
            _sourcename = Encoding.ASCII.GetBytes(source);
            if (_sourcename.Length != 8)
            {
                Array.Resize(ref _sourcename, 8);
            }
        }

        public Luid SourceIdentifier { get { return _sourceidentifier; } }

        public string SourceName { get { return Encoding.ASCII.GetString(_sourcename).TrimEnd('\0'); } }

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
        public LuidAndAttributes Privileges;
    }

    public enum ClaimSecurityValueType : ushort
    {
        None = 0,
        Int64 = 0x0001,
        UInt64 = 0x0002,
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
        Unknown40 = 0x0040,
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

        public override string ToString()
        {
            return $"Version {Version:X} - {Name}";
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
        public static extern NtStatus NtCompareTokens(
            SafeKernelObjectHandle FirstTokenHandle,
            SafeKernelObjectHandle SecondTokenHandle,
            out bool Equal
        );
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
            LuidAndAttributes priv = new LuidAndAttributes
            {
                Luid = luid,
                Attributes = (uint)attributes
            };
            _privs.Add(priv);
        }

        public void AddPrivilege(TokenPrivilegeValue name, PrivilegeAttributes attributes)
        {
            Luid luid = new Luid((uint)name, 0);
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
            return new SafeTokenPrivilegesBuffer(_privs.ToArray());
        }
    }

    public class SafeTokenPrivilegesBuffer : SafeStructureInOutBuffer<TokenPrivileges>
    {
        public SafeTokenPrivilegesBuffer(LuidAndAttributes[] privs)
            : base(new TokenPrivileges() { PrivilegeCount = privs.Length },
                  Marshal.SizeOf(typeof(LuidAndAttributes)) * privs.Length, true)
        {
            Data.WriteArray(0, privs, 0, privs.Length);
        }

        private SafeTokenPrivilegesBuffer() : base(IntPtr.Zero, 0, false)
        {
        }

        new public static SafeTokenPrivilegesBuffer Null { get { return new SafeTokenPrivilegesBuffer(); } }
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Groups")]
    public class TokenGroups
    {
        public int GroupCount;
        public SidAndAttributes Groups;
    }

    public class SafeTokenGroupsBuffer : SafeStructureInOutBuffer<TokenGroups>
    {
        SafeHandleList _sids;
        public SafeTokenGroupsBuffer(SidAndAttributes[] sid_and_attr, SafeHandleList sids)
            : base(new TokenGroups() { GroupCount = sids.Count },
                  Marshal.SizeOf(typeof(SidAndAttributes)) * sids.Count, true)
        {
            _sids = sids;
            Data.WriteArray(0, sid_and_attr, 0, sid_and_attr.Length);
        }

        private SafeTokenGroupsBuffer() : base(IntPtr.Zero, 0, false)
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

        public void AddGroup(UserGroup group)
        {
            AddGroup(group.Sid, group.Attributes);
        }

        public SafeTokenGroupsBuffer ToBuffer()
        {
            using (SafeHandleList sids = new SafeHandleList(_sid_and_attrs.Count))
            {
                SidAndAttributes[] result = new SidAndAttributes[_sid_and_attrs.Count];
                for (int i = 0; i < _sid_and_attrs.Count; ++i)
                {
                    sids.Add(_sid_and_attrs[i].sid.ToSafeBuffer());
                    result[i] = new SidAndAttributes
                    {
                        Sid = sids[i].DangerousGetHandle(),
                        Attributes = (GroupAttributes)_sid_and_attrs[i].attr
                    };
                }

                return new SafeTokenGroupsBuffer(result, sids.DangerousMove());
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
                case ClaimSecurityValueType.UInt64:
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

        public string Name { get; }
        public ClaimSecurityValueType ValueType { get; }
        public ClaimSecurityFlags Flags { get; }
        public IEnumerable<object> Values { get; }
        public int ValueCount { get; }

        internal ClaimSecurityAttribute(IntPtr ptr)
        {
            ClaimSecurityAttributeV1_NT v1 = (ClaimSecurityAttributeV1_NT)Marshal.PtrToStructure(ptr, typeof(ClaimSecurityAttributeV1_NT));
            Name = v1.Name.ToString();
            ValueType = v1.ValueType;
            Flags = v1.Flags;
            var values = ReadValues(v1.Values, v1.ValueCount, v1.ValueType).ToArray();
            Values = values;
            ValueCount = values.Length;
        }
    }

#pragma warning restore 1591

    /// <summary>
    /// Class to represent the state of a token privilege
    /// </summary>
    public class TokenPrivilege
    {
        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
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
            if (!LookupPrivilegeValue(".", name, out Luid luid))
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
                    return $"UnknownPrivilege-{luid}";
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
                string name = Name;
                LookupPrivilegeDisplayName(null, name, null, ref name_length, out int lang_id);
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
                ret = Sid.Name;
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
    [NtType("Token")]
    public sealed class NtToken : NtObjectWithDuplicateAndInfo<NtToken, TokenAccessRights, TokenInformationClass, TokenInformationClass>
    {
        #region Constructors

        internal NtToken(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(false)
            {
            }
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Duplicate token as specific type.
        /// </summary>
        /// <param name="type">The token type</param>
        /// <param name="level">The impersonation level us type is Impersonation</param>
        /// <param name="desired_access">Open with the desired access.</param>
        /// <param name="throw_on_error">If true then throw an exception on error.</param>
        /// <returns>The new token</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtResult<NtToken> DuplicateToken(TokenType type, SecurityImpersonationLevel level, TokenAccessRights desired_access, bool throw_on_error)
        {
            using (var token = Duplicate(TokenAccessRights.Duplicate, AttributeFlags.None, DuplicateObjectOptions.None, throw_on_error))
            {
                if (!token.IsSuccess)
                {
                    return token;
                }

                SecurityQualityOfService sqos = null;
                if (type == TokenType.Impersonation)
                {
                    sqos = new SecurityQualityOfService(level, SecurityContextTrackingMode.Static, false);
                }

                using (ObjectAttributes obja = new ObjectAttributes(null, AttributeFlags.None, SafeKernelObjectHandle.Null, sqos, null))
                {
                    return NtSystemCalls.NtDuplicateToken(token.Result.Handle,
                      desired_access, obja, false, type, out SafeKernelObjectHandle new_token).CreateResult(throw_on_error, () => new NtToken(new_token));
                }
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
            return DuplicateToken(type, level, desired_access, true).Result;
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
                    return new SidAndAttributes() { Sid = sid.DangerousGetHandle(), Attributes = GroupAttributes.Enabled };
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
                if (sids_to_disable != null && sids_to_disable.Any())
                {
                    sids_to_disable_buffer = BuildGroups(sids_to_disable, GroupAttributes.None);
                }
                if (restricted_sids != null && restricted_sids.Any())
                {
                    restricted_sids_buffer = BuildGroups(restricted_sids, GroupAttributes.None);
                }
                if (privileges_to_delete != null && privileges_to_delete.Any())
                {
                    TokenPrivilegesBuilder builder = new TokenPrivilegesBuilder();
                    foreach (Luid priv in privileges_to_delete)
                    {
                        builder.AddPrivilege(priv, PrivilegeAttributes.Disabled);
                    }
                    privileges_to_delete_buffer = builder.ToBuffer();
                }

                NtSystemCalls.NtFilterToken(Handle, flags, sids_to_disable_buffer, privileges_to_delete_buffer,
                    restricted_sids_buffer, out SafeKernelObjectHandle handle).ToNtException();
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
            Set(TokenInformationClass.TokenSessionId, session_id);
        }

        /// <summary>
        /// Set a token's default DACL
        /// </summary>
        /// <param name="dacl">The DACL to set.</param>
        public void SetDefaultDacl(Acl dacl)
        {
            using (var dacl_buf = dacl.ToSafeBuffer())
            {
                TokenDefaultDacl default_dacl = new TokenDefaultDacl
                {
                    DefaultDacl = dacl_buf.DangerousGetHandle()
                };
                Set(TokenInformationClass.TokenDefaultDacl, default_dacl);
            }
        }

        /// <summary>
        /// Set the origin logon session ID.
        /// </summary>
        /// <param name="origin">The origin logon session ID.</param>
        public void SetOrigin(Luid origin)
        {
            Set(TokenInformationClass.TokenOrigin, origin);
        }

        /// <summary>
        /// Set virtualization enabled
        /// </summary>
        /// <param name="enable">True to enable virtualization</param>
        public void SetVirtualizationEnabled(bool enable)
        {
            Set(TokenInformationClass.TokenVirtualizationEnabled, enable ? 1 : 0);
        }

        /// <summary>
        /// Set UI Access flag.
        /// </summary>
        /// <param name="enable">True to enable UI Access.</param>
        public void SetUIAccess(bool enable)
        {
            Set(TokenInformationClass.TokenUIAccess, enable ? 1 : 0);
        }

        /// <summary>
        /// Get the linked token 
        /// </summary>
        /// <returns>The linked token</returns>
        public NtToken GetLinkedToken()
        {
            IntPtr linked_token = Query<IntPtr>(TokenInformationClass.TokenLinkedToken);
            return new NtToken(new SafeKernelObjectHandle(linked_token, true));
        }

        /// <summary>
        /// Set the linked token.
        /// </summary>
        /// <param name="token">The token to set.</param>
        /// <remarks>Requires SeCreateTokenPrivilege.</remarks>
        public void SetLinkedToken(NtToken token)
        {
            Set(TokenInformationClass.TokenLinkedToken, token.Handle.DangerousGetHandle());
        }

        /// <summary>
        /// Impersonate the token.
        /// </summary>
        /// <returns>An impersonation context, dispose to revert to process token</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public ThreadImpersonationContext Impersonate()
        {
            return NtThread.Current.Impersonate(this);
        }

        /// <summary>
        /// Impersonate the token.
        /// </summary>
        /// <param name="impersonation_level">Impersonation level for token.</param>
        /// <returns>An impersonation context, dispose to revert to process token</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public ThreadImpersonationContext Impersonate(SecurityImpersonationLevel impersonation_level)
        {
            using (NtToken token = DuplicateToken(impersonation_level))
            {
                return NtThread.Current.Impersonate(token);
            }
        }

        /// <summary>
        /// Run a function under impersonation.
        /// </summary>
        /// <typeparam name="T">The return type.</typeparam>
        /// <param name="callback">The callback to run.</param>
        /// <returns>The return value from the callback.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public T RunUnderImpersonate<T>(Func<T> callback)
        {
            using (Impersonate())
            {
                return callback();
            }
        }

        /// <summary>
        /// Run an action under impersonation.
        /// </summary>
        /// <param name="callback">The callback to run.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void RunUnderImpersonate(Action callback)
        {
            using (Impersonate())
            {
                callback();
            }
        }

        /// <summary>
        /// Run a function under impersonation.
        /// </summary>
        /// <typeparam name="T">The return type.</typeparam>
        /// <param name="callback">The callback to run.</param>
        /// <param name="impersonation_level">Impersonation level for token.</param>
        /// <returns>The return value from the callback.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public T RunUnderImpersonate<T>(Func<T> callback, SecurityImpersonationLevel impersonation_level)
        {
            using (Impersonate(impersonation_level))
            {
                return callback();
            }
        }

        /// <summary>
        /// Run an action under impersonation.
        /// </summary>
        /// <param name="callback">The callback to run.</param>
        /// <param name="impersonation_level">Impersonation level for token.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void RunUnderImpersonate(Action callback, SecurityImpersonationLevel impersonation_level)
        {
            using (Impersonate(impersonation_level))
            {
                callback();
            }
        }

        /// <summary>
        /// Get a security attribute by name.
        /// </summary>
        /// <param name="name">The name of the security attribute, such as WIN://PKG</param>
        /// <param name="type">The expected type of the security attribute. If None return ignore type check.</param>
        /// <returns>The security attribute or null if not found.</returns>
        public ClaimSecurityAttribute GetSecurityAttributeByName(string name, ClaimSecurityValueType type)
        {
            IEnumerable<ClaimSecurityAttribute> ret = SecurityAttributes.Where(a => a.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (type != ClaimSecurityValueType.None)
            {
                ret = ret.Where(a => a.ValueType == type);
            }
            return ret.FirstOrDefault();
        }

        /// <summary>
        /// Get a security attribute by name.
        /// </summary>
        /// <param name="name">The name of the security attribute, such as WIN://PKG</param>
        /// <returns>The security attribute or null if not found.</returns>
        public ClaimSecurityAttribute GetSecurityAttributeByName(string name)
        {
            return GetSecurityAttributeByName(name, ClaimSecurityValueType.None);
        }

        private void SetIntegrityLevelSid(Sid sid)
        {
            using (SafeSidBufferHandle sid_buffer = sid.ToSafeBuffer())
            {
                TokenMandatoryLabel label = new TokenMandatoryLabel();
                label.Label.Sid = sid_buffer.DangerousGetHandle();
                Set(TokenInformationClass.TokenIntegrityLevel, label);
            }
        }

        /// <summary>
        /// Set the token's integrity level.
        /// </summary>
        /// <param name="level">The level to set.</param>
        public void SetIntegrityLevelRaw(int level)
        {
            SetIntegrityLevelSid(NtSecurity.GetIntegritySidRaw(level));
        }

        /// <summary>
        /// Set the token's integrity level.
        /// </summary>
        /// <param name="level">The level to set.</param>
        public void SetIntegrityLevel(TokenIntegrityLevel level)
        {
            SetIntegrityLevelSid(NtSecurity.GetIntegritySid(level));
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
        /// Compare two tokens.
        /// </summary>
        /// <param name="token">The other token to compare.</param>
        /// <returns>True if tokens are equal.</returns>
        public bool Compare(NtToken token)
        {
            NtSystemCalls.NtCompareTokens(Handle, token.Handle, out bool equal).ToNtException();
            return equal;
        }

        /// <summary>
        /// Get the App Policy for this token.
        /// </summary>
        /// <param name="policy_type">The type of app policy.</param>
        /// <returns>The policy value.</returns>
        public AppModelPolicy_PolicyValue GetAppModelPolicy(AppModelPolicy_Type policy_type)
        {
            OptionalInt64 attributes_present_obj = new OptionalInt64(0);
            PsPkgClaim pkg_claim = new PsPkgClaim();

            if (!NtRtl.RtlQueryPackageClaims(Handle, null, null, null, null, null,
                pkg_claim, attributes_present_obj).IsSuccess())
            {
                return AppModelPolicy_PolicyValue.None;
            }

            return GetAppPolicy(policy_type, attributes_present_obj.Value, pkg_claim.Flags);
        }

        /// <summary>
        /// Disable No Child process policy on the token.
        /// </summary>
        /// <remarks>Needs SeTcbPrivilege.</remarks>
        public void DisableNoChildProcess()
        {
            Set(TokenInformationClass.TokenChildProcessFlags, 0);
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(TokenInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryInformationToken(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public override NtStatus SetInformation(TokenInformationClass info_class, SafeBuffer buffer)
        {
            return NtSystemCalls.NtSetInformationToken(Handle, info_class, buffer, buffer.GetLength());
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Get token user
        /// </summary>
        public UserGroup User
        {
            get
            {
                if (_user == null)
                {
                    using (var user = QueryBuffer<TokenUser>(TokenInformationClass.TokenUser))
                    {
                        Interlocked.CompareExchange(ref _user, user.Result.User.ToUserGroup(), null);
                    }
                }
                return _user;
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
        /// Get/set the token's owner.
        /// </summary>
        public Sid Owner
        {
            get
            {
                using (var owner_buf = QueryBuffer<TokenOwner>(TokenInformationClass.TokenOwner))
                {
                    return new Sid(owner_buf.Result.Owner);
                }
            }

            set
            {
                using (var sid_buffer = value.ToSafeBuffer())
                {
                    Set(TokenInformationClass.TokenOwner, new TokenOwner() { Owner = sid_buffer.DangerousGetHandle() });
                }
            }
        }

        /// <summary>
        /// Get/set the token's primary group
        /// </summary>
        public Sid PrimaryGroup
        {
            get
            {
                using (var owner_buf = QueryBuffer<TokenPrimaryGroup>(TokenInformationClass.TokenPrimaryGroup))
                {
                    return new Sid(owner_buf.Result.PrimaryGroup);
                }
            }
            set
            {
                using (var sid_buffer = value.ToSafeBuffer())
                {
                    Set(TokenInformationClass.TokenPrimaryGroup, new TokenPrimaryGroup() { PrimaryGroup = sid_buffer.DangerousGetHandle() });
                }
            }
        }

        /// <summary>
        /// Get/set the token's default DACL
        /// </summary>
        public Acl DefaultDacl
        {
            get
            {
                using (var dacl_buf = QueryBuffer<TokenDefaultDacl>(TokenInformationClass.TokenDefaultDacl))
                {
                    return new Acl(dacl_buf.Result.DefaultDacl, false);
                }
            }
            set
            {
                SetDefaultDacl(value);
            }
        }

        /// <summary>
        /// Get the token's source
        /// </summary>
        public TokenSource Source
        {
            get
            {
                if (_source == null)
                {
                    using (var source_buf = QueryBuffer<TokenSource>(TokenInformationClass.TokenSource))
                    {
                        Interlocked.CompareExchange(ref _source, source_buf.Result, null);
                    }
                }
                return _source;
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
        /// Get/set token's session ID
        /// </summary>
        public int SessionId
        {
            get
            {
                return Query<int>(TokenInformationClass.TokenSessionId);
            }

            set
            {
                SetSessionId(value);
            }
        }

        /// <summary>
        /// Get whether token has sandbox inert flag set.
        /// </summary>
        public bool SandboxInert
        {
            get
            {
                return Query<int>(TokenInformationClass.TokenSandBoxInert) != 0;
            }
        }

        /// <summary>
        /// Get/set token's origin
        /// </summary>
        public Luid Origin
        {
            get
            {
                return Query<Luid>(TokenInformationClass.TokenOrigin);
            }

            set
            {
                SetOrigin(value);
            }
        }

        /// <summary>
        /// Get token's elevation type
        /// </summary>
        public TokenElevationType ElevationType
        {
            get
            {
                return (TokenElevationType)Query<int>(TokenInformationClass.TokenElevationType);
            }
        }

        /// <summary>
        /// Get whether token is elevated
        /// </summary>
        public bool Elevated
        {
            get
            {
                return Query<int>(TokenInformationClass.TokenElevation) != 0;
            }
        }

        /// <summary>
        /// Get whether token has restrictions
        /// </summary>
        public bool HasRestrictions
        {
            get
            {
                return Query<int>(TokenInformationClass.TokenHasRestrictions) != 0;
            }
        }

        /// <summary>
        /// Get/set token UI access flag
        /// </summary>
        public bool UIAccess
        {
            get
            {
                return Query<int>(TokenInformationClass.TokenUIAccess) != 0;
            }
            set
            {
                SetUIAccess(value);
            }
        }

        /// <summary>
        /// Get or set whether virtualization is allowed
        /// </summary>
        public bool VirtualizationAllowed
        {
            get
            {
                return Query<int>(TokenInformationClass.TokenVirtualizationAllowed) != 0;
            }
            set
            {
                Set(TokenInformationClass.TokenVirtualizationAllowed, value ? 1 : 0);
            }
        }

        /// <summary>
        /// Get/set whether virtualization is enabled
        /// </summary>
        public bool VirtualizationEnabled
        {
            get
            {
                return Query<int>(TokenInformationClass.TokenVirtualizationEnabled) != 0;
            }
            set
            {
                SetVirtualizationEnabled(value);
            }
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
        /// Get or set the token mandatory policy
        /// </summary>
        public TokenMandatoryPolicy MandatoryPolicy
        {
            get
            {
                return (TokenMandatoryPolicy)Query<int>(TokenInformationClass.TokenMandatoryPolicy);
            }
            set
            {
                Set(TokenInformationClass.TokenMandatoryPolicy, (int)value);
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
        /// Get token's integrity level sid
        /// </summary>
        public UserGroup IntegrityLevelSid
        {
            get
            {
                using (var label = QueryBuffer<TokenMandatoryLabel>(TokenInformationClass.TokenIntegrityLevel))
                {
                    return label.Result.Label.ToUserGroup();
                }
            }

            set
            {
                SetIntegrityLevelSid(value.Sid);
            }
        }

        /// <summary>
        /// Get token's App Container number.
        /// </summary>
        public int AppContainerNumber
        {
            get
            {
                return Query<int>(TokenInformationClass.TokenAppContainerNumber);
            }
        }

        /// <summary>
        /// Get or set token's integrity level.
        /// </summary>
        public TokenIntegrityLevel IntegrityLevel
        {
            get
            {
                UserGroup group = IntegrityLevelSid;
                string[] parts = group.Sid.ToString().Split('-');
                return (TokenIntegrityLevel)int.Parse(parts[parts.Length - 1]);
            }

            set
            {
                SetIntegrityLevel(value);
            }
        }

        /// <summary>
        /// Get token's security attributes
        /// </summary>
        public ClaimSecurityAttribute[] SecurityAttributes
        {
            get
            {
                using (var buf = QueryBuffer<ClaimSecurityAttributesInformation>(TokenInformationClass.TokenSecurityAttributes))
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

        /// <summary>
        /// Get whether a token is an AppContainer token
        /// </summary>
        public bool AppContainer
        {
            get
            {
                if (NtObjectUtils.IsWindows7OrLess)
                {
                    return false;
                }

                using (var appcontainer
                    = QueryBuffer<uint>(TokenInformationClass.TokenIsAppContainer))
                {
                    return appcontainer.Result != 0;
                }
            }
        }

        /// <summary>
        /// Get whether the token is configured for low privilege.
        /// </summary>
        public bool LowPrivilegeAppContainer
        {
            get
            {
                if (!AppContainer)
                {
                    return false;
                }

                ClaimSecurityAttribute attribute = GetSecurityAttributeByName("WIN://NOALLAPPPKG", ClaimSecurityValueType.UInt64);
                if (attribute != null)
                {
                    return (ulong)attribute.Values.First() != 0;
                }

                return false;
            }
        }

        /// <summary>
        /// Get token's AppContainer sid
        /// </summary>
        public Sid AppContainerSid
        {
            get
            {
                if (!AppContainer)
                {
                    return null;
                }

                if (_app_container_sid == null)
                {
                    using (var acsid = QueryBuffer<TokenAppContainerInformation>(TokenInformationClass.TokenAppContainerSid))
                    {
                        Interlocked.CompareExchange(ref _app_container_sid, new Sid(acsid.Result.TokenAppContainer), null);
                    }
                }

                return _app_container_sid;
            }
        }

        /// <summary>
        /// Get token's AppContainer package name (if available). 
        /// Returns an empty string if not an AppContainer.
        /// </summary>
        public string PackageName
        {
            get
            {
                if (!AppContainer)
                {
                    return String.Empty;
                }

                ClaimSecurityAttribute attribute = GetSecurityAttributeByName("WIN://SYSAPPID", ClaimSecurityValueType.String);
                if (attribute == null)
                {
                    return String.Empty;
                }

                return (string)attribute.Values.First();
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
                using (var buffer = QueryBuffer<TokenPrivileges>(TokenInformationClass.TokenPrivileges))
                {
                    int count = buffer.Result.PrivilegeCount;
                    LuidAndAttributes[] attrs = new LuidAndAttributes[count];
                    buffer.Data.ReadArray(0, attrs, 0, count);
                    return attrs.Select(a => new TokenPrivilege(a.Luid, (PrivilegeAttributes)a.Attributes)).ToArray();
                }
            }
        }

        /// <summary>
        /// Get full path to token
        /// </summary>
        public override string FullPath
        {
            get
            {
                try
                {
                    return $"{User.Sid.Name} - {AuthenticationId}";
                }
                catch
                {
                    return string.Empty;
                }
            }
        }

        /// <summary>
        /// Get the token's trust level. Will be null if no trust level present.
        /// </summary>
        public Sid TrustLevel
        {
            get
            {
                try
                {
                    using (var buffer = QueryBuffer<TokenProcessTrustLevel>(TokenInformationClass.TokenProcessTrustLevel))
                    {
                        if (buffer.Length > IntPtr.Size)
                        {
                            return new Sid(buffer.Data.DangerousGetHandle());
                        }
                    }
                }
                catch (NtException)
                {
                }

                return null;
            }
        }

        /// <summary>
        /// Returns true if this is a pseudo token.
        /// </summary>
        public bool IsPseudoToken { get; private set; }

        /// <summary>
        /// Get whether this token is a sandboxed token.
        /// </summary>
        public bool IsSandbox
        {
            get
            {
                try
                {
                    if (TokenType == TokenType.Primary)
                    {
                        return DuplicateToken(SecurityImpersonationLevel.Identification)
                            .RunAndDispose(token => token.IsSandbox);
                    }

                    if (NtRtl.RtlCheckSandboxedToken(Handle, out bool is_sandboxed).IsSuccess())
                    {
                        return is_sandboxed;
                    }
                }
                catch
                {
                }

                // Default to not using the RTL version.
                return AppContainer || Restricted || IntegrityLevel < TokenIntegrityLevel.Medium;
            }
        }

        /// <summary>
        /// Query the token's full package name.
        /// </summary>
        public string PackageFullName
        {
            get
            {
                byte[] package_name = new byte[1024];
                OptionalLength package_length = new OptionalLength(package_name.Length);
                if (NtRtl.RtlQueryPackageClaims(Handle, package_name, package_length, null, null, null, null, null).IsSuccess())
                {
                    return Encoding.Unicode.GetString(package_name, 0, package_length.Length.ToInt32()).TrimEnd('\0');
                }
                return string.Empty;
            }
        }

        /// <summary>
        /// Query the token's appid.
        /// </summary>
        public string AppId
        {
            get
            {
                byte[] app_id = new byte[1024];
                OptionalLength app_id_length = new OptionalLength(app_id.Length);
                if (NtRtl.RtlQueryPackageClaims(Handle, null, null, app_id, app_id_length, null, null, null).IsSuccess())
                {
                    return Encoding.Unicode.GetString(app_id, 0, app_id_length.Length.ToInt32()).TrimEnd('\0');
                }
                return string.Empty;
            }
        }

        /// <summary>
        /// Get the list of policies for this App.
        /// </summary>
        public IEnumerable<AppModelPolicy_PolicyValue> AppModelPolicies
        {
            get
            {
                OptionalInt64 attributes_present_obj = new OptionalInt64(0);
                PsPkgClaim pkg_claim = new PsPkgClaim();

                if (!NtRtl.RtlQueryPackageClaims(Handle, null, null, null, null, null,
                    pkg_claim, attributes_present_obj).IsSuccess())
                {
                    return Enumerable.Empty<AppModelPolicy_PolicyValue>();
                }

                return Enum.GetValues(typeof(AppModelPolicy_Type)).Cast<AppModelPolicy_Type>().Select(p => GetAppPolicy(p, attributes_present_obj.Value, pkg_claim.Flags));
            }
        }

        /// <summary>
        /// Get the BaseNamedObjects isolation prefix if enabled.
        /// </summary>
        public string BnoIsolationPrefix
        {
            get
            {
                using (var buffer = QueryBuffer<TokenBnoIsolationInformation>(TokenInformationClass.TokenBnoIsolation))
                {
                    var result = buffer.Result;
                    if (!result.IsolationEnabled || result.IsolationPrefix == IntPtr.Zero)
                        return string.Empty;

                    return Marshal.PtrToStringUni(result.IsolationPrefix);
                }
            }
        }

        /// <summary>
        /// Get or set the token audit policy.
        /// </summary>
        /// <remarks>Needs SeSecurityPrivilege to query and SeTcbPrivilege to set.</remarks>
        public byte[] AuditPolicy
        {
            get
            {
                return Query<TokenAuditPolicy>(TokenInformationClass.TokenAuditPolicy).PerUserPolicy;
            }

            set
            {
                byte[] audit_policy = new byte[30];
                Array.Copy(value, audit_policy, Math.Min(value.Length, audit_policy.Length));
                Set(TokenInformationClass.TokenAuditPolicy, new TokenAuditPolicy() { PerUserPolicy = audit_policy });
            }
        }

        /// <summary>
        /// Get or set if token is in a private namespace.
        /// </summary>
        public bool PrivateNamespace
        {
            get => Query<int>(TokenInformationClass.TokenPrivateNameSpace) != 0;
            set => Set(TokenInformationClass.TokenPrivateNameSpace, value ? 1 : 0);
        }

        /// <summary>
        /// Get if the token is restricted.
        /// </summary>
        public bool IsRestricted => Query<int>(TokenInformationClass.TokenIsRestricted) != 0;

        #endregion

        #region Static Methods

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
        /// Enable a privilege of the effective token.
        /// </summary>
        /// <param name="privilege">The privilege to enable.</param>
        /// <returns>True if set the privilege.</returns>
        public static bool EnableEffectivePrivilege(TokenPrivilegeValue privilege)
        {
            try
            {
                using (NtToken token = NtToken.OpenEffectiveToken())
                {
                    return token.SetPrivilege(privilege, PrivilegeAttributes.Enabled);
                }
            }
            catch (NtException)
            {
                return false;
            }
        }

        /// <summary>
        /// Open the process token of another process
        /// </summary>
        /// <param name="process">The process to open the token for</param>
        /// <param name="desired_access">The desired access for the token</param>
        /// <param name="throw_on_error">If true then throw an exception on error.</param>
        /// <returns>The opened token</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtResult<NtToken> OpenProcessToken(NtProcess process, TokenAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenProcessTokenEx(process.Handle,
              desired_access, AttributeFlags.None, out SafeKernelObjectHandle new_token)
              .CreateResult(throw_on_error, () => new NtToken(new_token));
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
            var ret = OpenProcessToken(process, desired_access, true).Result;
            if (duplicate)
            {
                using (ret)
                {
                    return ret.DuplicateToken();
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
            using (NtProcess process = NtProcess.Open(pid, ProcessAccessRights.QueryLimitedInformation))
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
        /// <param name="desired_access">The desired access for the token</param>
        /// <param name="throw_on_error">If true then throw an exception on error.</param>
        /// <returns>The opened token result</returns>
        /// <exception cref="NtException">Thrown if cannot open token</exception>
        public static NtResult<NtToken> OpenThreadToken(NtThread thread, bool open_as_self, TokenAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenThreadTokenEx(thread.Handle,
              desired_access, open_as_self, AttributeFlags.None, out SafeKernelObjectHandle new_token).CreateResult(throw_on_error, () => new NtToken(new_token));
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
            var result = OpenThreadToken(thread, open_as_self, desired_access, false);
            if (result.Status == NtStatus.STATUS_NO_TOKEN)
                return null;
            NtToken ret = result.GetResultOrThrow();
            if (duplicate)
            {
                using (ret)
                {
                    return ret.DuplicateToken();
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
        /// Create a token. Needs SeCreateTokenPrivilege.
        /// </summary>
        /// <param name="desired_access">The desired access for the token.</param>
        /// <param name="object_attributes">Object attributes, used to pass SecurityDescriptor or SQOS for impersonation token.</param>
        /// <param name="token_type">The type of token.</param>
        /// <param name="authentication_id">The authentication ID for the token.</param>
        /// <param name="expiration_time">The expiration time for the token.</param>
        /// <param name="token_user">The user for the token.</param>
        /// <param name="token_groups">The groups for the token.</param>
        /// <param name="token_privileges">The privileges for the token.</param>
        /// <param name="token_owner">The owner of the token.</param>
        /// <param name="token_primary_group">The primary group for the token.</param>
        /// <param name="token_default_dacl">The default dacl for the token.</param>
        /// <param name="token_source">The source for the token.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The token object.</returns>
        public static NtResult<NtToken> Create(
                    TokenAccessRights desired_access,
                    ObjectAttributes object_attributes,
                    TokenType token_type,
                    Luid authentication_id,
                    long expiration_time,
                    UserGroup token_user,
                    IEnumerable<UserGroup> token_groups,
                    IEnumerable<TokenPrivilege> token_privileges,
                    Sid token_owner,
                    Sid token_primary_group,
                    Acl token_default_dacl,
                    string token_source,
                    bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                TokenUser user = new TokenUser();
                SafeSidBufferHandle user_buffer = list.AddResource(token_user.Sid.ToSafeBuffer());
                user.User.Sid = user_buffer.DangerousGetHandle();
                user.User.Attributes = token_user.Attributes;
                var groups = list.AddResource(BuildGroups(token_groups));
                TokenPrivilegesBuilder builder = new TokenPrivilegesBuilder();
                builder.AddPrivilegeRange(token_privileges);
                var privileges = list.AddResource(builder.ToBuffer());

                TokenPrimaryGroup primary_group = new TokenPrimaryGroup
                {
                    PrimaryGroup = list.AddResource(token_primary_group.ToSafeBuffer()).DangerousGetHandle()
                };

                TokenOwner owner = new TokenOwner()
                {
                    Owner = list.AddResource(token_owner.ToSafeBuffer()).DangerousGetHandle()
                };

                TokenDefaultDacl dacl = new TokenDefaultDacl()
                {
                    DefaultDacl = list.AddResource(token_default_dacl.ToSafeBuffer()).DangerousGetHandle()
                };

                return NtSystemCalls.NtCreateToken(out SafeKernelObjectHandle handle, desired_access, object_attributes,
                    token_type, ref authentication_id, new LargeInteger(expiration_time),
                    ref user, groups, privileges, ref owner, ref primary_group, ref dacl,
                    new TokenSource(token_source)).CreateResult(throw_on_error, () => new NtToken(handle));
            }
        }

        /// <summary>
        /// Create a token. Needs SeCreateTokenPrivilege.
        /// </summary>
        /// <param name="desired_access">The desired access for the token.</param>
        /// <param name="object_attributes">Object attributes, used to pass SecurityDescriptor or SQOS for impersonation token.</param>
        /// <param name="token_type">The type of token.</param>
        /// <param name="authentication_id">The authentication ID for the token.</param>
        /// <param name="expiration_time">The expiration time for the token.</param>
        /// <param name="token_user">The user for the token.</param>
        /// <param name="token_groups">The groups for the token.</param>
        /// <param name="token_privileges">The privileges for the token.</param>
        /// <param name="token_owner">The owner of the token.</param>
        /// <param name="token_primary_group">The primary group for the token.</param>
        /// <param name="token_default_dacl">The default dacl for the token.</param>
        /// <param name="token_source">The source for the token.</param>
        /// <returns>The token object.</returns>
        public static NtToken Create(
                    TokenAccessRights desired_access,
                    ObjectAttributes object_attributes,
                    TokenType token_type,
                    Luid authentication_id,
                    long expiration_time,
                    UserGroup token_user,
                    IEnumerable<UserGroup> token_groups,
                    IEnumerable<TokenPrivilege> token_privileges,
                    Sid token_owner,
                    Sid token_primary_group,
                    Acl token_default_dacl,
                    string token_source)
        {
            return Create(desired_access, object_attributes, token_type, authentication_id, expiration_time, token_user,
                token_groups, token_privileges, token_owner, token_primary_group, token_default_dacl, token_source, true).Result;
        }

        /// <summary>
        /// Create a token. Needs SeCreateTokenPrivilege.
        /// </summary>
        /// <param name="token_user">The user for the token.</param>
        /// <param name="token_groups">The groups for the token.</param>
        /// <param name="token_privileges">The privileges for the token.</param>
        /// <returns>The token object.</returns>
        public static NtToken Create(Sid token_user,
                    IEnumerable<Sid> token_groups,
                    IEnumerable<TokenPrivilegeValue> token_privileges)
        {
            Acl default_dacl = new Acl();
            default_dacl.AddAccessAllowedAce(GenericAccessRights.GenericAll, AceFlags.None, token_user);
            return Create(TokenAccessRights.GenericAll, null, TokenType.Primary, new Luid(999, 0),
                DateTime.Now.AddYears(10).ToFileTimeUtc(), new UserGroup(token_user, GroupAttributes.Enabled | GroupAttributes.EnabledByDefault | GroupAttributes.Owner),
                token_groups.Select(s => new UserGroup(s, GroupAttributes.Enabled | GroupAttributes.EnabledByDefault)),
                token_privileges.Select(p => new TokenPrivilege(p, PrivilegeAttributes.Enabled | PrivilegeAttributes.EnabledByDefault)),
                token_user, token_user, default_dacl, "NT.NET");
        }

        /// <summary>
        /// Create a token. Needs SeCreateTokenPrivilege.
        /// </summary>
        /// <param name="token_user">The user for the token.</param>
        /// <returns>The token object.</returns>
        public static NtToken Create(Sid token_user)
        {
            return Create(token_user, new Sid[] { new Sid("WD") }, new TokenPrivilegeValue[] { TokenPrivilegeValue.SeDebugPrivilege });
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

        #endregion

        #region Static Properties

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
        /// Get authentication ID for ANONYMOUS
        /// </summary>
        public static Luid AnonymousAuthId { get { return new Luid(0x3e6, 0); } }

        /// <summary>
        /// Get a pseudo handle to the primary token.
        /// </summary>
        /// <remarks>Only useful for querying information.</remarks>
        public static NtToken PseudoPrimaryToken { get { return GetPseudoToken(-4); } }
        /// <summary>
        /// Get a pseudo handle to the impersonation token.
        /// </summary>
        /// <remarks>Only useful for querying information.</remarks>
        public static NtToken PseudoImpersonationToken { get { return GetPseudoToken(-5); } }
        /// <summary>
        /// Get a pseudo handle to the effective token.
        /// </summary>
        /// <remarks>Only useful for querying information.</remarks>
        public static NtToken PseudoEffectiveToken { get { return GetPseudoToken(-6); } }

        #endregion

        #region Private Members

        private UserGroup _user;
        private TokenStatistics _token_stats;
        private TokenSource _source;
        private Sid _app_container_sid;

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

        private static SafeTokenGroupsBuffer BuildGroups(IEnumerable<Sid> sids, GroupAttributes attributes)
        {
            return BuildGroups(sids.Select(s => new UserGroup(s, attributes)));
        }

        private static SafeTokenGroupsBuffer BuildGroups(IEnumerable<UserGroup> groups)
        {
            TokenGroupsBuilder builder = new TokenGroupsBuilder();
            foreach (UserGroup group in groups)
            {
                builder.AddGroup(group);
            }
            return builder.ToBuffer();
        }

        private UserGroup[] QueryGroups(TokenInformationClass info_class)
        {
            using (var groups = QueryBuffer<TokenGroups>(info_class))
            {
                TokenGroups result = groups.Result;
                SidAndAttributes[] sids = new SidAndAttributes[result.GroupCount];
                groups.Data.ReadArray(0, sids, 0, result.GroupCount);
                return sids.Select(s => s.ToUserGroup()).ToArray();
            }
        }

        private TokenStatistics GetTokenStats()
        {
            if (_token_stats == null)
            {
                using (var stats = QueryBuffer<TokenStatistics>(TokenInformationClass.TokenStatistics))
                {
                    Interlocked.CompareExchange(ref _token_stats, stats.Result, null);
                }
            }
            return _token_stats;
        }

        private static NtToken GetPseudoToken(int handle)
        {
            return new NtToken(new SafeKernelObjectHandle(new IntPtr(handle), false))
            {
                IsPseudoToken = true
            };
        }

        private static readonly AppModelPolicy_PolicyValue[] _policy_lookup_table = {
            AppModelPolicy_PolicyValue.LifecycleManager_ManagedByPLM, AppModelPolicy_PolicyValue.LifecycleManager_Unmanaged, AppModelPolicy_PolicyValue.LifecycleManager_Unmanaged, AppModelPolicy_PolicyValue.LifecycleManager_ManagedByPLM, AppModelPolicy_PolicyValue.LifecycleManager_ManagedByEM, AppModelPolicy_PolicyValue.LifecycleManager_ManagedByEM, AppModelPolicy_PolicyValue.LifecycleManager_Unmanaged, AppModelPolicy_PolicyValue.LifecycleManager_Unmanaged,
            AppModelPolicy_PolicyValue.AppDataAccess_Allowed, AppModelPolicy_PolicyValue.AppDataAccess_Allowed, AppModelPolicy_PolicyValue.AppDataAccess_Denied, AppModelPolicy_PolicyValue.AppDataAccess_Allowed, AppModelPolicy_PolicyValue.AppDataAccess_Denied, AppModelPolicy_PolicyValue.AppDataAccess_Denied, AppModelPolicy_PolicyValue.AppDataAccess_Denied, AppModelPolicy_PolicyValue.AppDataAccess_Denied,
            AppModelPolicy_PolicyValue.WindowingModel_CoreWindow, AppModelPolicy_PolicyValue.WindowingModel_Hwnd, AppModelPolicy_PolicyValue.WindowingModel_Hwnd, AppModelPolicy_PolicyValue.WindowingModel_CoreWindow, AppModelPolicy_PolicyValue.WindowingModel_LegacyPhone, AppModelPolicy_PolicyValue.WindowingModel_LegacyPhone, AppModelPolicy_PolicyValue.WindowingModel_None, AppModelPolicy_PolicyValue.WindowingModel_Hwnd,
            AppModelPolicy_PolicyValue.DllSearchOrder_PackageGraphBased, AppModelPolicy_PolicyValue.DllSearchOrder_PackageGraphBased, AppModelPolicy_PolicyValue.DllSearchOrder_Traditional, AppModelPolicy_PolicyValue.DllSearchOrder_PackageGraphBased, AppModelPolicy_PolicyValue.DllSearchOrder_Traditional, AppModelPolicy_PolicyValue.DllSearchOrder_Traditional, AppModelPolicy_PolicyValue.DllSearchOrder_Traditional, AppModelPolicy_PolicyValue.DllSearchOrder_Traditional,
            AppModelPolicy_PolicyValue.Fusion_Limited, AppModelPolicy_PolicyValue.Fusion_Full, AppModelPolicy_PolicyValue.Fusion_Full, AppModelPolicy_PolicyValue.Fusion_Limited, AppModelPolicy_PolicyValue.Fusion_Full, AppModelPolicy_PolicyValue.Fusion_Full, AppModelPolicy_PolicyValue.Fusion_Full, AppModelPolicy_PolicyValue.Fusion_Full,
            AppModelPolicy_PolicyValue.NonWindowsCodeLoading_Denied, AppModelPolicy_PolicyValue.NonWindowsCodeLoading_Allowed, AppModelPolicy_PolicyValue.NonWindowsCodeLoading_Allowed, AppModelPolicy_PolicyValue.NonWindowsCodeLoading_Denied, AppModelPolicy_PolicyValue.NonWindowsCodeLoading_Denied, AppModelPolicy_PolicyValue.NonWindowsCodeLoading_Denied, AppModelPolicy_PolicyValue.NonWindowsCodeLoading_Allowed, AppModelPolicy_PolicyValue.NonWindowsCodeLoading_Allowed,
            AppModelPolicy_PolicyValue.ProcessEnd_TerminateProcess, AppModelPolicy_PolicyValue.ProcessEnd_ExitProcess, AppModelPolicy_PolicyValue.ProcessEnd_ExitProcess, AppModelPolicy_PolicyValue.ProcessEnd_ExitProcess, AppModelPolicy_PolicyValue.ProcessEnd_ExitProcess, AppModelPolicy_PolicyValue.ProcessEnd_ExitProcess, AppModelPolicy_PolicyValue.ProcessEnd_ExitProcess, AppModelPolicy_PolicyValue.ProcessEnd_ExitProcess,
            AppModelPolicy_PolicyValue.BeginThreadInit_RoInitialize, AppModelPolicy_PolicyValue.BeginThreadInit_None, AppModelPolicy_PolicyValue.BeginThreadInit_None, AppModelPolicy_PolicyValue.BeginThreadInit_None, AppModelPolicy_PolicyValue.BeginThreadInit_None, AppModelPolicy_PolicyValue.BeginThreadInit_None, AppModelPolicy_PolicyValue.BeginThreadInit_None, AppModelPolicy_PolicyValue.BeginThreadInit_None,
            AppModelPolicy_PolicyValue.DeveloperInformation_None, AppModelPolicy_PolicyValue.DeveloperInformation_UI, AppModelPolicy_PolicyValue.DeveloperInformation_UI, AppModelPolicy_PolicyValue.DeveloperInformation_None, AppModelPolicy_PolicyValue.DeveloperInformation_None, AppModelPolicy_PolicyValue.DeveloperInformation_None, AppModelPolicy_PolicyValue.DeveloperInformation_None, AppModelPolicy_PolicyValue.DeveloperInformation_UI,
            AppModelPolicy_PolicyValue.CreateFileAccess_Limited, AppModelPolicy_PolicyValue.CreateFileAccess_Full, AppModelPolicy_PolicyValue.CreateFileAccess_Full, AppModelPolicy_PolicyValue.CreateFileAccess_Limited, AppModelPolicy_PolicyValue.CreateFileAccess_Limited, AppModelPolicy_PolicyValue.CreateFileAccess_Full, AppModelPolicy_PolicyValue.CreateFileAccess_Full, AppModelPolicy_PolicyValue.CreateFileAccess_Full,
            AppModelPolicy_PolicyValue.ImplicitPackageBreakaway_Denied, AppModelPolicy_PolicyValue.ImplicitPackageBreakaway_Allowed, AppModelPolicy_PolicyValue.ImplicitPackageBreakaway_Denied, AppModelPolicy_PolicyValue.ImplicitPackageBreakaway_Denied, AppModelPolicy_PolicyValue.ImplicitPackageBreakaway_Denied, AppModelPolicy_PolicyValue.ImplicitPackageBreakaway_Denied, AppModelPolicy_PolicyValue.ImplicitPackageBreakaway_Denied, AppModelPolicy_PolicyValue.ImplicitPackageBreakaway_Denied,
            AppModelPolicy_PolicyValue.ProcessActivationShim_None, AppModelPolicy_PolicyValue.ProcessActivationShim_PackagedCWALauncher, AppModelPolicy_PolicyValue.ProcessActivationShim_None, AppModelPolicy_PolicyValue.ProcessActivationShim_None, AppModelPolicy_PolicyValue.ProcessActivationShim_None, AppModelPolicy_PolicyValue.ProcessActivationShim_None, AppModelPolicy_PolicyValue.ProcessActivationShim_None, AppModelPolicy_PolicyValue.ProcessActivationShim_None,
            AppModelPolicy_PolicyValue.AppKnownToStateRepository_Known, AppModelPolicy_PolicyValue.AppKnownToStateRepository_Known, AppModelPolicy_PolicyValue.AppKnownToStateRepository_Unknown, AppModelPolicy_PolicyValue.AppKnownToStateRepository_Known, AppModelPolicy_PolicyValue.AppKnownToStateRepository_Known, AppModelPolicy_PolicyValue.AppKnownToStateRepository_Known, AppModelPolicy_PolicyValue.AppKnownToStateRepository_Unknown, AppModelPolicy_PolicyValue.AppKnownToStateRepository_Unknown,
            AppModelPolicy_PolicyValue.AudioManagement_ManagedByPBM, AppModelPolicy_PolicyValue.AudioManagement_Unmanaged, AppModelPolicy_PolicyValue.AudioManagement_Unmanaged, AppModelPolicy_PolicyValue.AudioManagement_ManagedByPBM, AppModelPolicy_PolicyValue.AudioManagement_ManagedByPBM, AppModelPolicy_PolicyValue.AudioManagement_ManagedByPBM, AppModelPolicy_PolicyValue.AudioManagement_Unmanaged, AppModelPolicy_PolicyValue.AudioManagement_Unmanaged,
            AppModelPolicy_PolicyValue.PackageMayContainPublicComRegistrations_No, AppModelPolicy_PolicyValue.PackageMayContainPublicComRegistrations_Yes, AppModelPolicy_PolicyValue.PackageMayContainPublicComRegistrations_No, AppModelPolicy_PolicyValue.PackageMayContainPublicComRegistrations_No, AppModelPolicy_PolicyValue.PackageMayContainPublicComRegistrations_No, AppModelPolicy_PolicyValue.PackageMayContainPublicComRegistrations_No, AppModelPolicy_PolicyValue.PackageMayContainPublicComRegistrations_No, AppModelPolicy_PolicyValue.PackageMayContainPublicComRegistrations_No,
            AppModelPolicy_PolicyValue.PackageMayContainPrivateComRegistrations_None, AppModelPolicy_PolicyValue.PackageMayContainPrivateComRegistrations_PrivateHive, AppModelPolicy_PolicyValue.PackageMayContainPrivateComRegistrations_None, AppModelPolicy_PolicyValue.PackageMayContainPrivateComRegistrations_None, AppModelPolicy_PolicyValue.PackageMayContainPrivateComRegistrations_None, AppModelPolicy_PolicyValue.PackageMayContainPrivateComRegistrations_None, AppModelPolicy_PolicyValue.PackageMayContainPrivateComRegistrations_None, AppModelPolicy_PolicyValue.PackageMayContainPrivateComRegistrations_None,
            AppModelPolicy_PolicyValue.LaunchCreateProcessExtensions_RegisterWithPsm, AppModelPolicy_PolicyValue.LaunchCreateProcessExtensions_RegisterWithDesktopAppX, AppModelPolicy_PolicyValue.LaunchCreateProcessExtensions_None, AppModelPolicy_PolicyValue.LaunchCreateProcessExtensions_RegisterWithPsm, AppModelPolicy_PolicyValue.LaunchCreateProcessExtensions_RegisterWithPsm, AppModelPolicy_PolicyValue.LaunchCreateProcessExtensions_RegisterWithPsm, AppModelPolicy_PolicyValue.LaunchCreateProcessExtensions_None, AppModelPolicy_PolicyValue.LaunchCreateProcessExtensions_None,
            AppModelPolicy_PolicyValue.ClrCompat_Universal, AppModelPolicy_PolicyValue.ClrCompat_PackagedDesktop, AppModelPolicy_PolicyValue.ClrCompat_ClassicDesktop, AppModelPolicy_PolicyValue.ClrCompat_Others, AppModelPolicy_PolicyValue.ClrCompat_Others, AppModelPolicy_PolicyValue.ClrCompat_Others, AppModelPolicy_PolicyValue.ClrCompat_Others, AppModelPolicy_PolicyValue.ClrCompat_ClassicDesktop,
            AppModelPolicy_PolicyValue.LoaderIgnoreAlteredSearchForRelativePath_False, AppModelPolicy_PolicyValue.LoaderIgnoreAlteredSearchForRelativePath_True, AppModelPolicy_PolicyValue.LoaderIgnoreAlteredSearchForRelativePath_False, AppModelPolicy_PolicyValue.LoaderIgnoreAlteredSearchForRelativePath_False, AppModelPolicy_PolicyValue.LoaderIgnoreAlteredSearchForRelativePath_False, AppModelPolicy_PolicyValue.LoaderIgnoreAlteredSearchForRelativePath_False, AppModelPolicy_PolicyValue.LoaderIgnoreAlteredSearchForRelativePath_False, AppModelPolicy_PolicyValue.LoaderIgnoreAlteredSearchForRelativePath_False,
            AppModelPolicy_PolicyValue.ImplicitlyActivateClassicAAAServersAsIU_No, AppModelPolicy_PolicyValue.ImplicitlyActivateClassicAAAServersAsIU_Yes, AppModelPolicy_PolicyValue.ImplicitlyActivateClassicAAAServersAsIU_No, AppModelPolicy_PolicyValue.ImplicitlyActivateClassicAAAServersAsIU_No, AppModelPolicy_PolicyValue.ImplicitlyActivateClassicAAAServersAsIU_No, AppModelPolicy_PolicyValue.ImplicitlyActivateClassicAAAServersAsIU_No, AppModelPolicy_PolicyValue.ImplicitlyActivateClassicAAAServersAsIU_No, AppModelPolicy_PolicyValue.ImplicitlyActivateClassicAAAServersAsIU_Yes,
            AppModelPolicy_PolicyValue.ComClassicCatalog_MachineHiveOnly, AppModelPolicy_PolicyValue.ComClassicCatalog_MachineHiveAndUserHive, AppModelPolicy_PolicyValue.ComClassicCatalog_MachineHiveAndUserHive, AppModelPolicy_PolicyValue.ComClassicCatalog_MachineHiveOnly, AppModelPolicy_PolicyValue.ComClassicCatalog_MachineHiveOnly, AppModelPolicy_PolicyValue.ComClassicCatalog_MachineHiveAndUserHive, AppModelPolicy_PolicyValue.ComClassicCatalog_MachineHiveAndUserHive, AppModelPolicy_PolicyValue.ComClassicCatalog_MachineHiveAndUserHive,
            AppModelPolicy_PolicyValue.ComUnmarshaling_ForceStrongUnmarshaling, AppModelPolicy_PolicyValue.ComUnmarshaling_ApplicationManaged, AppModelPolicy_PolicyValue.ComUnmarshaling_ApplicationManaged, AppModelPolicy_PolicyValue.ComUnmarshaling_ForceStrongUnmarshaling, AppModelPolicy_PolicyValue.ComUnmarshaling_ForceStrongUnmarshaling, AppModelPolicy_PolicyValue.ComUnmarshaling_ApplicationManaged, AppModelPolicy_PolicyValue.ComUnmarshaling_ApplicationManaged, AppModelPolicy_PolicyValue.ComUnmarshaling_ApplicationManaged,
            AppModelPolicy_PolicyValue.ComAppLaunchPerfEnhancements_Enabled, AppModelPolicy_PolicyValue.ComAppLaunchPerfEnhancements_Disabled, AppModelPolicy_PolicyValue.ComAppLaunchPerfEnhancements_Disabled, AppModelPolicy_PolicyValue.ComAppLaunchPerfEnhancements_Enabled, AppModelPolicy_PolicyValue.ComAppLaunchPerfEnhancements_Enabled, AppModelPolicy_PolicyValue.ComAppLaunchPerfEnhancements_Disabled, AppModelPolicy_PolicyValue.ComAppLaunchPerfEnhancements_Disabled, AppModelPolicy_PolicyValue.ComAppLaunchPerfEnhancements_Disabled,
            AppModelPolicy_PolicyValue.ComSecurityInitialization_SystemManaged, AppModelPolicy_PolicyValue.ComSecurityInitialization_ApplicationManaged, AppModelPolicy_PolicyValue.ComSecurityInitialization_ApplicationManaged, AppModelPolicy_PolicyValue.ComSecurityInitialization_SystemManaged, AppModelPolicy_PolicyValue.ComSecurityInitialization_SystemManaged, AppModelPolicy_PolicyValue.ComSecurityInitialization_SystemManaged, AppModelPolicy_PolicyValue.ComSecurityInitialization_ApplicationManaged, AppModelPolicy_PolicyValue.ComSecurityInitialization_ApplicationManaged,
            AppModelPolicy_PolicyValue.RoInitializeSingleThreadedBehavior_ASTA, AppModelPolicy_PolicyValue.RoInitializeSingleThreadedBehavior_STA, AppModelPolicy_PolicyValue.RoInitializeSingleThreadedBehavior_STA, AppModelPolicy_PolicyValue.RoInitializeSingleThreadedBehavior_ASTA, AppModelPolicy_PolicyValue.RoInitializeSingleThreadedBehavior_ASTA, AppModelPolicy_PolicyValue.RoInitializeSingleThreadedBehavior_STA, AppModelPolicy_PolicyValue.RoInitializeSingleThreadedBehavior_STA, AppModelPolicy_PolicyValue.RoInitializeSingleThreadedBehavior_STA,
            AppModelPolicy_PolicyValue.ComDefaultExceptionHandling_HandleNone, AppModelPolicy_PolicyValue.ComDefaultExceptionHandling_HandleAll, AppModelPolicy_PolicyValue.ComDefaultExceptionHandling_HandleAll, AppModelPolicy_PolicyValue.ComDefaultExceptionHandling_HandleNone, AppModelPolicy_PolicyValue.ComDefaultExceptionHandling_HandleNone, AppModelPolicy_PolicyValue.ComDefaultExceptionHandling_HandleAll, AppModelPolicy_PolicyValue.ComDefaultExceptionHandling_HandleAll, AppModelPolicy_PolicyValue.ComDefaultExceptionHandling_HandleAll,
            AppModelPolicy_PolicyValue.ComOopProxyAgility_Agile, AppModelPolicy_PolicyValue.ComOopProxyAgility_NonAgile, AppModelPolicy_PolicyValue.ComOopProxyAgility_NonAgile, AppModelPolicy_PolicyValue.ComOopProxyAgility_Agile, AppModelPolicy_PolicyValue.ComOopProxyAgility_Agile, AppModelPolicy_PolicyValue.ComOopProxyAgility_NonAgile, AppModelPolicy_PolicyValue.ComOopProxyAgility_NonAgile, AppModelPolicy_PolicyValue.ComOopProxyAgility_NonAgile,
            AppModelPolicy_PolicyValue.AppServiceLifetime_StandardTimeout, AppModelPolicy_PolicyValue.AppServiceLifetime_ExtendedForSamePackage, AppModelPolicy_PolicyValue.AppServiceLifetime_StandardTimeout, AppModelPolicy_PolicyValue.AppServiceLifetime_StandardTimeout, AppModelPolicy_PolicyValue.AppServiceLifetime_StandardTimeout, AppModelPolicy_PolicyValue.AppServiceLifetime_StandardTimeout, AppModelPolicy_PolicyValue.AppServiceLifetime_StandardTimeout, AppModelPolicy_PolicyValue.AppServiceLifetime_StandardTimeout,
            AppModelPolicy_PolicyValue.WebPlatform_Edge, AppModelPolicy_PolicyValue.WebPlatform_Legacy, AppModelPolicy_PolicyValue.WebPlatform_Legacy, AppModelPolicy_PolicyValue.WebPlatform_Legacy, AppModelPolicy_PolicyValue.WebPlatform_Legacy, AppModelPolicy_PolicyValue.WebPlatform_Legacy, AppModelPolicy_PolicyValue.WebPlatform_Legacy, AppModelPolicy_PolicyValue.WebPlatform_Legacy,
            AppModelPolicy_PolicyValue.WinInetStoragePartitioning_Isolated, AppModelPolicy_PolicyValue.WinInetStoragePartitioning_SharedWithAppContainer, AppModelPolicy_PolicyValue.WinInetStoragePartitioning_Isolated, AppModelPolicy_PolicyValue.WinInetStoragePartitioning_Isolated, AppModelPolicy_PolicyValue.WinInetStoragePartitioning_Isolated, AppModelPolicy_PolicyValue.WinInetStoragePartitioning_Isolated, AppModelPolicy_PolicyValue.WinInetStoragePartitioning_Isolated, AppModelPolicy_PolicyValue.WinInetStoragePartitioning_Isolated,
            AppModelPolicy_PolicyValue.IndexerProtocolHandlerHost_PerUser, AppModelPolicy_PolicyValue.IndexerProtocolHandlerHost_PerApp, AppModelPolicy_PolicyValue.IndexerProtocolHandlerHost_PerUser, AppModelPolicy_PolicyValue.IndexerProtocolHandlerHost_PerUser, AppModelPolicy_PolicyValue.IndexerProtocolHandlerHost_PerUser, AppModelPolicy_PolicyValue.IndexerProtocolHandlerHost_PerUser, AppModelPolicy_PolicyValue.IndexerProtocolHandlerHost_PerUser, AppModelPolicy_PolicyValue.IndexerProtocolHandlerHost_PerUser,
            AppModelPolicy_PolicyValue.LoaderIncludeUserDirectories_False, AppModelPolicy_PolicyValue.LoaderIncludeUserDirectories_True, AppModelPolicy_PolicyValue.LoaderIncludeUserDirectories_False, AppModelPolicy_PolicyValue.LoaderIncludeUserDirectories_False, AppModelPolicy_PolicyValue.LoaderIncludeUserDirectories_False, AppModelPolicy_PolicyValue.LoaderIncludeUserDirectories_False, AppModelPolicy_PolicyValue.LoaderIncludeUserDirectories_False, AppModelPolicy_PolicyValue.LoaderIncludeUserDirectories_False,
            AppModelPolicy_PolicyValue.ConvertAppContainerToRestrictedAppContainer_False, AppModelPolicy_PolicyValue.ConvertAppContainerToRestrictedAppContainer_True, AppModelPolicy_PolicyValue.ConvertAppContainerToRestrictedAppContainer_False, AppModelPolicy_PolicyValue.ConvertAppContainerToRestrictedAppContainer_False, AppModelPolicy_PolicyValue.ConvertAppContainerToRestrictedAppContainer_False, AppModelPolicy_PolicyValue.ConvertAppContainerToRestrictedAppContainer_False, AppModelPolicy_PolicyValue.ConvertAppContainerToRestrictedAppContainer_False, AppModelPolicy_PolicyValue.ConvertAppContainerToRestrictedAppContainer_False,
            AppModelPolicy_PolicyValue.PackageMayContainPrivateMapiProvider_None, AppModelPolicy_PolicyValue.PackageMayContainPrivateMapiProvider_PrivateHive, AppModelPolicy_PolicyValue.PackageMayContainPrivateMapiProvider_None, AppModelPolicy_PolicyValue.PackageMayContainPrivateMapiProvider_None, AppModelPolicy_PolicyValue.PackageMayContainPrivateMapiProvider_None, AppModelPolicy_PolicyValue.PackageMayContainPrivateMapiProvider_None, AppModelPolicy_PolicyValue.PackageMayContainPrivateMapiProvider_None, AppModelPolicy_PolicyValue.PackageMayContainPrivateMapiProvider_None,
            AppModelPolicy_PolicyValue.AdminProcessPackageClaims_None, AppModelPolicy_PolicyValue.AdminProcessPackageClaims_Caller, AppModelPolicy_PolicyValue.AdminProcessPackageClaims_None, AppModelPolicy_PolicyValue.AdminProcessPackageClaims_None, AppModelPolicy_PolicyValue.AdminProcessPackageClaims_None, AppModelPolicy_PolicyValue.AdminProcessPackageClaims_None, AppModelPolicy_PolicyValue.AdminProcessPackageClaims_None, AppModelPolicy_PolicyValue.AdminProcessPackageClaims_None,
            AppModelPolicy_PolicyValue.RegistryRedirectionBehavior_None, AppModelPolicy_PolicyValue.RegistryRedirectionBehavior_CopyOnWrite, AppModelPolicy_PolicyValue.RegistryRedirectionBehavior_None, AppModelPolicy_PolicyValue.RegistryRedirectionBehavior_None, AppModelPolicy_PolicyValue.RegistryRedirectionBehavior_None, AppModelPolicy_PolicyValue.RegistryRedirectionBehavior_None, AppModelPolicy_PolicyValue.RegistryRedirectionBehavior_None, AppModelPolicy_PolicyValue.RegistryRedirectionBehavior_None,
            AppModelPolicy_PolicyValue.BypassCreateProcessAppxExtension_False, AppModelPolicy_PolicyValue.BypassCreateProcessAppxExtension_False, AppModelPolicy_PolicyValue.BypassCreateProcessAppxExtension_False, AppModelPolicy_PolicyValue.BypassCreateProcessAppxExtension_False, AppModelPolicy_PolicyValue.BypassCreateProcessAppxExtension_False, AppModelPolicy_PolicyValue.BypassCreateProcessAppxExtension_False, AppModelPolicy_PolicyValue.BypassCreateProcessAppxExtension_False, AppModelPolicy_PolicyValue.BypassCreateProcessAppxExtension_True,
            AppModelPolicy_PolicyValue.KnownFolderRedirection_Isolated, AppModelPolicy_PolicyValue.KnownFolderRedirection_RedirectToPackage, AppModelPolicy_PolicyValue.KnownFolderRedirection_Isolated, AppModelPolicy_PolicyValue.KnownFolderRedirection_Isolated, AppModelPolicy_PolicyValue.KnownFolderRedirection_Isolated, AppModelPolicy_PolicyValue.KnownFolderRedirection_Isolated, AppModelPolicy_PolicyValue.KnownFolderRedirection_Isolated, AppModelPolicy_PolicyValue.KnownFolderRedirection_Isolated,
            AppModelPolicy_PolicyValue.PrivateActivateAsPackageWinrtClasses_AllowNonFullTrust, AppModelPolicy_PolicyValue.PrivateActivateAsPackageWinrtClasses_AllowFullTrust, AppModelPolicy_PolicyValue.PrivateActivateAsPackageWinrtClasses_AllowNone, AppModelPolicy_PolicyValue.PrivateActivateAsPackageWinrtClasses_AllowNone, AppModelPolicy_PolicyValue.PrivateActivateAsPackageWinrtClasses_AllowNone, AppModelPolicy_PolicyValue.PrivateActivateAsPackageWinrtClasses_AllowNone, AppModelPolicy_PolicyValue.PrivateActivateAsPackageWinrtClasses_AllowNone, AppModelPolicy_PolicyValue.PrivateActivateAsPackageWinrtClasses_AllowNone,
            AppModelPolicy_PolicyValue.AppPrivateFolderRedirection_AppPrivate, AppModelPolicy_PolicyValue.AppPrivateFolderRedirection_AppPrivate, AppModelPolicy_PolicyValue.AppPrivateFolderRedirection_None, AppModelPolicy_PolicyValue.AppPrivateFolderRedirection_None, AppModelPolicy_PolicyValue.AppPrivateFolderRedirection_None, AppModelPolicy_PolicyValue.AppPrivateFolderRedirection_None, AppModelPolicy_PolicyValue.AppPrivateFolderRedirection_None, AppModelPolicy_PolicyValue.AppPrivateFolderRedirection_None,
            AppModelPolicy_PolicyValue.GlobalSystemAppDataAccess_Virtualized, AppModelPolicy_PolicyValue.GlobalSystemAppDataAccess_Virtualized, AppModelPolicy_PolicyValue.GlobalSystemAppDataAccess_Normal, AppModelPolicy_PolicyValue.GlobalSystemAppDataAccess_Normal, AppModelPolicy_PolicyValue.GlobalSystemAppDataAccess_Normal, AppModelPolicy_PolicyValue.GlobalSystemAppDataAccess_Normal, AppModelPolicy_PolicyValue.GlobalSystemAppDataAccess_Normal, AppModelPolicy_PolicyValue.GlobalSystemAppDataAccess_Normal,
            AppModelPolicy_PolicyValue.ConsoleHandleInheritance_All, AppModelPolicy_PolicyValue.ConsoleHandleInheritance_ConsoleOnly, AppModelPolicy_PolicyValue.ConsoleHandleInheritance_ConsoleOnly, AppModelPolicy_PolicyValue.ConsoleHandleInheritance_ConsoleOnly, AppModelPolicy_PolicyValue.ConsoleHandleInheritance_ConsoleOnly, AppModelPolicy_PolicyValue.ConsoleHandleInheritance_ConsoleOnly, AppModelPolicy_PolicyValue.ConsoleHandleInheritance_ConsoleOnly, AppModelPolicy_PolicyValue.ConsoleHandleInheritance_ConsoleOnly,
            AppModelPolicy_PolicyValue.ConsoleBufferAccess_RestrictedUnidirectional, AppModelPolicy_PolicyValue.ConsoleBufferAccess_Unrestricted, AppModelPolicy_PolicyValue.ConsoleBufferAccess_Unrestricted, AppModelPolicy_PolicyValue.ConsoleBufferAccess_RestrictedUnidirectional, AppModelPolicy_PolicyValue.ConsoleBufferAccess_RestrictedUnidirectional, AppModelPolicy_PolicyValue.ConsoleBufferAccess_RestrictedUnidirectional, AppModelPolicy_PolicyValue.ConsoleBufferAccess_Unrestricted, AppModelPolicy_PolicyValue.ConsoleBufferAccess_Unrestricted,
            AppModelPolicy_PolicyValue.ConvertCallerTokenToUserTokenForDeployment_UserCallerToken, AppModelPolicy_PolicyValue.ConvertCallerTokenToUserTokenForDeployment_ConvertTokenToUserToken, AppModelPolicy_PolicyValue.ConvertCallerTokenToUserTokenForDeployment_UserCallerToken, AppModelPolicy_PolicyValue.ConvertCallerTokenToUserTokenForDeployment_UserCallerToken, AppModelPolicy_PolicyValue.ConvertCallerTokenToUserTokenForDeployment_UserCallerToken, AppModelPolicy_PolicyValue.ConvertCallerTokenToUserTokenForDeployment_UserCallerToken, AppModelPolicy_PolicyValue.ConvertCallerTokenToUserTokenForDeployment_UserCallerToken, AppModelPolicy_PolicyValue.ConvertCallerTokenToUserTokenForDeployment_UserCallerToken,
        };

        private static int? GetPolicyOffset(AppModelPolicy_Type policy_type, long attributes_present, ulong pkg_claim_flags)
        {
            if ((attributes_present & 1) == 0)
            {
                return 2;
            }

            if ((attributes_present & 2) == 0)
            {
                return 5;
            }

            if ((attributes_present & 4) != 0)
            {
                return 4;
            }

            if ((pkg_claim_flags & 4) != 0)
            {
                return 1;
            }

            if ((pkg_claim_flags & 8) != 0)
            {
                return 6;
            }

            if ((pkg_claim_flags & 0x40) != 0)
            {
                if (policy_type == AppModelPolicy_Type.LifecycleManager)
                {
                    return null;
                }
                return 7;
            }

            return 0;
        }

        private static AppModelPolicy_PolicyValue GetAppPolicy(AppModelPolicy_Type policy_type, long attributes_present, ulong pkg_claim_flags)
        {
            var offset = GetPolicyOffset(policy_type, attributes_present, pkg_claim_flags);
            if (!offset.HasValue)
            {
                return AppModelPolicy_PolicyValue.None;
            }

            return _policy_lookup_table[8 * ((int)policy_type - 1) + offset.Value];
        }

        #endregion
    }
}
