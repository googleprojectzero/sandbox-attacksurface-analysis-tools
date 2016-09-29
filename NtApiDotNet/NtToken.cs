using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Linq;
using System.Text;

namespace NtApiDotNet
{
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
        //PWSTR* ppString;
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

        public PrivilegeAttributes Attributes { get; set; }

        public Luid Luid { get; private set; }

        public string GetName()
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

        public string GetDisplayName()
        {
            int name_length = 0;
            int lang_id = 0;
            string name = GetName();
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

        public bool IsEnabled
        {
            get { return (Attributes & PrivilegeAttributes.Enabled) == PrivilegeAttributes.Enabled; }
        }

        public TokenPrivilege(Luid luid, PrivilegeAttributes attribute)
        {
            Luid = luid;
            Attributes = attribute;
        }

        public TokenPrivilege(TokenPrivilegeValue value, PrivilegeAttributes attribute) 
            : this(new Luid((uint)value, 0), attribute)
        {
        }
    }

    internal class TokenPrivilegesBuilder
    {
        private List<LuidAndAttributes> _privs;

        public TokenPrivilegesBuilder()
        {
            _privs = new List<LuidAndAttributes>();
        }
        
        // Don't think there's a direct NT equivalent as this talks to LSASS.
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(
          string lpSystemName,
          string lpName,
          out Luid lpLuid
        );

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
            Luid luid;
            if (!LookupPrivilegeValue(null, name, out luid))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            AddPrivilege(luid, enable ? PrivilegeAttributes.Enabled : PrivilegeAttributes.Disabled);
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
                for(int i = 0; i < _sid_and_attrs.Count; ++i)
                {                
                    sids.Add(_sid_and_attrs[i].sid.ToSafeBuffer());
                    result[i] = new SidAndAttributes();
                    result[i].Sid = sids[i].DangerousGetHandle();
                    result[i].Attributes = _sid_and_attrs[i].attr;
                }
                TokenGroups groups = new TokenGroups();
                groups.GroupCount = result.Length;
                groups.Groups = result;
                return new SafeTokenGroupsBuffer(groups, sids.DangerousTakeCopy());
            }
        }
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

    public sealed class UserGroup
    {
        public Sid Sid { get; private set; }
        public GroupAttributes Attributes { get; private set; }

        public bool IsEnabled()
        {
            return (Attributes & GroupAttributes.Enabled) == GroupAttributes.Enabled;
        }

        public bool IsMandatory()
        {
            return (Attributes & GroupAttributes.Mandatory) == GroupAttributes.Mandatory;
        }

        public bool IsDenyOnly()
        {
            return (Attributes & GroupAttributes.UseForDenyOnly) == GroupAttributes.UseForDenyOnly;
        }

        public UserGroup(Sid sid, GroupAttributes attributes)
        {
            Sid = sid;
            Attributes = attributes;
        }

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
                    return ReadTyped<IntPtr>(buffer, count).Select(v => Marshal.PtrToStringUni(v)).Cast<object>();
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

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus NtCreateLowBoxToken(
          out SafeKernelObjectHandle token,
          SafeHandle original_token,
          GenericAccessRights access,
          ObjectAttributes object_attribute,
          byte[] appcontainer_sid,
          int capabilityCount,
          SidAndAttributes[] capabilities,
          int handle_count,
          IntPtr[] handles);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus NtOpenProcessTokenEx(
          SafeKernelObjectHandle ProcessHandle,
          GenericAccessRights DesiredAccess,
          AttributeFlags HandleAttributes,
          out SafeKernelObjectHandle TokenHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenThreadTokenEx(
          SafeKernelObjectHandle ThreadHandle,
          GenericAccessRights DesiredAccess,
          [MarshalAs(UnmanagedType.U1)] bool OpenAsSelf,
          AttributeFlags HandleAttributes,
          out SafeKernelObjectHandle TokenHandle
        );

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus NtDuplicateToken(
            SafeKernelObjectHandle ExistingTokenHandle,
            GenericAccessRights DesiredAccess,
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
                    StatusToNtException(status);
                ret = new SafeStructureInOutBuffer<T>(return_length, false);
                status = NtSystemCalls.NtQueryInformationToken(Handle, token_info, ret.DangerousGetHandle(), ret.Length, out return_length);
                StatusToNtException(status);
            }
            finally
            {
                if (ret != null && !IsSuccess(status))
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
                StatusToNtException(NtSystemCalls.NtSetInformationToken(Handle, token_info, buffer, buffer.Length));
            }
        }

        /// <summary>
        /// Duplicate token as specific type
        /// </summary>
        /// <param name="type">The token type</param>
        /// <param name="level">The impersonation level us type is Impersonation</param>
        /// <returns>The new token</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtToken DuplicateToken(TokenType type, SecurityImpersonationLevel level)
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
                StatusToNtException(NtSystemCalls.NtDuplicateToken(Handle,
                  GenericAccessRights.MaximumAllowed, obja, false, type, out new_token));
                return new NtToken(new_token);
            }
        }

        /// <summary>
        /// Duplicate the token as a primary token
        /// </summary>
        /// <returns>The new token</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtToken DuplicateToken()
        {
            return DuplicateToken(TokenType.Primary, SecurityImpersonationLevel.Anonymous);
        }

        /// <summary>
        /// Duplicate token as an impersonation token with a specific level
        /// </summary>
        /// <param name="level">The token impersonation level</param>
        /// <returns>The new token</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtToken DuplicateToken(SecurityImpersonationLevel level)
        {
            return DuplicateToken(TokenType.Impersonation, level);
        }
        
        private bool SetPrivileges(TokenPrivilegesBuilder tp)
        {
            using (var priv_buffer = tp.ToBuffer())
            {
                NtStatus status = NtSystemCalls.NtAdjustPrivilegesToken(Handle, false, 
                    priv_buffer, priv_buffer.Length, IntPtr.Zero, IntPtr.Zero);
                if (status == NtStatus.STATUS_NOT_ALL_ASSIGNED)
                    return false;
                StatusToNtException(status);
                return true;
            }
        }

        public bool SetPrivilege(string privilege, bool enable)
        {
            TokenPrivilegesBuilder tp = new TokenPrivilegesBuilder();
            tp.AddPrivilege(privilege, enable);
            return SetPrivileges(tp);
        }

        public bool SetPrivilege(Luid luid, bool enable)
        {
            TokenPrivilegesBuilder tp = new TokenPrivilegesBuilder();
            tp.AddPrivilege(luid, enable ? PrivilegeAttributes.Enabled : PrivilegeAttributes.Disabled);
            return SetPrivileges(tp);
        }

        public bool SetPrivilege(TokenPrivilegeValue privilege, PrivilegeAttributes attributes)
        {
            TokenPrivilegesBuilder tp = new TokenPrivilegesBuilder();
            tp.AddPrivilege(privilege, attributes);
            return SetPrivileges(tp);
        }

        public bool SetPrivilege(TokenPrivilege privilege)
        {
            TokenPrivilegesBuilder tp = new TokenPrivilegesBuilder();
            tp.AddPrivilege(privilege);
            return SetPrivileges(tp);
        }

        public static bool EnableDebugPrivilege()
        {
            using (NtToken token = NtProcess.Current.OpenToken())
            {
                return token.SetPrivilege(TokenPrivilegeValue.SeDebugPrivilege, PrivilegeAttributes.Enabled);
            }
        }

        public static NtToken OpenProcessToken(NtProcess process, bool duplicate)
        {
            SafeKernelObjectHandle new_token;
            StatusToNtException(NtSystemCalls.NtOpenProcessTokenEx(process.Handle,
              GenericAccessRights.MaximumAllowed, AttributeFlags.None, out new_token));
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

        public static NtToken OpenProcessToken(NtProcess process)
        {
            return OpenProcessToken(process, false);
        }

        public static NtToken OpenProcessToken()
        {
            return OpenProcessToken(false);
        }

        public static NtToken OpenProcessToken(bool duplicate)
        {
            return OpenProcessToken(NtProcess.Current, duplicate);
        }

        public static NtToken OpenProcessToken(int pid, bool duplicate)
        {
            using (NtProcess process = NtProcess.Open(pid, ProcessAccessRights.QueryInformation))
            {
                return OpenProcessToken(process, duplicate);
            }
        }

        public static NtToken OpenProcessToken(int pid)
        {
            return OpenProcessToken(pid, false);
        }
        public static NtToken OpenThreadToken(NtThread thread, bool open_as_self, bool duplicate)
        {
            SafeKernelObjectHandle new_token;
            NtStatus status = NtSystemCalls.NtOpenThreadTokenEx(thread.Handle,
              GenericAccessRights.MaximumAllowed, open_as_self, AttributeFlags.None, out new_token);
            if (status == NtStatus.STATUS_NO_TOKEN)
                return null;
            StatusToNtException(status);
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

        public static NtToken OpenThreadToken(NtThread thread)
        {
            return OpenThreadToken(thread, true, false);
        }

        public static NtToken OpenThreadToken(bool duplicate)
        {
            return OpenThreadToken(NtThread.Current, true, duplicate);
        }

        public static NtToken OpenThreadToken()
        {
            return OpenThreadToken(false);
        }

        public static NtToken OpenEffectiveToken(bool duplicate)
        {
            try
            {
                return OpenThreadToken(duplicate);
            }
            catch (NtException)
            {
                return OpenProcessToken(duplicate);
            }
        }

        public static NtToken OpenEffectiveToken()
        {
            return OpenEffectiveToken(false);
        }

        public NtToken CreateLowBoxToken(string package_sid, params SafeHandle[] handles)
        {
            SafeKernelObjectHandle token;
            SecurityIdentifier sid = new SecurityIdentifier(package_sid);
            byte[] sid_bin = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sid_bin, 0);

            IntPtr[] handle_array = null;
            int handle_count = handles != null ? handles.Length : 0;
            if (handle_count > 0)
            {
                handle_array = new IntPtr[handle_count];
                for (int i = 0; i < handle_count; ++i)
                {
                    handle_array[i] = handles[i].DangerousGetHandle();
                }
            }

            StatusToNtException(NtSystemCalls.NtCreateLowBoxToken(out token, 
                Handle, GenericAccessRights.MaximumAllowed,
              new ObjectAttributes(), sid_bin, 0, null, handle_count, handle_array));

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

        public NtToken Filter(FilterTokenFlags flags, IEnumerable<Sid> sids_to_disable, IEnumerable<TokenPrivilegeValue> privileges_to_delete, IEnumerable<Sid> restricted_sids)
        {
            return Filter(flags, sids_to_disable, privileges_to_delete.Select(p => new Luid((uint)p, 0)), restricted_sids);
        }

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

        public void SetGroup(Sid group, GroupAttributes attributes)
        {
            using (var buffer = BuildGroups(new Sid[] { group }, attributes))
            {
                StatusToNtException(NtSystemCalls.NtAdjustGroupsToken(Handle, false, buffer, 0, IntPtr.Zero, IntPtr.Zero));
            }
        }
        

        public void SetSessionId(int session_id)
        {
            SetToken(TokenInformationClass.TokenSessionId, session_id);
        }

        public UserGroup GetUser()
        {
            using (var user = QueryToken<TokenUser>(TokenInformationClass.TokenUser))
            {
                return user.Result.User.ToUserGroup();
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

        public UserGroup[] GetGroups()
        {
            return QueryGroups(TokenInformationClass.TokenGroups);
        }

        public static UserGroup GetCurrentUser()
        {
            using (NtToken token = OpenEffectiveToken())
            {
                return token.GetUser();
            }
        }

        private TokenStatistics GetTokenStats()
        {
            using (var stats = QueryToken<TokenStatistics>(TokenInformationClass.TokenStatistics))
            {
                return stats.Result;
            }
        }

        public Luid GetAuthenticationId()
        {
            return GetTokenStats().AuthenticationId;
        }

        public TokenType GetTokenType()
        {
            return GetTokenStats().TokenType;
        }

        public LargeInteger GetExpirationTime()
        {
            return new LargeInteger(GetTokenStats().ExpirationTime.QuadPart);
        }

        public Luid GetId()
        {
            return GetTokenStats().TokenId;
        }

        public Luid GetModifiedId()
        {
            return GetTokenStats().ModifiedId;
        }

        public Sid GetOwner()
        {
            using (var owner_buf = QueryToken<TokenOwner>(TokenInformationClass.TokenOwner))
            {
                return new Sid(owner_buf.Result.Owner);
            }
        }

        public Sid GetPrimaryGroup()
        {
            using (var owner_buf = QueryToken<TokenPrimaryGroup>(TokenInformationClass.TokenPrimaryGroup))
            {
                return new Sid(owner_buf.Result.PrimaryGroup);
            }
        }

        public Acl GetDefaultDalc()
        {
            using (var dacl_buf = QueryToken<TokenDefaultDacl>(TokenInformationClass.TokenDefaultDacl))
            {
                return new Acl(dacl_buf.Result.DefaultDacl, false);
            }
        }

        public void SetDefaultDacl(Acl dacl)
        {
            using (var dacl_buf = dacl.ToSafeBuffer())
            {
                TokenDefaultDacl default_dacl = new TokenDefaultDacl();
                default_dacl.DefaultDacl = dacl_buf.DangerousGetHandle();
                SetToken(TokenInformationClass.TokenDefaultDacl, default_dacl);
            }
        }

        public TokenSource GetSource()
        {
            using (var source_buf = QueryToken<TokenSource>(TokenInformationClass.TokenSource))
            {
                return source_buf.Result;
            }
        }

        public UserGroup[] GetRestrictedSids()
        {
            return QueryGroups(TokenInformationClass.TokenRestrictedSids);
        }

        public SecurityImpersonationLevel GetImpersonationLevel()
        {
            return GetTokenStats().ImpersonationLevel;
        }

        public int GetSessionId()
        {
            using (var buf = QueryToken<int>(TokenInformationClass.TokenSessionId))
            {
                return buf.Result;
            }
        }

        public bool IsSandboxInert()
        {
            using (var buf = QueryToken<int>(TokenInformationClass.TokenSandBoxInert))
            {
                return buf.Result != 0;
            }
        }

        public Luid GetOrigin()
        {
            using (var buf = QueryToken<Luid>(TokenInformationClass.TokenOrigin))
            {
                return buf.Result;
            }
        }

        public TokenElevationType GetElevationType()
        {
            using (var buf = QueryToken<int>(TokenInformationClass.TokenElevationType))
            {
                return (TokenElevationType)buf.Result;
            }
        }

        public bool IsElevated()
        {
            using (var buf = QueryToken<int>(TokenInformationClass.TokenElevation))
            {
                return buf.Result != 0;
            }
        }

        public bool HasRestrictions()
        {
            using (var buf = QueryToken<int>(TokenInformationClass.TokenHasRestrictions))
            {
                return buf.Result != 0;
            }
        }

        public bool IsUiAccess()
        {
            using (var buf = QueryToken<int>(TokenInformationClass.TokenUIAccess))
            {
                return buf.Result != 0;
            }
        }

        public bool IsVirtualizationAllowed()
        {
            using (var buf = QueryToken<int>(TokenInformationClass.TokenVirtualizationAllowed))
            {
                return buf.Result != 0;
            }
        }

        public bool IsVirtualizationEnabled()
        {
            using (var buf = QueryToken<int>(TokenInformationClass.TokenVirtualizationEnabled))
            {
                return buf.Result != 0;
            }
        }

        public bool IsRestricted()
        {
            return GetRestrictedSids().Length > 0;
        }

        public NtToken GetLinkedToken()
        {
            using (var buf = QueryToken<IntPtr>(TokenInformationClass.TokenLinkedToken))
            {
                return new NtToken(new SafeKernelObjectHandle(buf.Result, true));
            }
        }

        public UserGroup[] GetCapabilities()
        {
            return QueryGroups(TokenInformationClass.TokenCapabilities);
        }

        public TokenMandatoryPolicy GetMandatoryPolicy()
        {
            using (var buf = QueryToken<int>(TokenInformationClass.TokenMandatoryPolicy))
            {
                return (TokenMandatoryPolicy)buf.Result;
            }
        }

        public UserGroup GetLogonSid()
        {
            return QueryGroups(TokenInformationClass.TokenLogonSid).FirstOrDefault();
        }

        public WindowsImpersonationContext Impersonate()
        {
            return WindowsIdentity.Impersonate(Handle.DangerousGetHandle());
        }

        public static WindowsImpersonationContext Impersonate(int pid, SecurityImpersonationLevel impersonation_level)
        {
            using (NtToken process_token = OpenProcessToken(pid))
            {
                using (NtToken imp_token = process_token.DuplicateToken(impersonation_level))
                {
                    return imp_token.Impersonate();
                }
            }
        }

        public UserGroup GetIntegrityLevelSid()
        {
            using (var label = QueryToken<TokenMandatoryLabel>(TokenInformationClass.TokenIntegrityLevel))
            {
                return label.Result.Label.ToUserGroup();
            }
        }

        public int GetAppContainerNumber()
        {
            using (var buf = QueryToken<int>(TokenInformationClass.TokenAppContainerNumber))
            {
                return buf.Result;
            }
        }

        public TokenIntegrityLevel GetIntegrityLevel()
        {
            UserGroup group = GetIntegrityLevelSid();
            string[] parts = group.Sid.ToString().Split('-');
            return (TokenIntegrityLevel)int.Parse(parts[parts.Length - 1]);
        }

        public ClaimSecurityAttribute[] GetSecurityAttributes()
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

        private void SetIntegrityLevel(Sid sid)
        {
            using (SafeSidBufferHandle sid_buffer = sid.ToSafeBuffer())
            {                
                TokenMandatoryLabel label = new TokenMandatoryLabel();
                label.Label.Sid = sid_buffer.DangerousGetHandle();
                SetToken(TokenInformationClass.TokenIntegrityLevel, label);                
            }
        }

        public void SetIntegrityLevel(int level)
        {            
            SetIntegrityLevel(Sid.GetIntegritySid(level));
        }

        public void SetIntegrityLevel(TokenIntegrityLevel level)
        {
            SetIntegrityLevel(Sid.GetIntegritySid(level));
        }

        public bool IsAppContainer()
        {
            using (var appcontainer = QueryToken<uint>(TokenInformationClass.TokenIsAppContainer))
            {
                return appcontainer.Result != 0;
            }
        }

        public Sid GetAppContainerSid()
        {
            using (var acsid = QueryToken<TokenAppContainerInformation>(TokenInformationClass.TokenAppContainerSid))
            {
                return new Sid(acsid.Result.TokenAppContainer);
            }
        }

        public UserGroup[] GetDeviceGroups()
        {
            return QueryGroups(TokenInformationClass.TokenDeviceGroups);
        }

        public UserGroup[] GetRestrictedDeviceGroups()
        {
            return QueryGroups(TokenInformationClass.TokenRestrictedDeviceGroups);
        }

        public TokenPrivilege[] GetPrivileges()
        {
            using (var buffer = QueryToken<TokenPrivileges>(TokenInformationClass.TokenPrivileges))
            {
                int count = buffer.Result.PrivilegeCount;
                LuidAndAttributes[] attrs = new LuidAndAttributes[count];
                buffer.Data.ReadArray(0, attrs, 0, count);
                return attrs.Select(a => new TokenPrivilege(a.Luid, (PrivilegeAttributes)a.Attributes)).ToArray();
            }
        }

        public static Luid LocalSystemAuthId { get { return new Luid(0x3e7, 0); } }
        public static Luid LocalServiceAuthId { get { return new Luid(0x3e5, 0); } }
        public static Luid NetworkServiceAuthId { get { return new Luid(0x3e4, 0); } }
    }
}
