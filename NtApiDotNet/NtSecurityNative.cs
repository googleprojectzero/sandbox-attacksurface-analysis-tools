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

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

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
        AccessFilter = 0x100,
        Backup = 0x10000,
        ProtectedDacl = 0x80000000,
        ProtectedSacl = 0x40000000,
        UnprotectedDacl = 0x20000000,
        UnprotectedSacl = 0x1000000,
        AllBasic = Dacl | Owner | Group | Label | ProcessTrustLabel,
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

    public enum HashAlgorithm
    {
        Unknown = 0,
        Sha1 = 0x8004,
        Sha256 = 0x800C,
        Sha384 = 0x800D,
        Sha512 = 0x800E
    }

    [Flags]
    public enum CachedSigningLevelFlags
    {
        None = 0,
        UntrustedSignature = 1,
        TrustedSignature = 2,
        Unknown4 = 4,
        DontUseUSNJournal = 8,
        HasPerAppRules = 0x10,
        SetInTestMode = 0x20,
        ProtectedLightVerification = 0x40
    }

    public class CachedSigningLevel
    {
        public CachedSigningLevelFlags Flags { get; }
        public SigningLevel SigningLevel { get; }
        public string Thumbprint { get; }
        public byte[] ThumbprintBytes { get; }
        public HashAlgorithm ThumbprintAlgorithm { get; }

        internal CachedSigningLevel(int flags, SigningLevel signing_level, byte[] thumbprint, HashAlgorithm thumbprint_algo)
        {
            Flags = (CachedSigningLevelFlags)flags;
            SigningLevel = signing_level;
            ThumbprintBytes = thumbprint;
            ThumbprintAlgorithm = thumbprint_algo;
            Thumbprint = thumbprint.ToHexString();
        }
    }

    public enum CachedSigningLevelBlobType
    {
        FileHash,
        SignerHash,
        WIMGuid,
        Timestamp,
        DGPolicyHash,
        AntiCheatPolicyHash
    }

    public class CachedSigningLevelBlob
    {
        public CachedSigningLevelBlobType BlobType { get; }
        public byte[] Data { get; }
        internal CachedSigningLevelBlob(CachedSigningLevelBlobType blob_type, byte[] data)
        {
            BlobType = blob_type;
            Data = data;
        }

        public override string ToString()
        {
            return $"Type {BlobType} - Length {Data.Length}";
        }

        internal static CachedSigningLevelBlob ReadBlob(BinaryReader reader)
        {
            int blob_size = reader.ReadByte();
            CachedSigningLevelBlobType type = (CachedSigningLevelBlobType)reader.ReadByte();
            byte[] data = reader.ReadAllBytes(blob_size - 2);
            switch (type)
            {
                case CachedSigningLevelBlobType.SignerHash:
                case CachedSigningLevelBlobType.FileHash:
                case CachedSigningLevelBlobType.DGPolicyHash:
                case CachedSigningLevelBlobType.AntiCheatPolicyHash:
                    return new HashCachedSigningLevelBlob(type, data);
                default:
                    return new CachedSigningLevelBlob(type, data);
            }
        }
    }

    public class HashCachedSigningLevelBlob : CachedSigningLevelBlob
    {
        public HashAlgorithm Algorithm { get; }
        public byte[] Hash { get; }

        internal HashCachedSigningLevelBlob(CachedSigningLevelBlobType blob_type, byte[] data)
            : base(blob_type, data)
        {
            Algorithm = (HashAlgorithm)BitConverter.ToInt32(data, 0);
            int size = data[4];
            Hash = new byte[size];
            Buffer.BlockCopy(data, 5, Hash, 0, size);
        }

        public override string ToString()
        {
            return $"Type {BlobType} - Algorithm {Algorithm} - Hash {BitConverter.ToString(Hash).Replace("-", "")}";
        }
    }

    public class CachedSigningLevelEaBuffer : CachedSigningLevel
    {
        public int Version { get; }
        public int Version2 { get; }
        public long USNJournalId { get; }
        public DateTime LastBlackListTime { get; }
        public string Hash { get; }
        public byte[] HashBytes { get; }
        public HashAlgorithm HashAlgorithm { get; }
        public int Sequence { get; }

        internal CachedSigningLevelEaBuffer(int version2, int flags, SigningLevel signing_level,
            long usn, long last_blacklist_time, int sequence, byte[] thumbprint,
            HashAlgorithm thumbprint_algo, byte[] hash, HashAlgorithm hash_algo)
            : base(flags, signing_level, thumbprint, thumbprint_algo)
        {
            Version = 1;
            Version2 = version2;
            USNJournalId = usn;
            LastBlackListTime = DateTime.FromFileTime(last_blacklist_time);
            Sequence = sequence;
            Hash = hash.ToHexString();
            HashBytes = hash;
            HashAlgorithm = hash_algo;
        }
    }

    public class CachedSigningLevelEaBufferV2 : CachedSigningLevel
    {
        public int Version { get; }
        public int Version2 { get; }
        public long USNJournalId { get; }
        public DateTime LastBlackListTime { get; }
        public string Hash { get; }
        public byte[] HashBytes { get; }
        public HashAlgorithm HashAlgorithm { get; }
        public DateTime LastTimeStamp { get; }

        internal CachedSigningLevelEaBufferV2(int version2, int flags, SigningLevel signing_level,
            long usn, long last_blacklist_time, long last_timestamp,
            byte[] thumbprint, HashAlgorithm thumbprint_algo, byte[] hash, HashAlgorithm hash_algo)
            : base(flags, signing_level, thumbprint, thumbprint_algo)
        {
            Version = 2;
            Version2 = version2;
            USNJournalId = usn;
            LastBlackListTime = DateTime.FromFileTime(last_blacklist_time);
            LastTimeStamp = DateTime.FromFileTime(last_timestamp);
            Hash = hash.ToHexString();
            HashBytes = hash;
            HashAlgorithm = hash_algo;
        }
    }

    public class CachedSigningLevelEaBufferV3 : CachedSigningLevel
    {
        public int Version { get; }
        public int Version2 { get; }
        public long USNJournalId { get; }
        public DateTime LastBlackListTime { get; }
        public IEnumerable<CachedSigningLevelBlob> ExtraData { get; }

        internal CachedSigningLevelEaBufferV3(int version2, int flags, SigningLevel signing_level,
            long usn, long last_blacklist_time, IEnumerable<CachedSigningLevelBlob> extra_data,
            HashCachedSigningLevelBlob thumbprint)
            : base(flags, signing_level, thumbprint != null ? thumbprint.Hash : new byte[0],
                  thumbprint != null ? thumbprint.Algorithm : 0)
        {
            Version = 3;
            Version2 = version2;
            USNJournalId = usn;
            LastBlackListTime = DateTime.FromFileTime(last_blacklist_time);
            ExtraData = extra_data;
        }
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Privilege")]
    public struct PrivilegeSet
    {
        public int PrivilegeCount;
        public int Control;
        public LuidAndAttributes Privilege;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class CachedSigningLevelInformation
    {
        int Size;
        UnicodeStringIn CatalogDirectory;

        public CachedSigningLevelInformation(string name)
        {
            Size = Marshal.SizeOf(this);
            CatalogDirectory.SetString(name);
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
        DynamicCodeGeneration = 11,
        Windows = 12,
        WindowsProtectedProcessLight = 13,
        WindowsTCB = 14,
        Custom6 = 15
    }

    public class SafePrivilegeSetBuffer : SafeStructureInOutBuffer<PrivilegeSet>
    {
        public SafePrivilegeSetBuffer(int count)
            : base(new PrivilegeSet(),
                  count * Marshal.SizeOf(typeof(LuidAndAttributes)),
                  true)
        {
        }

        public SafePrivilegeSetBuffer() : this(1)
        {
        }
    }

    /// <summary>
    /// Source for a SID name.
    /// </summary>
    public enum SidNameSource
    {
        Sddl,
        Account,
        Capability,
        Package,
        ProcessTrust,
    }

    /// <summary>
    /// Represents a name for a SID.
    /// </summary>
    public class SidName
    {
        /// <summary>
        /// The name of the SID.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The source of name.
        /// </summary>
        public SidNameSource Source { get; }

        internal SidName(string name, SidNameSource source)
        {
            Name = name;
            Source = source;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public class PsPkgClaim
    {
        public ulong Flags;
        public ulong Origin;
    }

    public enum AppModelPolicy_Type
    {
        LifecycleManager = 0x1,
        AppDataAccess = 0x2,
        WindowingModel = 0x3,
        DllSearchOrder = 0x4,
        Fusion = 0x5,
        NonWindowsCodeLoading = 0x6,
        ProcessEnd = 0x7,
        BeginThreadInit = 0x8,
        DeveloperInformation = 0x9,
        CreateFileAccess = 0xA,
        ImplicitPackageBreakaway_Internal = 0xB,
        ProcessActivationShim = 0xC,
        AppKnownToStateRepository = 0xD,
        AudioManagement = 0xE,
        PackageMayContainPublicComRegistrations = 0xF,
        PackageMayContainPrivateComRegistrations = 0x10,
        LaunchCreateProcessExtensions = 0x11,
        ClrCompat = 0x12,
        LoaderIgnoreAlteredSearchForRelativePath = 0x13,
        ImplicitlyActivateClassicAAAServersAsIU = 0x14,
        ComClassicCatalog = 0x15,
        ComUnmarshaling = 0x16,
        ComAppLaunchPerfEnhancements = 0x17,
        ComSecurityInitialization = 0x18,
        RoInitializeSingleThreadedBehavior = 0x19,
        ComDefaultExceptionHandling = 0x1A,
        ComOopProxyAgility = 0x1B,
        AppServiceLifetime = 0x1C,
        WebPlatform = 0x1D,
        WinInetStoragePartitioning = 0x1E,
        IndexerProtocolHandlerHost = 0x1F,
        LoaderIncludeUserDirectories = 0x20,
        ConvertAppContainerToRestrictedAppContainer = 0x21,
        PackageMayContainPrivateMapiProvider = 0x22,
        AdminProcessPackageClaims = 0x23,
        RegistryRedirectionBehavior = 0x24,
        BypassCreateProcessAppxExtension = 0x25,
        KnownFolderRedirection = 0x26,
        PrivateActivateAsPackageWinrtClasses = 0x27,
        AppPrivateFolderRedirection = 0x28,
        GlobalSystemAppDataAccess = 0x29,
        ConsoleHandleInheritance = 0x2A,
        ConsoleBufferAccess = 0x2B,
        ConvertCallerTokenToUserTokenForDeployment = 0x2C
    };

    public enum AppModelPolicy_PolicyValue
    {
        None = 0,
        LifecycleManager_Unmanaged = 0x10000,
        LifecycleManager_ManagedByPLM = 0x10001,
        LifecycleManager_ManagedByEM = 0x10002,
        AppDataAccess_Allowed = 0x20000,
        AppDataAccess_Denied = 0x20001,
        WindowingModel_Hwnd = 0x30000,
        WindowingModel_CoreWindow = 0x30001,
        WindowingModel_LegacyPhone = 0x30002,
        WindowingModel_None = 0x30003,
        DllSearchOrder_Traditional = 0x40000,
        DllSearchOrder_PackageGraphBased = 0x40001,
        Fusion_Full = 0x50000,
        Fusion_Limited = 0x50001,
        NonWindowsCodeLoading_Allowed = 0x60000,
        NonWindowsCodeLoading_Denied = 0x60001,
        ProcessEnd_TerminateProcess = 0x70000,
        ProcessEnd_ExitProcess = 0x70001,
        BeginThreadInit_RoInitialize = 0x80000,
        BeginThreadInit_None = 0x80001,
        DeveloperInformation_UI = 0x90000,
        DeveloperInformation_None = 0x90001,
        CreateFileAccess_Full = 0xA0000,
        CreateFileAccess_Limited = 0xA0001,
        ImplicitPackageBreakaway_Allowed = 0xB0000,
        ImplicitPackageBreakaway_Denied = 0xB0001,
        ImplicitPackageBreakaway_DeniedByApp = 0xB0002,
        ProcessActivationShim_None = 0xC0000,
        ProcessActivationShim_PackagedCWALauncher = 0xC0001,
        AppKnownToStateRepository_Known = 0xD0000,
        AppKnownToStateRepository_Unknown = 0xD0001,
        AudioManagement_Unmanaged = 0xE0000,
        AudioManagement_ManagedByPBM = 0xE0001,
        PackageMayContainPublicComRegistrations_Yes = 0xF0000,
        PackageMayContainPublicComRegistrations_No = 0xF0001,
        PackageMayContainPrivateComRegistrations_None = 0x100000,
        PackageMayContainPrivateComRegistrations_PrivateHive = 0x100001,
        LaunchCreateProcessExtensions_None = 0x110000,
        LaunchCreateProcessExtensions_RegisterWithPsm = 0x110001,
        LaunchCreateProcessExtensions_RegisterWithDesktopAppX = 0x110002,
        ClrCompat_Others = 0x120000,
        ClrCompat_ClassicDesktop = 0x120001,
        ClrCompat_Universal = 0x120002,
        ClrCompat_PackagedDesktop = 0x120003,
        LoaderIgnoreAlteredSearchForRelativePath_False = 0x130000,
        LoaderIgnoreAlteredSearchForRelativePath_True = 0x130001,
        ImplicitlyActivateClassicAAAServersAsIU_Yes = 0x140000,
        ImplicitlyActivateClassicAAAServersAsIU_No = 0x140001,
        ComClassicCatalog_MachineHiveAndUserHive = 0x150000,
        ComClassicCatalog_MachineHiveOnly = 0x150001,
        ComUnmarshaling_ForceStrongUnmarshaling = 0x160000,
        ComUnmarshaling_ApplicationManaged = 0x160001,
        ComAppLaunchPerfEnhancements_Enabled = 0x170000,
        ComAppLaunchPerfEnhancements_Disabled = 0x170001,
        ComSecurityInitialization_ApplicationManaged = 0x180000,
        ComSecurityInitialization_SystemManaged = 0x180001,
        RoInitializeSingleThreadedBehavior_ASTA = 0x190000,
        RoInitializeSingleThreadedBehavior_STA = 0x190001,
        ComDefaultExceptionHandling_HandleAll = 0x1A0000,
        ComDefaultExceptionHandling_HandleNone = 0x1A0001,
        ComOopProxyAgility_Agile = 0x1B0000,
        ComOopProxyAgility_NonAgile = 0x1B0001,
        AppServiceLifetime_StandardTimeout = 0x1C0000,
        AppServiceLifetime_ExtendedForSamePackage = 0x1C0001,
        WebPlatform_Edge = 0x1D0000,
        WebPlatform_Legacy = 0x1D0001,
        WinInetStoragePartitioning_Isolated = 0x1E0000,
        WinInetStoragePartitioning_SharedWithAppContainer = 0x1E0001,
        IndexerProtocolHandlerHost_PerUser = 0x1F0000,
        IndexerProtocolHandlerHost_PerApp = 0x1F0001,
        LoaderIncludeUserDirectories_False = 0x200000,
        LoaderIncludeUserDirectories_True = 0x200001,
        ConvertAppContainerToRestrictedAppContainer_False = 0x210000,
        ConvertAppContainerToRestrictedAppContainer_True = 0x210001,
        PackageMayContainPrivateMapiProvider_None = 0x220000,
        PackageMayContainPrivateMapiProvider_PrivateHive = 0x220001,
        AdminProcessPackageClaims_None = 0x230000,
        AdminProcessPackageClaims_Caller = 0x230001,
        RegistryRedirectionBehavior_None = 0x240000,
        RegistryRedirectionBehavior_CopyOnWrite = 0x240001,
        BypassCreateProcessAppxExtension_False = 0x250000,
        BypassCreateProcessAppxExtension_True = 0x250001,
        KnownFolderRedirection_Isolated = 0x260000,
        KnownFolderRedirection_RedirectToPackage = 0x260001,
        PrivateActivateAsPackageWinrtClasses_AllowNone = 0x270000,
        PrivateActivateAsPackageWinrtClasses_AllowFullTrust = 0x270001,
        PrivateActivateAsPackageWinrtClasses_AllowNonFullTrust = 0x270002,
        AppPrivateFolderRedirection_None = 0x280000,
        AppPrivateFolderRedirection_AppPrivate = 0x280001,
        GlobalSystemAppDataAccess_Normal = 0x290000,
        GlobalSystemAppDataAccess_Virtualized = 0x290001,
        ConsoleHandleInheritance_ConsoleOnly = 0x2A0000,
        ConsoleHandleInheritance_All = 0x2A0001,
        ConsoleBufferAccess_RestrictedUnidirectional = 0x2B0000,
        ConsoleBufferAccess_Unrestricted = 0x2B0001,
        ConvertCallerTokenToUserTokenForDeployment_UserCallerToken = 0x2C0000,
        ConvertCallerTokenToUserTokenForDeployment_ConvertTokenToUserToken = 0x2C0001,
    };

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
                     out SafeSecurityObjectBuffer NewDescriptor,
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

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlCheckSandboxedToken(SafeKernelObjectHandle token, out bool is_sandboxed);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus RtlQueryPackageClaims(
            SafeKernelObjectHandle TokenHandle,
            [In, Out] byte[] PackageFullName,
            [In, Out] OptionalLength PackageSize, // Size in bytes.
            [In, Out] byte[] AppId,
            [In, Out] OptionalLength AppIdSize,   // Size in bytes.
            [Out] OptionalGuid DynamicId,
            [Out] PsPkgClaim PkgClaim,
            OptionalInt64 AttributesPresent);
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
          int Flags,
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
          out HashAlgorithm ThumbprintAlgorithm
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
        Alarm = 0x3,
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
        AccessFilter = 0x15,
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
        Critical = 0x20,
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
}
