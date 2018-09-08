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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

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
            return (Access & mask.Access) == mask.Access;
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
            return $"{Access:X08}";
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
            return $"R:{GenericRead:X08} W:{GenericWrite:X08} E:{GenericExecute:X08} A:{GenericAll:X08}";
        }
    }

    /// <summary>
    /// Class to represent an Access Control Entry (ACE)
    /// </summary>
    public class Ace
    {
        private static bool IsObjectAceType(AceType type)
        {
            switch(type)
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

        /// <summary>
        /// Check if the ACE is an Object ACE
        /// </summary>
        public bool IsObjectAce
        {
            get
            {
                return IsObjectAceType(Type);
            }
        }

        private static bool IsCallbackAceType(AceType type)
        {
            switch (type)
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

        /// <summary>
        /// Check if the ACE is a callback ACE
        /// </summary>
        public bool IsCallbackAce
        {
            get
            {
                return IsCallbackAceType(Type);
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

                if (ApplicationData == null || ApplicationData.Length < 4)
                {
                    return false;
                }

                return BitConverter.ToUInt32(ApplicationData, 0) == 0x78747261;
            }
        }

        internal Ace(AceType type)
        {
            Type = type;
        }

        internal static Ace CreateAceFromReader(BinaryReader reader)
        {
            long current_position = reader.BaseStream.Position;
            AceType type = (AceType)reader.ReadByte();
            Ace ace;
            switch (type)
            {
                case AceType.MandatoryLabel:
                    ace = new MandatoryLabelAce();
                    break;
                default:
                    ace = new Ace(type);
                    break;
            }
            ace.Flags = (AceFlags)reader.ReadByte();
            int ace_size = reader.ReadUInt16();
            ace.Mask = reader.ReadUInt32();
            if (ace.IsObjectAce)
            {
                ObjectAceFlags flags = (ObjectAceFlags)reader.ReadUInt32();
                if ((flags & ObjectAceFlags.ObjectTypePresent) != 0)
                {
                    ace.ObjectType = new Guid(reader.ReadAllBytes(16));
                }
                if ((flags & ObjectAceFlags.InheritedObjectTypePresent) != 0)
                {
                    ace.InheritedObjectType = new Guid(reader.ReadAllBytes(16));
                }
            }

            ace.Sid = new Sid(reader);
            int bytes_used = (int)(reader.BaseStream.Position - current_position);
            ace.ApplicationData = reader.ReadAllBytes(ace_size - bytes_used);
            return ace;
        }

        internal void Serialize(BinaryWriter writer)
        {
            byte[] sid_data = Sid.ToArray();
            int total_length = 4 + 4 + sid_data.Length;
            if (ApplicationData != null)
            {
                total_length += ApplicationData.Length;
            }

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

            writer.Write((byte)Type);
            writer.Write((byte)Flags);
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
        [Obsolete("Use Type property")]
        public AceType AceType { get { return Type; } set { Type = value; } }

        /// <summary>
        /// Get ACE flags
        /// </summary>
        [Obsolete("Use Flags property")]
        public AceFlags AceFlags { get { return Flags; } set { Flags = value; } }

        /// <summary>
        /// Get ACE type
        /// </summary>
        public AceType Type { get; set; }

        /// <summary>
        /// Get ACE flags
        /// </summary>
        public AceFlags Flags { get; set; }

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
        /// Get conditional check if a conditional ace.
        /// </summary>
        public string Condition
        {
            get
            {
                if (IsConditionalAce)
                {
                    return NtSecurity.ConditionalAceToString(ApplicationData);
                }
                return String.Empty;
            }

            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    ApplicationData = new byte[0];
                    switch (Type)
                    {
                        case AceType.AllowedCallback:
                            Type = AceType.Allowed;
                            break;
                        case AceType.DeniedCallback:
                            Type = AceType.Denied;
                            break;
                    }
                }
                else
                {
                    ApplicationData = NtSecurity.StringToConditionalAce(value);
                    switch (Type)
                    {
                        case AceType.Allowed:
                            Type = AceType.AllowedCallback;
                            break;
                        case AceType.Denied:
                            Type = AceType.DeniedCallback;
                            break;
                    }
                }
            }
        }

        /// <summary>
        /// Convert ACE to a string
        /// </summary>
        /// <returns>The ACE as a string</returns>
        public override string ToString()
        {
            return $"Type {Type} - Flags {Flags} - Mask {Mask:X08} - Sid {Sid}";
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
            return $"Type {Type} - Flags {Flags} - Mask {mask} - Sid {account}";
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

            return ace.Type == Type && ace.Flags == Flags && ace.Sid == Sid && ace.Mask == Mask
                && ace.ObjectType == ObjectType && ace.InheritedObjectType == InheritedObjectType;
        }

        /// <summary>
        /// Get hash code.
        /// </summary>
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            return Type.GetHashCode() ^ Flags.GetHashCode() ^ Mask.GetHashCode() ^ Sid.GetHashCode() ^ ObjectType.GetHashCode() ^ InheritedObjectType.GetHashCode();
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

            if (a is null)
            {
                return false;
            }

            if (b is null)
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
            Type = type;
            Flags = flags;
            Mask = mask;
            Sid = sid;
            ApplicationData = new byte[0];
        }
    }

    /// <summary>
    /// Class to represent an Access Control Entry for a Mandatory Label.
    /// </summary>
    public sealed class MandatoryLabelAce : Ace
    {
        internal MandatoryLabelAce() : base(AceType.MandatoryLabel)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="flags">Flags for the ACE.</param>
        /// <param name="policy">The mandatory label policy.</param>
        /// <param name="integrity_level">The integrity level.</param>
        public MandatoryLabelAce(AceFlags flags, MandatoryLabelPolicy policy, TokenIntegrityLevel integrity_level) 
            : this(flags, policy, NtSecurity.GetIntegritySid(integrity_level))
        {
        }

        /// <summary>
        /// Constructor from a raw integrity level.
        /// </summary>
        /// <param name="flags">Flags for the ACE.</param>
        /// <param name="policy">The mandatory label policy.</param>
        /// <param name="sid">The integrity level sid.</param>
        public MandatoryLabelAce(AceFlags flags, MandatoryLabelPolicy policy, Sid sid)
            : base(AceType.MandatoryLabel, flags, policy, sid)
        {
        }

        /// <summary>
        /// The policy for the mandatory label.
        /// </summary>
        public MandatoryLabelPolicy Policy
        {
            get
            {
                return Mask.ToMandatoryLabelPolicy();
            }
            set
            {
                Mask = value;
            }
        }

        /// <summary>
        /// Get or set the integrity level
        /// </summary>
        public TokenIntegrityLevel IntegrityLevel
        {
            get
            {
                return NtSecurity.GetIntegrityLevel(Sid);
            }
            set
            {
                Sid = NtSecurity.GetIntegritySid(value);
            }
        }

        /// <summary>
        /// Convert ACE to a string.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"Mandatory Label - Flags {Flags} - Policy {Policy} - IntegrityLevel {IntegrityLevel}";
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
                        NtRtl.RtlGetAce(acl, i, out IntPtr ace).ToNtException();
                        reader.BaseStream.Position = ace.ToInt64() - acl.ToInt64();
                        Add(Ace.CreateAceFromReader(reader));
                    }
                }
            }
            Revision = GetAclInformation<AclRevisionInformation>(acl, AclInformationClass.AclRevisionInformation).AclRevision;
        }

        private void InitializeFromPointer(IntPtr acl, bool defaulted)
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
        /// Constructor
        /// </summary>
        /// <param name="acl">Pointer to a raw ACL in memory</param>
        /// <param name="defaulted">True if the ACL was defaulted</param>
        public Acl(IntPtr acl, bool defaulted)
        {
            InitializeFromPointer(acl, defaulted);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="acl">Buffer containing an ACL in memory</param>
        /// <param name="defaulted">True if the ACL was defaulted</param>
        public Acl(byte[] acl, bool defaulted)
        {
            using (var buffer = new SafeHGlobalBuffer(acl))
            {
                InitializeFromPointer(buffer.DangerousGetHandle(), defaulted);
            }
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
                if ((ace.Flags & AceFlags.Inherited) == AceFlags.Inherited)
                {
                    inherited.Add(ace);
                }
                else
                {
                    switch (ace.Type)
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

        /// <summary>
        /// Indicates the ACL has at least one conditional ACE.
        /// </summary>
        public bool HasConditionalAce
        {
            get
            {
                foreach (var ace in this)
                {
                    if (ace.IsConditionalAce)
                    {
                        return true;
                    }
                }
                return false;
            }
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
                if (!LookupAccountSid(null, sid_buffer, name, ref length, domain, ref domain_length, out SidNameUse name_use))
                {
                    return null;
                }

                if (domain_length == 0)
                {
                    return name.ToString();
                }
                else
                {
                    return $@"{domain}\{name}";
                }
            }
        }

        private static Dictionary<Sid, string> _known_capabilities = null;

        private static string[] _known_capability_names = {
                "ID_CAP_ACCESSIBILITY_CLIENT",
                "ID_CAP_ACCESS_FAMILY_NOTES_API",
                "ID_CAP_ACCESS_REMINDER_IMAGES",
                "ID_CAP_ACC_MGR_ADMIN",
                "ID_CAP_ADAPTIVE_BRIGHTNESS_CONTROL",
                "ID_CAP_ADVERTISING_CONFIG",
                "ID_CAP_AIS_TOKEN_MANAGER",
                "ID_CAP_APPCONTAINER_PACKAGE_CERTIFICATES",
                "ID_CAP_APPOINTMENTS",
                "ID_CAP_APPPREINSTALL_DIRECTORY",
                "ID_CAP_APPPREINSTALL_EVENTS",
                "ID_CAP_APPRESOLVER",
                "ID_CAP_APPX_EXECUTION",
                "ID_CAP_APP_STORE_PURCHASE_HISTORY",
                "ID_CAP_AUDIO_EVENTSND",
                "ID_CAP_AUDIO_INTERNAL",
                "ID_CAP_AUDIO_ROUTING_CONTROLLER",
                "ID_CAP_AUDIO_SETTINGS",
                "ID_CAP_AUTHHOST",
                "ID_CAP_BACKGROUND_EXECUTION_MANAGEMENT",
                "ID_CAP_BACKGROUND_SETTINGS_MANAGEMENT",
                "ID_CAP_BACKGROUND_WORKER",
                "ID_CAP_BACKUPROAMRESTORE",
                "ID_CAP_BASEOS_UPDATEAPI",
                "ID_CAP_BINGCLIENT_BINGCONFIGURATION",
                "ID_CAP_BINGCLIENT_CA_INTERESTEXTRACTION",
                "ID_CAP_BINGCLIENT_DDC",
                "ID_CAP_BINGCLIENT_IDENTITY",
                "ID_CAP_BINGCLIENT_OSS",
                "ID_CAP_BINGCLIENT_SUGGESTSHIGHLIGHTS",
                "ID_CAP_BINGCLIENT_TEE",
                "ID_CAP_BLUETOOTH",
                "ID_CAP_BLUETOOTH_ADMIN",
                "ID_CAP_BMR2_MONITOR_SERVICE",
                "ID_CAP_BMR_CONFIGURATION",
                "ID_CAP_BMR_SYNC",
                "ID_CAP_BROKER_NAVIGATION",
                "ID_CAP_BROWSER_ACCESSIBILITY_SETTINGS",
                "ID_CAP_BROWSER_FEATURE_CONTROL_KEYS",
                "ID_CAP_BSS_AIM_INTERFACE",
                "ID_CAP_BSS_NABSYNC_INTERFACE",
                "ID_CAP_BSS_PUSH_INTERFACE",
                "ID_CAP_BSS_REMINDER_INTERFACE",
                "ID_CAP_BUILTIN_BASEPRIORITY",
                "ID_CAP_BUILTIN_CREATEGLOBAL",
                "ID_CAP_BUILTIN_CREATEPERMANENT",
                "ID_CAP_BUILTIN_DEFAULT",
                "ID_CAP_BUILTIN_IMPERSONATE",
                "ID_CAP_BUILTIN_PROFILE",
                "ID_CAP_BUILTIN_SETTIME",
                "ID_CAP_BUILTIN_SHUTDOWN",
                "ID_CAP_BUILTIN_SYMBOLICLINK",
                "ID_CAP_BUILTIN_TCB",
                "ID_CAP_BUTTONS",
                "ID_CAP_CALLMESSAGING_FILTER",
                "ID_CAP_CAMERA",
                "ID_CAP_CA_ACTIONURI_TEST_EVENT",
                "ID_CAP_CA_ADMIN",
                "ID_CAP_CA_BACKGROUND_PROCESSOR",
                "ID_CAP_CA_BACKGROUND_PROCESSOR_ADMIN",
                "ID_CAP_CA_CONTEXT",
                "ID_CAP_CA_DND_MANAGER",
                "ID_CAP_CA_ENABLED",
                "ID_CAP_CA_HISTORY",
                "ID_CAP_CA_RULES",
                "ID_CAP_CA_SIGNALS_GENERIC",
                "ID_CAP_CA_SIGNALS_MANAGER",
                "ID_CAP_CA_SIGNALS_MANAGER_ADMIN",
                "ID_CAP_CA_UPLOAD_FOLDER",
                "ID_CAP_CELLUX_CONFIG_READ",
                "ID_CAP_CELL_API_ADMIN",
                "ID_CAP_CELL_API_COMMON",
                "ID_CAP_CELL_API_LOCATION",
                "ID_CAP_CELL_API_MESSAGING",
                "ID_CAP_CELL_API_MODEMLOGGING",
                "ID_CAP_CELL_API_OEM_PASSTHROUGH",
                "ID_CAP_CELL_API_TELEPHONY",
                "ID_CAP_CELL_API_UICC",
                "ID_CAP_CELL_API_UICC_LOWLEVEL",
                "ID_CAP_CELL_CELLMGR",
                "ID_CAP_CELL_CMCSPWWAN_PLUS",
                "ID_CAP_CELL_MSFT_UICC_DATASTORE",
                "ID_CAP_CELL_OEM_UICC_DATASTORE",
                "ID_CAP_CELL_RCSPRESENCE",
                "ID_CAP_CELL_VIDEOTELEPHONY",
                "ID_CAP_CELL_WNF",
                "ID_CAP_CELL_WNF_ADMIN",
                "ID_CAP_CELL_WNF_PII",
                "ID_CAP_CHAMBER_PROFILE_CODE_INSTALLTEMP_RWD",
                "ID_CAP_CHAMBER_PROFILE_CODE_NITEMP_RW",
                "ID_CAP_CHAMBER_PROFILE_CODE_R",
                "ID_CAP_CHAMBER_PROFILE_CODE_RW",
                "ID_CAP_CHAMBER_PROFILE_DATA_LIVETILES_RWD",
                "ID_CAP_CHAMBER_PROFILE_DATA_MEDIA_RWD",
                "ID_CAP_CHAMBER_PROFILE_DATA_PLATFORMDATA_ALL",
                "ID_CAP_CHAMBER_PROFILE_DATA_R",
                "ID_CAP_CHAMBER_PROFILE_DATA_RW",
                "ID_CAP_CHAMBER_PROFILE_DATA_SHELLCONTENT_R",
                "ID_CAP_CHAMBER_PROFILE_DATA_SHELLCONTENT_RWD",
                "ID_CAP_CLIPBOARD",
                "ID_CAP_COMMANDCHANNEL",
                "ID_CAP_COMMS_APPLICATIONS",
                "ID_CAP_COMMS_COMMON",
                "ID_CAP_COMMS_SERVICES",
                "ID_CAP_COMMS_SETTINGS",
                "ID_CAP_CONTACTS",
                "ID_CAP_CONTENTSHARING",
                "ID_CAP_CORTANA_RULES_DB",
                "ID_CAP_CREATE_PROCESS_IN_CHAMBER",
                "ID_CAP_CREDENTIAL_COLLECTION_UI",
                "ID_CAP_CRITICAL_DATA",
                "ID_CAP_CSP_BMR_PROVISION",
                "ID_CAP_CSP_DMCLIENT",
                "ID_CAP_CSP_FOUNDATION",
                "ID_CAP_CSP_LOCATION",
                "ID_CAP_CSP_MAIL",
                "ID_CAP_CSP_NODECACHE",
                "ID_CAP_CSP_OEM",
                "ID_CAP_CSP_PHONE",
                "ID_CAP_CSP_W4_APPLICATION",
                "ID_CAP_CSP_WIFI_HOTSPOT",
                "ID_CAP_DATACOLLECTION_ACTIVITY",
                "ID_CAP_DATACOLLECTION_COLLECTOR",
                "ID_CAP_DATACOLLECTION_RAWETW",
                "ID_CAP_DATAPLANUSAGE",
                "ID_CAP_DATAPLANUSAGE_ADMIN",
                "ID_CAP_DCP",
                "ID_CAP_DEBUG",
                "ID_CAP_DEBUG_FOLDERS",
                "ID_CAP_DEBUG_NAVIGATION",
                "ID_CAP_DEVELOPERUNLOCK",
                "ID_CAP_DEVELOPERUNLOCK_API",
                "ID_CAP_DEVELOPERUNLOCK_CODEDUI",
                "ID_CAP_DEVICE_LOCK",
                "ID_CAP_DEVICE_LOCK_ADMIN",
                "ID_CAP_DEVICE_MANAGEMENT",
                "ID_CAP_DEVICE_MANAGEMENT_ADMIN",
                "ID_CAP_DEVICE_MANAGEMENT_BOOTSTRAP",
                "ID_CAP_DEVICE_MANAGEMENT_SECURITY_POLICIES",
                "ID_CAP_DIAGNOSTIC_CLIENT",
                "ID_CAP_DISPLAY_CONTROL",
                "ID_CAP_DMCLIENT_APPMGMT",
                "ID_CAP_DO_NOT_DISTURB",
                "ID_CAP_DRIVE_MODE_ADMIN",
                "ID_CAP_DUASVC",
                "ID_CAP_DU_AGENT",
                "ID_CAP_DU_CORE_API",
                "ID_CAP_DU_CSP",
                "ID_CAP_DU_MIGRATION_MANAGER_STATUS",
                "ID_CAP_DU_MIGRATION_WNF_EVENTS",
                "ID_CAP_DU_MIGRATOR_PROVISIONING_STATUS_MICROSOFT",
                "ID_CAP_DU_MIGRATOR_PROVISIONING_STATUS_OEM",
                "ID_CAP_DU_MIGRATOR_STATUS_MICROSOFT",
                "ID_CAP_DU_MIGRATOR_STATUS_OEM",
                "ID_CAP_DU_PROVISIONING",
                "ID_CAP_DU_SHARED_DATA",
                "ID_CAP_DU_USS",
                "ID_CAP_DU_UX",
                "ID_CAP_DU_UX_FEATURE_DISCOVERY",
                "ID_CAP_EAS_CREDENTIALS",
                "ID_CAP_EDM_CACHE_RWDELETE",
                "ID_CAP_EDM_CACHE_WRITE",
                "ID_CAP_ENDPOINTDISCOVERY",
                "ID_CAP_ENROLLMENT",
                "ID_CAP_ENROLLMENT_ADMIN",
                "ID_CAP_ENROLLMENT_POLL",
                "ID_CAP_ENROLLMENT_RENEW",
                "ID_CAP_ENTERPRISERESOURCESTORE",
                "ID_CAP_ENTERPRISE_AUTHENTICATION",
                "ID_CAP_ENTERPRISE_ENROLLMENT",
                "ID_CAP_ENTERPRISE_SERVICE",
                "ID_CAP_ENTERPRISE_SHARED_DATA",
                "ID_CAP_ETW_PROFILER",
                "ID_CAP_EVERYONE",
                "ID_CAP_EVERYONE_INROM",
                "ID_CAP_EXTERNAL_DISPLAY",
                "ID_CAP_FAILURE_REPORT_CONTENT_PROVIDER",
                "ID_CAP_FINDMYPHONE",
                "ID_CAP_FOREGROUND_TASK_MANAGER",
                "ID_CAP_GAMERSERVICES",
                "ID_CAP_GLOBALIZATION_SETTINGS",
                "ID_CAP_HTTP_ACCEPT_LANGUAGE_HEADER",
                "ID_CAP_ICS_RO",
                "ID_CAP_ICS_RW",
                "ID_CAP_IDENTITY_DEVICE",
                "ID_CAP_IDENTITY_DEVICE_1ST_PARTY",
                "ID_CAP_IDENTITY_USER",
                "ID_CAP_IDENTITY_USER_1ST_PARTY",
                "ID_CAP_IDM_IMAGE_CACHE",
                "ID_CAP_IMMERSIVE_SHELL",
                "ID_CAP_INPUT_CORE",
                "ID_CAP_INPUT_FEATURES",
                "ID_CAP_INPUT_INJECTION",
                "ID_CAP_INPUT_LOCALES",
                "ID_CAP_INPUT_SERVICE",
                "ID_CAP_INSTALL_CERTIFICATES",
                "ID_CAP_INTENTTEXTRACTION_OPTIN",
                "ID_CAP_INTERNAL_DEPLOYMENT",
                "ID_CAP_INTERNET_EXPLORER_BROWSER_HISTORY",
                "ID_CAP_INTERNET_EXPLORER_DATA_OPTIMIZATION",
                "ID_CAP_INTERNET_EXPLORER_FAVORITES",
                "ID_CAP_INTERNET_EXPLORER_HKCU_WRITE",
                "ID_CAP_INTERNET_EXPLORER_HKLM_SECURITY_SETTINGS",
                "ID_CAP_INTERNET_EXPLORER_INTRANET_ZONE_SETTINGS",
                "ID_CAP_INTERNET_EXPLORER_REMOTEDEBUGGING",
                "ID_CAP_INTERNET_EXPLORER_ROAMING",
                "ID_CAP_INTERNET_EXPLORER_SEARCH_PROVIDER_KEYS_HKCU",
                "ID_CAP_INTEROPSERVICES",
                "ID_CAP_ISV_CAMERA",
                "ID_CAP_KEYBOARD",
                "ID_CAP_KIDZONE_ADMIN",
                "ID_CAP_KIDZONE_CUSTOMIZATION",
                "ID_CAP_LANGUAGEUNDERSTANDING",
                "ID_CAP_LASS_ADMIN",
                "ID_CAP_LASS_REMOTELOCK",
                "ID_CAP_LEGACY_VOICEMAIL_HANDLER",
                "ID_CAP_LEXICONUPDATE",
                "ID_CAP_LIVEID",
                "ID_CAP_LIVETOKEN_WNF_EVENTS",
                "ID_CAP_LOCATION",
                "ID_CAP_LOCATION_ADMIN",
                "ID_CAP_LOCATION_BTPOLICY",
                "ID_CAP_LOCATION_GNSSDRIVER",
                "ID_CAP_MAP",
                "ID_CAP_MAP_ADMIN",
                "ID_CAP_MAP_WRITE",
                "ID_CAP_MEDIALIB",
                "ID_CAP_MEDIALIB_AUDIO",
                "ID_CAP_MEDIALIB_INT",
                "ID_CAP_MEDIALIB_PHOTO",
                "ID_CAP_MEDIALIB_PHOTO_FULL",
                "ID_CAP_MEDIALIB_PLAYBACK",
                "ID_CAP_MEDIALIB_VIDEO",
                "ID_CAP_MEDIASERVICE_VOLUMELIMIT_INT",
                "ID_CAP_MICMUTEPOLICY_BYPASS",
                "ID_CAP_MICROPHONE",
                "ID_CAP_MONITOR_NAVIGATION",
                "ID_CAP_MOUSE",
                "ID_CAP_MO_CLOUDMESSAGING",
                "ID_CAP_MSS_BYTESTREAM_RPC",
                "ID_CAP_MULTIMEDIA_ENCODER_HARDWARE",
                "ID_CAP_MULTIVARIANT",
                "ID_CAP_MULTIVARIANT_INSTALL_DATA",
                "ID_CAP_NARRATOR_SETTINGS",
                "ID_CAP_NATIVE_NETWORK_REPLACEMENT",
                "ID_CAP_NAVIGATIONBAR_ADMIN",
                "ID_CAP_NETWORKING",
                "ID_CAP_NETWORKING_ADMIN",
                "ID_CAP_NETWORKING_INTERNET_CLIENT",
                "ID_CAP_NETWORKING_INTERNET_CLIENT_SERVER",
                "ID_CAP_NETWORKING_PRIVATE_NETWORK_CLIENT_SERVER",
                "ID_CAP_NETWORKING_VPN_ADMIN",
                "ID_CAP_NETWORKING_VPN_PROVIDER",
                "ID_CAP_NETWORKING_VPN_SERVICES",
                "ID_CAP_NFC_ADMIN",
                "ID_CAP_NOCENTER_SOUNDS",
                "ID_CAP_NTSERVICES",
                "ID_CAP_NVREAD",
                "ID_CAP_NVREADWRITE",
                "ID_CAP_O365_DISCOVERY",
                "ID_CAP_OEMPUBLICDIRECTORY",
                "ID_CAP_OEM_ADC",
                "ID_CAP_OEM_CUSTOM",
                "ID_CAP_OEM_DEPLOYMENT",
                "ID_CAP_OFFICE_LAUNCH_URL",
                "ID_CAP_OFFICE_MSDRM_HKCU",
                "ID_CAP_ONENOTE_EVENTS",
                "ID_CAP_OOBE_PRIVATE",
                "ID_CAP_ORIENTATION_LOCK",
                "ID_CAP_PEOPLE_EXTENSION",
                "ID_CAP_PEOPLE_EXTENSION_IM",
                "ID_CAP_PEOPLE_EXTENSION_MOBILE",
                "ID_CAP_PERSONA",
                "ID_CAP_PERSONAL_INFORMATION_IMPORT",
                "ID_CAP_PHONEBROKER_INTERFACE",
                "ID_CAP_PHONEDIALER",
                "ID_CAP_PHONEPROVISIONER_DEVICEUPDATE",
                "ID_CAP_PHONEPROVISIONER_EVENTS",
                "ID_CAP_PHONE_2ND_PARTY",
                "ID_CAP_PHONE_ADMIN",
                "ID_CAP_PHONE_INTERNAL",
                "ID_CAP_PHOTOS_SETTINGS_R",
                "ID_CAP_PHOTOS_SETTINGS_RW",
                "ID_CAP_PICKER_CONTRACT_UI",
                "ID_CAP_PLATFORM_EXTENSIBILITY",
                "ID_CAP_PLAYREADY",
                "ID_CAP_PLAYREADY_ADMIN",
                "ID_CAP_PM_1ST_PARTY",
                "ID_CAP_PM_BSS",
                "ID_CAP_PM_INSTALL",
                "ID_CAP_POIDATASTORE",
                "ID_CAP_POIDATASTORE_ADMIN",
                "ID_CAP_POLICY_MANAGER",
                "ID_CAP_POLICY_MANAGER_READONLY",
                "ID_CAP_POWERNOTIF_USER",
                "ID_CAP_PRESERVED_DATA",
                "ID_CAP_PRIV_ABOUTCPL",
                "ID_CAP_PRIV_ACCESSIBILITYCPL",
                "ID_CAP_PRIV_ACCESSORIESCPL",
                "ID_CAP_PRIV_ACCESSORYMGRSVC",
                "ID_CAP_PRIV_ACCOUNTPROVSVC",
                "ID_CAP_PRIV_ACTIONURIHOST",
                "ID_CAP_PRIV_ADVERTISINGIDCPL",
                "ID_CAP_PRIV_ALARMS",
                "ID_CAP_PRIV_APHCHECK",
                "ID_CAP_PRIV_APMUX",
                "ID_CAP_PRIV_APPCORNER",
                "ID_CAP_PRIV_APPPREINSTALLER",
                "ID_CAP_PRIV_APPRESOLVERUI",
                "ID_CAP_PRIV_APPSDATAMIGRATOR",
                "ID_CAP_PRIV_APPXEXECUTIONSVC",
                "ID_CAP_PRIV_AUTHHOST_MSA",
                "ID_CAP_PRIV_AUTHHOST_WAB_A",
                "ID_CAP_PRIV_AUTHHOST_WAB_B",
                "ID_CAP_PRIV_AUTHHOST_WAB_C",
                "ID_CAP_PRIV_AUTHHOST_WAB_ENTERPRISE",
                "ID_CAP_PRIV_AUTHHOST_WAB_SSO",
                "ID_CAP_PRIV_AUTHHOST_WAB_SSO_ENTERPRISE",
                "ID_CAP_PRIV_AUTOTIMEUPDATE",
                "ID_CAP_PRIV_BATTERYSAVERCPL",
                "ID_CAP_PRIV_BLUETOOTHPBAPSVC",
                "ID_CAP_PRIV_BMR2MONITORSVC",
                "ID_CAP_PRIV_BMR2SCHEDULETRIGGER",
                "ID_CAP_PRIV_BMRCPL",
                "ID_CAP_PRIV_BMRSCHEDULETRIGGER",
                "ID_CAP_PRIV_BRIGHTNESSCPL",
                "ID_CAP_PRIV_BSSVC",
                "ID_CAP_PRIV_BTAGSERVICE",
                "ID_CAP_PRIV_BTCONNMGR",
                "ID_CAP_PRIV_BTHAVCTPSVC",
                "ID_CAP_PRIV_BTSERV",
                "ID_CAP_PRIV_BTUXCPL",
                "ID_CAP_PRIV_CALC7",
                "ID_CAP_PRIV_CAPTURESVC",
                "ID_CAP_PRIV_CASVCSHARED3",
                "ID_CAP_PRIV_CELLMANAGER",
                "ID_CAP_PRIV_CELLULARDATACOLLECTOR",
                "ID_CAP_PRIV_CELLUX",
                "ID_CAP_PRIV_CERTINSTALLER",
                "ID_CAP_PRIV_CFMSVC",
                "ID_CAP_PRIV_CGSVC",
                "ID_CAP_PRIV_CLOUDSTORAGECPL",
                "ID_CAP_PRIV_CMSERVICE",
                "ID_CAP_PRIV_COMMANDCHANNEL",
                "ID_CAP_PRIV_COMMSAPHOST",
                "ID_CAP_PRIV_COMMSAPPLICATIONS",
                "ID_CAP_PRIV_COMMSCERTINSTSVC",
                "ID_CAP_PRIV_COMMSMESSAGESVC",
                "ID_CAP_PRIV_COMMSMMSTRANSPORT",
                "ID_CAP_PRIV_CONTACTSTOKENSVC",
                "ID_CAP_PRIV_CONTENTSHARESVC",
                "ID_CAP_PRIV_CONTENTSHARINGAPP",
                "ID_CAP_PRIV_COREUIREGISTRAR",
                "ID_CAP_PRIV_DACCERTINSTSVC",
                "ID_CAP_PRIV_DATACOLLECTION",
                "ID_CAP_PRIV_DATASENSESVC",
                "ID_CAP_PRIV_DATASMART",
                "ID_CAP_PRIV_DATETIMECPL",
                "ID_CAP_PRIV_DCPSVC",
                "ID_CAP_PRIV_DEBUGGERMUXNOTIFY",
                "ID_CAP_PRIV_DIAGNOSTICSVC",
                "ID_CAP_PRIV_DMCFGHOST",
                "ID_CAP_PRIV_DMOMACPNETWMO",
                "ID_CAP_PRIV_DMOMACPUSERMO",
                "ID_CAP_PRIV_DMWAPPUSHSVC",
                "ID_CAP_PRIV_DRIVINGMODEMANAGER",
                "ID_CAP_PRIV_DRIVINGMODESETTINGS",
                "ID_CAP_PRIV_DSSVC",
                "ID_CAP_PRIV_DSTOKENCLEAN",
                "ID_CAP_PRIV_DUACALLBACK",
                "ID_CAP_PRIV_DUACLIENT",
                "ID_CAP_PRIV_DUCLEANUPMIGRATOR",
                "ID_CAP_PRIV_DUFEATUREDISCOVERY",
                "ID_CAP_PRIV_DUMIGRATIONMANAGER",
                "ID_CAP_PRIV_DUMIGRATIONPROVISIONERMICROSOFT",
                "ID_CAP_PRIV_DUMIGRATIONPROVISIONEROEM",
                "ID_CAP_PRIV_DUPOSTUPDATEUX",
                "ID_CAP_PRIV_DUSTARTINGMIGRATOR",
                "ID_CAP_PRIV_DUSVC",
                "ID_CAP_PRIV_ENROLLMENTCLIENT",
                "ID_CAP_PRIV_ENTAPPSERVICE",
                "ID_CAP_PRIV_ENTERPRISEINSTALL",
                "ID_CAP_PRIV_ENTERPRISEMGMSVC",
                "ID_CAP_PRIV_ENTERPRISERING",
                "ID_CAP_PRIV_ENTERPRISEVALIDATION",
                "ID_CAP_PRIV_EXECMANSERVICE",
                "ID_CAP_PRIV_FINDMYPHONE",
                "ID_CAP_PRIV_FLYOUTDATAMIGRATOR",
                "ID_CAP_PRIV_GROVELER",
                "ID_CAP_PRIV_GWPCENROLLSVC",
                "ID_CAP_PRIV_HFA",
                "ID_CAP_PRIV_HOTSPOTHOST",
                "ID_CAP_PRIV_HUBTILERESTOREHOST",
                "ID_CAP_PRIV_ICSENTITLEMENTHOST",
                "ID_CAP_PRIV_ICSSVC",
                "ID_CAP_PRIV_INPUTSERVICE",
                "ID_CAP_PRIV_INSTALLERWORKER",
                "ID_CAP_PRIV_INTERNETEXPLORER",
                "ID_CAP_PRIV_IPOVERUSB",
                "ID_CAP_PRIV_KEYBOARDCPL",
                "ID_CAP_PRIV_KIDZONECONFIGURATION",
                "ID_CAP_PRIV_KIDZONECUSTOMIZATION",
                "ID_CAP_PRIV_LASSCREDENTIALEXPIRATIONCHECK",
                "ID_CAP_PRIV_LAUNCHAPPSVC",
                "ID_CAP_PRIV_LEXICONUPDATE",
                "ID_CAP_PRIV_LFSVC",
                "ID_CAP_PRIV_LIVETOKEN",
                "ID_CAP_PRIV_LOCATIONUXCPL",
                "ID_CAP_PRIV_LOCKANDWALLPAPER",
                "ID_CAP_PRIV_MEDIA",
                "ID_CAP_PRIV_MEDIASERVICE",
                "ID_CAP_PRIV_MIRRORCPL",
                "ID_CAP_PRIV_MOBILEUI",
                "ID_CAP_PRIV_MOSHOST",
                "ID_CAP_PRIV_MSATICKETSVC",
                "ID_CAP_PRIV_MSGIMTRANSPORT",
                "ID_CAP_PRIV_MSGSMSTRANSPORT",
                "ID_CAP_PRIV_MTP",
                "ID_CAP_PRIV_MVPROVISIONHOST",
                "ID_CAP_PRIV_MVUX",
                "ID_CAP_PRIV_NABSYNC",
                "ID_CAP_PRIV_NOCENTERSETTINGSCPL",
                "ID_CAP_PRIV_NOTIFICATIONPLATFORMMIGRATOR",
                "ID_CAP_PRIV_NOTIFSVC",
                "ID_CAP_PRIV_OFFICE",
                "ID_CAP_PRIV_OMADMCLIENT_ENTERPRISE",
                "ID_CAP_PRIV_OMADMCLIENT_MOBILE_OPERATOR",
                "ID_CAP_PRIV_OMADMPRC",
                "ID_CAP_PRIV_OOBE",
                "ID_CAP_PRIV_ORIENTSRV",
                "ID_CAP_PRIV_PACMANSERVICE",
                "ID_CAP_PRIV_PHONEAUDIOSRV",
                "ID_CAP_PRIV_PHONEPROVISIONER",
                "ID_CAP_PRIV_PHONEPROVISIONER_OEM",
                "ID_CAP_PRIV_PHONESVCSG",
                "ID_CAP_PRIV_PHOTOS",
                "ID_CAP_PRIV_PHOTOSSVC",
                "ID_CAP_PRIV_PIMIDXMAINT",
                "ID_CAP_PRIV_PLACESSVC",
                "ID_CAP_PRIV_POSTDUAPPMIGRATOR",
                "ID_CAP_PRIV_POWERNOTIF",
                "ID_CAP_PRIV_PROXIMITYSVC",
                "ID_CAP_PRIV_PROXYSVC",
                "ID_CAP_PRIV_REALWORLD-BINGCLIENT",
                "ID_CAP_PRIV_REALWORLD-INTERESTEXTRACTION",
                "ID_CAP_PRIV_REBOOTDEVICE",
                "ID_CAP_PRIV_REGIONCPL",
                "ID_CAP_PRIV_REMEMBER",
                "ID_CAP_PRIV_RETAILDEMO",
                "ID_CAP_PRIV_RETAILDEMOERROR",
                "ID_CAP_PRIV_RETAILDEMOGLOB",
                "ID_CAP_PRIV_RETAILDEMOUI",
                "ID_CAP_PRIV_RILADAPTATION",
                "ID_CAP_PRIV_RINGTONESANDSOUNDS",
                "ID_CAP_PRIV_ROAMINGCPL",
                "ID_CAP_PRIV_ROTATIONLOCKCPL",
                "ID_CAP_PRIV_SAPISVR",
                "ID_CAP_PRIV_SECMIGRATOR",
                "ID_CAP_PRIV_SEMGRSVC",
                "ID_CAP_PRIV_SETTINGS",
                "ID_CAP_PRIV_SHELLDATAMIGRATOR",
                "ID_CAP_PRIV_SIREPSVC",
                "ID_CAP_PRIV_SOFTAPUX",
                "ID_CAP_PRIV_SPEECHCPL",
                "ID_CAP_PRIV_SPEECHUPDATE",
                "ID_CAP_PRIV_START",
                "ID_CAP_PRIV_STORAGESENSE",
                "ID_CAP_PRIV_STORAGESVC",
                "ID_CAP_PRIV_STOREDATAMIGRATOR",
                "ID_CAP_PRIV_TASKSCHEDULERSVC",
                "ID_CAP_PRIV_TELCPL",
                "ID_CAP_PRIV_TELREPSVC",
                "ID_CAP_PRIV_THEMECPL",
                "ID_CAP_PRIV_TILEMIGRATOR",
                "ID_CAP_PRIV_TIMEBROKER",
                "ID_CAP_PRIV_UPDATEMGRSVC",
                "ID_CAP_PRIV_USBCPL",
                "ID_CAP_PRIV_USERDATASERVICE",
                "ID_CAP_PRIV_USSREPORTING",
                "ID_CAP_PRIV_UTKSERVICE",
                "ID_CAP_PRIV_UTKUX",
                "ID_CAP_PRIV_VPNUX",
                "ID_CAP_PRIV_WALLET",
                "ID_CAP_PRIV_WALLETSVC",
                "ID_CAP_PRIV_WEHCSPHELPER",
                "ID_CAP_PRIV_WEHSTART",
                "ID_CAP_PRIV_WIFICONNSVC",
                "ID_CAP_PRIV_WIFICPASSIST",
                "ID_CAP_PRIV_WIFICPBROWSERUX",
                "ID_CAP_PRIV_WIFIUDPTEST",
                "ID_CAP_PRIV_WIFIUXBLUE",
                "ID_CAP_PRIV_WLID2MSA",
                "ID_CAP_PRIV_WPABSVC",
                "ID_CAP_PRIV_WPNARRATOR",
                "ID_CAP_PRIV_WPNCERTINSTSVC",
                "ID_CAP_PRIV_WPTOOLS",
                "ID_CAP_PRIV_WPTPMVSCMGRSVC",
                "ID_CAP_PRIV_WPUITESTTOOLS",
                "ID_CAP_PRIV_ZMEDIAQUEUESVC",
                "ID_CAP_PRIV_ZMF",
                "ID_CAP_PRIV_ZMF_SERVICE",
                "ID_CAP_PROVISIONWPCERTIFICATE",
                "ID_CAP_PROXIMITY",
                "ID_CAP_PUBLIC_FOLDER_FULL",
                "ID_CAP_PUBLISH_ALARM_STATE",
                "ID_CAP_PUBLISH_OOBE_STATE",
                "ID_CAP_PUSHROUTER",
                "ID_CAP_PUSH_NOTIFICATION",
                "ID_CAP_PUSH_SERVER",
                "ID_CAP_QUICK_SETTINGS",
                "ID_CAP_READGWPCERTIFICATE",
                "ID_CAP_REBOOT_FLASHING_MODE",
                "ID_CAP_REMEMBER_ADMIN",
                "ID_CAP_REMEMBER_API",
                "ID_CAP_REMOVABLE_STORAGE",
                "ID_CAP_RESET_PHONE",
                "ID_CAP_RESOURCE_MANAGER",
                "ID_CAP_RETAILDEMO_BACKGROUNDIMAGE",
                "ID_CAP_RETAILDEMO_CLIENT",
                "ID_CAP_RETAILDEMO_GLOB_REGISTRY",
                "ID_CAP_RETAILDEMO_OFFLINECONTENT",
                "ID_CAP_RINGTONE_ADD",
                "ID_CAP_ROAMING_CONFIGURATION",
                "ID_CAP_ROTATION_MANAGER",
                "ID_CAP_RUNTIME_CONFIG",
                "ID_CAP_SCREENCAPTURE",
                "ID_CAP_SCREEN_RECORDER",
                "ID_CAP_SCREEN_RECORDER_BKG",
                "ID_CAP_SEARCHMAPS_SHAREDCONFIG",
                "ID_CAP_SEND_TO_ONENOTE",
                "ID_CAP_SENSORS",
                "ID_CAP_SETDEVICENAME",
                "ID_CAP_SETTINGSYNC",
                "ID_CAP_SETTINGSYNC_CONFIGURATION",
                "ID_CAP_SETTINGS_MANAGEMENT_PROVIDER",
                "ID_CAP_SHARED_OBJECT_DIRECTORY",
                "ID_CAP_SHARED_USER_CERTIFICATES",
                "ID_CAP_SHARE_DELEGATE",
                "ID_CAP_SHELL_DEVICE_LOCK_UI_API",
                "ID_CAP_SHELL_LAUNCH_SESSION",
                "ID_CAP_SHELL_NAVIGATION",
                "ID_CAP_SHELL_NOTIFICATION_CLIENT",
                "ID_CAP_SHELL_OEM_ADMIN",
                "ID_CAP_SHELL_RESET_NAVIGATION",
                "ID_CAP_SHELL_TEST_CLIENT",
                "ID_CAP_SHOW_VOLUME_CONTROL",
                "ID_CAP_SMS",
                "ID_CAP_SMS_COMPANION",
                "ID_CAP_SMS_INTERCEPT_AGENT",
                "ID_CAP_SMS_INTERCEPT_RECIPIENT",
                "ID_CAP_SOUND_CONTROL",
                "ID_CAP_SPEECH_GRAMMARS",
                "ID_CAP_SPEECH_RECOGNITION",
                "ID_CAP_SPEECH_RECOGNITION_SYSTEM",
                "ID_CAP_SPEECH_SETTINGS",
                "ID_CAP_SPEECH_UPDATE",
                "ID_CAP_SPLASH_CONFIG",
                "ID_CAP_STARTMENU_CONFIG",
                "ID_CAP_STORAGE_MANAGEMENT",
                "ID_CAP_SUPPRESS_MSA_CONNECT_ARD",
                "ID_CAP_SYNC_EXTENSION",
                "ID_CAP_SYSTEMTRAY_ADMIN",
                "ID_CAP_SYSTEM_ALLOC_WINDOWID",
                "ID_CAP_SYSTEM_COMPOSITOR",
                "ID_CAP_SYSTEM_COUNTERS",
                "ID_CAP_SYSTEM_REGISTRAR",
                "ID_CAP_SYSTEM_WAITCURSOR",
                "ID_CAP_TELEMETRY_ADMIN",
                "ID_CAP_TELEMETRY_CONFIGURE",
                "ID_CAP_TELEMETRY_STUDY",
                "ID_CAP_TEST_NAVIGATION",
                "ID_CAP_TILERESTOREDATA",
                "ID_CAP_TOUCH",
                "ID_CAP_TOUCH_TEST",
                "ID_CAP_TPM_VSCMANAGER",
                "ID_CAP_TS_SCHEDULES_ALL",
                "ID_CAP_USB",
                "ID_CAP_USER_ACTIVITY",
                "ID_CAP_VIDEOSINK_INTERNAL",
                "ID_CAP_VOICEMAIL",
                "ID_CAP_VOIP",
                "ID_CAP_VOIP_CALL_CONTROLLER",
                "ID_CAP_VSTEST_INSTALL_FOLDER",
                "ID_CAP_W32TIME_API",
                "ID_CAP_WAB_RESOURCES",
                "ID_CAP_WALLET",
                "ID_CAP_WALLET_ADMIN",
                "ID_CAP_WALLET_DEALS",
                "ID_CAP_WALLET_PAYMENTINSTRUMENTS",
                "ID_CAP_WALLET_SECUREELEMENT",
                "ID_CAP_WALLPAPER_ADMIN",
                "ID_CAP_WBOEXT",
                "ID_CAP_WEBBROWSERCOMPONENT",
                "ID_CAP_WEB_CREDENTIALS",
                "ID_CAP_WIFI_ADMIN",
                "ID_CAP_WIFI_BASIC",
                "ID_CAP_WIFI_BROWSER",
                "ID_CAP_WIFI_HOTSPOT_HOST",
                "ID_CAP_WIFI_PROFILE_ADMIN",
                "ID_CAP_WIFI_TILE_MANAGER",
                "ID_CAP_WPN_PLATFORM",
                "ID_CAP_WPN_PLATFORM_REG_KEY",
                "ID_CAP_WPTOOLS_INSTALL_FOLDER",
                "ID_CAP_ZMFSERVICES",
                "ID_CAP_ZTRACE",
                "accessoryManager",
                "activateAsUser",
                "activitySystem",
                "allJoyn",
                "appBroadcast",
                "appBroadcastServices",
                "appBroadcastSettings",
                "appCaptureServices",
                "appCaptureSettings",
                "appLicensing",
                "applicationDefaults",
                "applicationViewActivation",
                "appointments",
                "appointmentsSystem",
                "audioDeviceConfiguration",
                "backgroundMediaPlayback",
                "biometricSystem",
                "blockedChatMessages",
                "broadFileSystemAccess",
                "cellularDeviceControl",
                "cellularDeviceIdentity",
                "cellularMessaging",
                "chat",
                "chatSystem",
                "childWebContent",
                "cloudExperienceHost",
                "cloudStore",
                "codeGeneration",
                "confirmAppClose",
                "constrainedImpersonation",
                "contacts",
                "contactsSystem",
                "contentDeliveryManagerSettings",
                "contentRestrictions",
                "coreShell",
                "cortanaPermissions",
                "cortanaSettings",
                "cortanaSpeechAccessory",
                "curatedTileCollections",
                "developerSettings",
                "developmentModeNetwork",
                "deviceManagementAdministrator",
                "deviceManagementDeviceLockPolicies",
                "deviceManagementDmAccount",
                "deviceManagementEmailAccount",
                "deviceManagementFoundation",
                "deviceManagementWapSecurityPolicies",
                "deviceUnlock",
                "documentsLibrary",
                "dualSimTiles",
                "email",
                "emailSystem",
                "enterpriseAuthentication",
                "enterpriseDataPolicy",
                "enterpriseDeviceLockdown",
                "eraApplication",
                "exclusiveResource",
                "extendedExecutionBackgroundAudio",
                "extendedExecutionCritical",
                "extendedExecutionUnconstrained",
                "featureStagingInfo",
                "feedbackLogCollection",
                "firstSignInSettings",
                "flashPlayerSupport",
                "gameBarServices",
                "gameConfigStoreManagement",
                "gameList",
                "hevcPlayback",
                "hfxSystem",
                "hidTelephony",
                "holographicCompositor",
                "holographicCompositorSystem",
                "indexedContent",
                "inputForegroundObservation",
                "inputInjection",
                "inputInjectionBrokered",
                "inputObservation",
                "inputSuppression",
                "internetClient",
                "internetClientServer",
                "interopServices",
                "kinectAudio",
                "kinectGamechat",
                "liveIdService",
                "locationHistory",
                "locationSystem",
                "lockScreenCreatives",
                "lowLevelDevices",
                "lpacAppExperience",
                "lpacClipboard",
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
                "multiplaneOverlay",
                "muma",
                "musicLibrary",
                "networkConnectionManagerProvisioning",
                "networkDataPlanProvisioning",
                "networkDiagnostics",
                "networkingVpnProvider",
                "objects3D",
                "oemDeployment",
                "oemPublicDirectory",
                "offlineMapsManagement",
                "packageContents",
                "packageManagement",
                "packagePolicySystem",
                "packageQuery",
                "perceptionMonitoring",
                "perceptionSystem",
                "phoneCall",
                "phoneCallHistory",
                "phoneCallHistoryPublic",
                "phoneCallHistorySystem",
                "picturesLibrary",
                "previewHfx",
                "previewPenWorkspace",
                "previewStore",
                "previewUiComposition",
                "privateNetworkClientServer",
                "recordedCallsFolder",
                "registryRead",
                "relatedPackages",
                "remotePassportAuthentication",
                "remoteSystem",
                "removableStorage",
                "runFullTrust",
                "screenDuplication",
                "secondaryAuthenticationFactor",
                "secureAssessment",
                "sessionImpersonation",
                "settingSyncConfiguration",
                "sharedUserCertificates",
                "shellExperience",
                "shellExperienceComposer",
                "slapiQueryLicenseValue",
                "smsSend",
                "smsSystem",
                "spatialPerception",
                "startScreenManagement",
                "storeAppInstall",
                "storeAppInstallation",
                "storeConfiguration",
                "storeLicenseManagement",
                "systemManagement",
                "systemRegistrar",
                "targetedContent",
                "targetedContentSubscription",
                "teamEditionExperience",
                "uiAutomationSystem",
                "unzipFile",
                "userAccountInformation",
                "userDataAccountSetup",
                "userDataAccountsProvider",
                "userDataSystem",
                "userDataTasks",
                "userDataTasksSystem",
                "userNotificationListener",
                "userPrincipalName",
                "userSigninSupport",
                "userSystemId",
                "userWebAccounts",
                "videosLibrary",
                "visualElementsSystem",
                "visualVoiceMail",
                "voipCall",
                "walletSystem",
                "windowsHelloCredentialAccess",
                "xboxAccessoryManagement",
                "xboxBroadcaster",
                "xboxGameSpeechWindow",
                "xboxLiveAuthenticationProvider",
                "xboxSystemApplicationClipQuery",
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
                        GetCapabilitySids(name, out Sid capability_sid, out Sid capability_group_sid);
                        known_capabilities.Add(capability_sid, name);
                        known_capabilities.Add(capability_group_sid, name);
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
            if (!LookupAccountName(null, username, SafeHGlobalBuffer.Null, ref sid_length,
                SafeHGlobalBuffer.Null, ref domain_length, out SidNameUse name))
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

        /// <summary>
        /// Lookup the name of a process trust SID.
        /// </summary>
        /// <param name="trust_sid">The trust sid to lookup.</param>
        /// <returns>The name of the trust sid. null if not found.</returns>
        /// <exception cref="ArgumentException">Thrown if trust_sid is not a trust sid.</exception>
        public static string LookupProcessTrustName(Sid trust_sid)
        {
            if (!IsProcessTrustSid(trust_sid))
            {
                throw new ArgumentException("Must pass a process trust sid to lookup", "trust_sid");
            }

            if (trust_sid.SubAuthorities.Count != 2)
            {
                return null;
            }

            string protection_type;
            switch (trust_sid.SubAuthorities[0])
            {
                case 0:
                    protection_type = "None";
                    break;
                case 512:
                    protection_type = "ProtectedLight";
                    break;
                case 1024:
                    protection_type = "Protected";
                    break;
                default:
                    protection_type = $"Protected-{trust_sid.SubAuthorities[0]}";
                    break;
            }

            string protection_level;
            switch (trust_sid.SubAuthorities[1])
            {
                case 0:
                    protection_level = "None";
                    break;
                case 1024:
                    protection_level = "Authenticode";
                    break;
                case 1536:
                    protection_level = "AntiMalware";
                    break;
                case 2048:
                    protection_level = "App";
                    break;
                case 4096:
                    protection_level = "Windows";
                    break;
                case 8192:
                    protection_level = "WinTcb";
                    break;
                default:
                    protection_level = trust_sid.SubAuthorities[1].ToString();
                    break;
            }

            return $"{protection_type}-{protection_level}";
        }

        private static string ReadMoniker(NtKey rootkey, Sid sid)
        {
            PackageSidType sid_type = GetPackageSidType(sid);
            Sid child_sid = null;
            if (sid_type == PackageSidType.Child)
            {
                child_sid = sid;
                sid = GetPackageSidParent(sid);
            }

            string path = $@"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\{sid}";
            if (child_sid != null)
            {
                path = $@"{path}\Children\{child_sid}";
            }

            using (ObjectAttributes obj_attr = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, rootkey))
            {
                using (var key = NtKey.Open(obj_attr, KeyAccessRights.QueryValue, KeyCreateOptions.NonVolatile, false))
                {
                    if (key.IsSuccess)
                    {
                        var moniker = key.Result.QueryValue("Moniker", false);
                        if (!moniker.IsSuccess)
                        {
                            return null;
                        }

                        if (child_sid == null)
                        {
                            return moniker.Result.ToString().TrimEnd('\0');
                        }

                        var parent_moniker = key.Result.QueryValue("ParentMoniker", false);
                        string parent_moniker_string;
                        if (parent_moniker.IsSuccess)
                        {
                            parent_moniker_string = parent_moniker.Result.ToString();
                        }
                        else
                        {
                            parent_moniker_string = ReadMoniker(rootkey, sid) ?? String.Empty;
                        }

                        return $"{parent_moniker_string.TrimEnd('\0')}/{moniker.Result.ToString().TrimEnd('\0')}";
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
        public static string LookupPackageName(Sid sid)
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

        private static Dictionary<Sid, string> _device_capabilities;

        private static Sid GuidToCapabilitySid(Guid g)
        {
            byte[] guid_buffer = g.ToByteArray();
            List<uint> subauthorities = new List<uint>
            {
                3
            };
            for (int i = 0; i < 4; ++i)
            {
                subauthorities.Add(BitConverter.ToUInt32(guid_buffer, i * 4));
            }
            return new Sid(SecurityAuthority.Package, subauthorities.ToArray());
        }

        private static Dictionary<Sid, string> GetDeviceCapabilities()
        {
            if (_device_capabilities != null)
            {
                return _device_capabilities;
            }

            var device_capabilities = new Dictionary<Sid, string>();

            try
            {
                using (var base_key = NtKey.Open(@"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\CapabilityMappings", null, KeyAccessRights.EnumerateSubKeys))
                {
                    using (var key_list = base_key.QueryAccessibleKeys(KeyAccessRights.EnumerateSubKeys).ToDisposableList())
                    {
                        foreach (var key in key_list)
                        {
                            foreach (var guid in key.QueryKeys())
                            {
                                if (Guid.TryParse(guid, out Guid g))
                                {
                                    Sid sid = GuidToCapabilitySid(g);
                                    if (!device_capabilities.ContainsKey(sid))
                                    {
                                        device_capabilities[sid] = key.Name;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (NtException)
            {
            }
            
            _device_capabilities = device_capabilities;
            return _device_capabilities;
        }

        /// <summary>
        /// Lookup a device capability SID name if known.
        /// </summary>
        /// <param name="sid">The SID to lookup.</param>
        /// <returns>Returns the device capability name. If not found returns null.</returns>
        /// <exception cref="ArgumentException">Thrown if SID is not a package sid.</exception>
        public static string LookupDeviceCapabilityName(Sid sid)
        {
            if (!IsCapabilitySid(sid))
            {
                throw new ArgumentException("Sid not a capability sid", "sid");
            }

            var device_capabilities = GetDeviceCapabilities();
            if (device_capabilities.ContainsKey(sid))
            {
                return device_capabilities[sid];
            }
            return null;
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
            if (token.IsPseudoToken)
            {
                // This is a pseudo token, pass along as no need to duplicate.
                return token;
            }

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
                    using (var privs = new SafePrivilegeSetBuffer())
                    {
                        int buffer_length = privs.Length;

                        using (var self_sid = principal != null ? principal.ToSafeBuffer() : SafeSidBufferHandle.Null)
                        {
                            NtSystemCalls.NtAccessCheckByType(sd_buffer, self_sid, imp_token.Handle, access_rights,
                                SafeHGlobalBuffer.Null, 0, ref generic_mapping, privs,
                                ref buffer_length, out AccessMask granted_access, out NtStatus result_status).ToNtException();
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
            return GetAllowedAccess
                (sd, token, access_rights, null, generic_mapping);
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
        /// Checks if a SID is a process trust SID.
        /// </summary>
        /// <param name="sid">The sid to check.</param>
        /// <returns>True if a process trust sid.</returns>
        public static bool IsProcessTrustSid(Sid sid)
        {
            return sid.Authority.IsAuthority(SecurityAuthority.ProcessTrust);
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

        /// <summary>
        /// Checks if a SID is a capbility group SID.
        /// </summary>
        /// <param name="sid">The sid to check.</param>
        /// <returns>True if a capability group sid.</returns>
        public static bool IsCapabilityGroupSid(Sid sid)
        {
            return sid.Authority.IsAuthority(SecurityAuthority.Nt) && 
                sid.SubAuthorities.Count == 9 &&
                sid.SubAuthorities[0] == 32;
        }

        private static int GetSidSize(int rids)
        {
            return 8 + rids * 4;
        }

        private static void GetCapabilitySids(string capability_name, out Sid capability_sid, out Sid capability_group_sid)
        {
            using (SafeHGlobalBuffer cap_sid = new SafeHGlobalBuffer(GetSidSize(9)),
                    cap_group_sid = new SafeHGlobalBuffer(GetSidSize(10)))
            {
                NtRtl.RtlDeriveCapabilitySidsFromName(
                    new UnicodeString(capability_name),
                    cap_group_sid, cap_sid).ToNtException();
                capability_sid = new Sid(cap_sid);
                capability_group_sid = new Sid(cap_group_sid);
            }
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
        /// Get the parent package SID for a child package SID.
        /// </summary>
        /// <param name="sid">The child package SID.</param>
        /// <returns>The parent package SID.</returns>
        /// <exception cref="ArgumentException">Thrown if sid not a child package SID.</exception>
        public static Sid GetPackageSidParent(Sid sid)
        {
            if (GetPackageSidType(sid) != PackageSidType.Child)
            {
                throw new ArgumentException("Package sid not a child sid");
            }

            return new Sid(sid.Authority, sid.SubAuthorities.Take(8).ToArray());
        }

        private static Regex ConditionalAceRegex = new Regex(@"^D:\(XA;;;;;WD;\((.+)\)\)$");

        /// <summary>
        /// Converts conditional ACE data to an SDDL string
        /// </summary>
        /// <param name="conditional_data">The conditional application data.</param>
        /// <returns>The conditional ACE string.</returns>
        public static string ConditionalAceToString(byte[] conditional_data)
        {
            SecurityDescriptor sd = new SecurityDescriptor
            {
                Dacl = new Acl
                {
                    NullAcl = false
                }
            };
            sd.Dacl.Add(new Ace(AceType.AllowedCallback, AceFlags.None, 0, KnownSids.World) { ApplicationData = conditional_data });
            var matches = ConditionalAceRegex.Match(sd.ToSddl());

            if (!matches.Success || matches.Groups.Count != 2)
            {
                throw new ArgumentException("Invalid condition data");
            }
            return matches.Groups[1].Value;
        }

        /// <summary>
        /// Converts a condition in SDDL format to an ACE application data.
        /// </summary>
        /// <param name="condition_sddl">The condition in SDDL format.</param>
        /// <returns>The condition in ACE application data format.</returns>
        public static byte[] StringToConditionalAce(string condition_sddl)
        {
            SecurityDescriptor sd = new SecurityDescriptor($"D:(XA;;;;;WD;({condition_sddl}))");
            return sd.Dacl[0].ApplicationData;
        }

        /// <summary>
        /// Get the cached signing level for a file.
        /// </summary>
        /// <param name="handle">The handle to the file to query.</param>
        /// <returns>The cached signing level.</returns>
        public static CachedSigningLevel GetCachedSigningLevel(SafeKernelObjectHandle handle)
        {
            byte[] thumb_print = new byte[0x68];
            int thumb_print_size = thumb_print.Length;

            NtSystemCalls.NtGetCachedSigningLevel(handle, out int flags,
                out SigningLevel signing_level, thumb_print, ref thumb_print_size, out HashAlgorithm thumb_print_algo).ToNtException();
            Array.Resize(ref thumb_print, thumb_print_size);
            return new CachedSigningLevel(flags, signing_level, thumb_print, thumb_print_algo);
        }

        private static CachedSigningLevelEaBuffer ReadCachedSigningLevelVersion1(BinaryReader reader)
        {
            int version2 = reader.ReadInt16();
            int flags = reader.ReadInt32();
            int policy = reader.ReadInt32();
            long last_blacklist_time = reader.ReadInt64();
            int sequence = reader.ReadInt32();
            byte[] thumbprint = reader.ReadAllBytes(64);
            int thumbprint_size = reader.ReadInt32();
            Array.Resize(ref thumbprint, thumbprint_size);
            HashAlgorithm thumbprint_algo = (HashAlgorithm)reader.ReadInt32();
            byte[] hash = reader.ReadAllBytes(64);
            int hash_size = reader.ReadInt32();
            Array.Resize(ref hash, hash_size);
            HashAlgorithm hash_algo = (HashAlgorithm)reader.ReadInt32();
            long usn = reader.ReadInt64();
           
            return new CachedSigningLevelEaBuffer(version2, flags, (SigningLevel)policy, usn,
                last_blacklist_time, sequence, thumbprint, thumbprint_algo, hash, hash_algo);
        }

        private static CachedSigningLevelEaBufferV2 ReadCachedSigningLevelVersion2(BinaryReader reader)
        {
            int version2 = reader.ReadInt16();
            int flags = reader.ReadInt32();
            int policy = reader.ReadInt32();
            long last_blacklist_time = reader.ReadInt64();
            long last_timestamp = reader.ReadInt64();
            int thumbprint_size = reader.ReadInt32();
            HashAlgorithm thumbprint_algo = (HashAlgorithm) reader.ReadInt32();
            int hash_size = reader.ReadInt32();
            HashAlgorithm hash_algo = (HashAlgorithm) reader.ReadInt32();
            long usn = reader.ReadInt64();
            byte[] thumbprint = reader.ReadAllBytes(thumbprint_size);
            byte[] hash = reader.ReadAllBytes(hash_size);
            
            return new CachedSigningLevelEaBufferV2(version2, flags, (SigningLevel)policy, usn,
                last_blacklist_time, last_timestamp, thumbprint, thumbprint_algo, hash, hash_algo);
        }

        private static CachedSigningLevelEaBufferV3 ReadCachedSigningLevelVersion3(BinaryReader reader)
        {
            int version2 = reader.ReadByte();
            int policy = reader.ReadByte();
            long usn = reader.ReadInt64();
            long last_blacklist_time = reader.ReadInt64();
            int flags = reader.ReadInt32();
            int extra_size = reader.ReadUInt16();
            long end_size = reader.BaseStream.Position + extra_size;
            List<CachedSigningLevelBlob> extra_data = new List<CachedSigningLevelBlob>();
            HashCachedSigningLevelBlob thumbprint = null;
            while (reader.BaseStream.Position < end_size)
            {
                CachedSigningLevelBlob blob = CachedSigningLevelBlob.ReadBlob(reader);
                if (blob.BlobType == CachedSigningLevelBlobType.SignerHash)
                {
                    thumbprint = (HashCachedSigningLevelBlob)blob;
                }
                extra_data.Add(blob);
            }

            return new CachedSigningLevelEaBufferV3(version2, flags, (SigningLevel)policy, usn,
                last_blacklist_time, extra_data.AsReadOnly(), thumbprint);
        }

        /// <summary>
        /// Get the cached singing level from the raw EA buffer.
        /// </summary>
        /// <param name="ea">The EA buffer to read the cached signing level from.</param>
        /// <returns>The cached signing level.</returns>
        /// <exception cref="NtException">Throw on error.</exception>
        public static CachedSigningLevel GetCachedSigningLevelFromEa(EaBuffer ea)
        {
            EaBufferEntry buffer = ea.GetEntry("$KERNEL.PURGE.ESBCACHE");
            if (buffer == null)
            {
                NtStatus.STATUS_OBJECT_NAME_NOT_FOUND.ToNtException();
            }

            BinaryReader reader = new BinaryReader(new MemoryStream(buffer.Data));
            int total_size = reader.ReadInt32();
            int version = reader.ReadInt16();
            switch (version)
            {
                case 1:
                    return ReadCachedSigningLevelVersion1(reader);
                case 2:
                    return ReadCachedSigningLevelVersion2(reader);
                case 3:
                    return ReadCachedSigningLevelVersion3(reader);
                default:
                    throw new ArgumentException($"Unsupported cached signing level buffer version {version}");
            }
        }

        /// <summary>
        /// Set the cached signing level for a file.
        /// </summary>
        /// <param name="handle">The handle to the file to set the cache on.</param>
        /// <param name="flags">Flags to set for the cache.</param>
        /// <param name="signing_level">The signing level to cache</param>
        /// <param name="source_files">A list of source file for the cache.</param>
        /// <param name="catalog_path">Optional directory path to look for catalog files.</param>
        public static void SetCachedSigningLevel(SafeKernelObjectHandle handle, 
                                                 int flags, SigningLevel signing_level,
                                                 IEnumerable<SafeKernelObjectHandle> source_files,
                                                 string catalog_path)
        {
            IntPtr[] handles = source_files?.Select(f => f.DangerousGetHandle()).ToArray();
            int handles_count = handles == null ? 0 : handles.Length;
            if (catalog_path != null)
            {
                CachedSigningLevelInformation info = new CachedSigningLevelInformation(catalog_path);
                NtSystemCalls.NtSetCachedSigningLevel2(flags, signing_level, handles, handles_count, handle, info).ToNtException();
            }
            else
            {
                NtSystemCalls.NtSetCachedSigningLevel(flags, signing_level, handles, handles_count, handle).ToNtException();
            }
        }

        private static string UpperCaseString(string name)
        {
            StringBuilder result = new StringBuilder(name);
            if (result.Length > 0)
            {
                result[0] = char.ToUpper(result[0]);
            }
            return result.ToString();
        }

        private static string MakeFakeCapabilityName(string name, bool group)
        {
            List<string> parts = new List<string>();
            if (name.Contains("_"))
            {
                parts.Add(name);
            }
            else
            {
                int start = 0;
                int index = 1;
                while (index < name.Length)
                {
                    if (Char.IsUpper(name[index]))
                    {
                        parts.Add(name.Substring(start, index - start));
                        start = index;
                    }
                    index++;
                }

                parts.Add(name.Substring(start));
                parts[0] = UpperCaseString(parts[0]);
            }

            return $@"NAMED CAPABILITIES{(group ? " GROUP":"")}\{String.Join(" ", parts)}";
        }

        private static SidName GetNameForSidInternal(Sid sid)
        {
            string name = LookupAccountSid(sid);
            if (name != null)
            {
                return new SidName(name, SidNameSource.Account);
            }

            if (IsCapabilitySid(sid))
            {
                // See if there's a known SID with this name.
                name = LookupKnownCapabilityName(sid);
                if (name == null)
                {
                    switch (sid.SubAuthorities.Count)
                    {
                        case 8:
                            uint[] sub_authorities = sid.SubAuthorities.ToArray();
                            // Convert to a package SID.
                            sub_authorities[0] = 2;
                            name = LookupPackageName(new Sid(sid.Authority, sub_authorities));
                            break;
                        case 5:
                            name = LookupDeviceCapabilityName(sid);
                            break;
                    }
                }

                if (!string.IsNullOrWhiteSpace(name))
                {
                    return new SidName(MakeFakeCapabilityName(name, false), SidNameSource.Capability);
                }
            }
            else if (IsCapabilityGroupSid(sid))
            {
                name = LookupKnownCapabilityName(sid);
                if (!string.IsNullOrWhiteSpace(name))
                {
                    return new SidName(MakeFakeCapabilityName(name, true), SidNameSource.Capability);
                }
            }
            else if (IsPackageSid(sid))
            {
                name = LookupPackageName(sid);
                if (name != null)
                {
                    return new SidName(name, SidNameSource.Package);
                }
            }
            else if (IsProcessTrustSid(sid))
            {
                name = LookupProcessTrustName(sid);
                if (name != null)
                {
                    return new SidName($@"TRUST LEVEL\{name}", SidNameSource.ProcessTrust);
                }
            }

            return new SidName(sid.ToString(), SidNameSource.Sddl);
        }

        private static ConcurrentDictionary<Sid, SidName> _cached_names = new ConcurrentDictionary<Sid, SidName>();

        /// <summary>
        /// Get readable name for a SID, if known. This covers sources of names such as LSASS lookup, capability names and package names.
        /// </summary>
        /// <param name="sid">The SID to lookup.</param>
        /// <param name="bypass_cache">True to bypass the internal cache and get the current name.</param>
        /// <returns>The name for the SID. Returns the SDDL form if no other name is known.</returns>
        public static SidName GetNameForSid(Sid sid, bool bypass_cache)
        {
            if (bypass_cache)
            {
                return GetNameForSidInternal(sid);
            }
            return _cached_names.GetOrAdd(sid, s => GetNameForSidInternal(sid));
        }

        /// <summary>
        /// Get readable name for a SID, if known. This covers sources of names such as LSASS lookup, capability names and package names.
        /// </summary>
        /// <param name="sid">The SID to lookup.</param>
        /// <returns>The name for the SID. Returns the SDDL form if no other name is known.</returns>
        /// <remarks>This function will cache name lookups, this means the name might not reflect what's currently in LSASS if it's been changed.</remarks>
        public static SidName GetNameForSid(Sid sid)
        {
            return GetNameForSid(sid, false);
        }

        /// <summary>
        /// Clear the SID name cache.
        /// </summary>
        public static void ClearSidNameCache()
        {
            _cached_names.Clear();
        }
    }
}
