//  Copyright 2020 Google Inc. All Rights Reserved.
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
using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Audit;
using NtApiDotNet.Win32.Security.Authentication;
using NtApiDotNet.Win32.Security.Authorization;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace NtApiDotNet.Win32.Security
{
#pragma warning disable 1591
    /// <summary>
    /// Security buffer type.
    /// </summary>
    internal enum SecBufferType
    {
        Empty = 0,
        Data = 1,
        Token = 2,
        PkgParams = 3,
        Missing = 4,
        Extra = 5,
        StreamTrailer = 6,
        StreamHeader = 7,
        NegotiationInfo = 8,
        Padding = 9,
        Stream = 10,
        Mechlist = 11,
        MechlistSignature = 12,
        Target = 13,
        ChannelBindings = 14,
        ChangePassResponse = 15,
        TargetHost = 16,
        Alert = 17,
        ApplicationProtocols = 18,
        SRTPProtectionProfiles = 19,
        SRTPMasterKeyIdentifier = 20,
        TokenBinding = 21,
        PresharedKey = 22,
        PresharedKeyIdentity = 23,
        DTLAMtu = 24,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal sealed class SecBuffer : IDisposable
    {
        public int cbBuffer;
        public SecBufferType BufferType;
        public IntPtr pvBuffer;

        void IDisposable.Dispose()
        {
            if (pvBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvBuffer);
            }
        }

        public SecBuffer()
        {
        }

        public SecBuffer(SecBufferType type, byte[] data)
            : this(type, data.Length)
        {
            Marshal.Copy(data, 0, pvBuffer, data.Length);
        }

        public SecBuffer(SecBufferType type, int length)
        {
            cbBuffer = length;
            BufferType = type;
            pvBuffer = Marshal.AllocHGlobal(length);
        }

        public byte[] ToArray()
        {
            byte[] ret = new byte[cbBuffer];
            Marshal.Copy(pvBuffer, ret, 0, ret.Length);
            return ret;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal sealed class SecBufferDesc : IDisposable
    {
        const int SECBUFFER_VERSION = 0;

        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers;

        void IDisposable.Dispose()
        {
            if (pBuffers != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pBuffers);
            }
        }

        public SecBufferDesc(SecBuffer buffer) : this(new SecBuffer[] { buffer })
        {
        }

        public SecBufferDesc(SecBuffer[] buffers)
        {
            int size = Marshal.SizeOf(typeof(SecBuffer));
            ulVersion = SECBUFFER_VERSION;
            cBuffers = buffers.Length;
            pBuffers = Marshal.AllocHGlobal(buffers.Length * size);
            int offset = 0;
            foreach (var buffer in buffers)
            {
                Marshal.StructureToPtr(buffer, pBuffers + offset, false);
                offset += size;
            }
        }

        public SecBuffer[] ToArray()
        {
            SecBuffer[] buffers = new SecBuffer[cBuffers];
            int size = Marshal.SizeOf(typeof(SecBuffer));
            for (int i = 0; i < cBuffers; ++i)
            {
                buffers[i] = (SecBuffer)Marshal.PtrToStructure(pBuffers + (i * size), typeof(SecBuffer));
            }
            return buffers;
        }
    }

    internal enum SecWinNtAuthIdentityFlags
    {
        Ansi = 0x1,
        Unicode = 0x2,
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SecureStringMarshal : IDisposable
    {
        public IntPtr Ptr;

        public SecureStringMarshal(SecureString s)
        {
            Ptr = Marshal.SecureStringToBSTR(s);
        }

        public void Dispose()
        {
            if (Ptr != IntPtr.Zero)
            {
                Marshal.ZeroFreeBSTR(Ptr);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class SEC_WINNT_AUTH_IDENTITY
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string User;
        public int UserLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Domain;
        public int DomainLength;
        public SecureStringMarshal Password;
        public int PasswordLength;
        public SecWinNtAuthIdentityFlags Flags;

        public SEC_WINNT_AUTH_IDENTITY()
        {
        }

        public SEC_WINNT_AUTH_IDENTITY(string user, string domain, SecureString password, DisposableList list)
        {
            User = user;
            UserLength = user?.Length ?? 0;
            Domain = domain;
            DomainLength = domain?.Length ?? 0;
            if (password != null)
            {
                Password = list.AddResource(new SecureStringMarshal(password));
                PasswordLength = password.Length;
            }
            Flags = SecWinNtAuthIdentityFlags.Unicode;
        }
    }


    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class SEC_WINNT_AUTH_IDENTITY_EX
    {
        const int SEC_WINNT_AUTH_IDENTITY_VERSION = 0x200;

        public int Version;
        public int Length;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string User;
        public int UserLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Domain;
        public int DomainLength;
        public SecureStringMarshal Password;
        public int PasswordLength;
        public SecWinNtAuthIdentityFlags Flags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string PackageList;
        public int PackageListLength;

        public SEC_WINNT_AUTH_IDENTITY_EX()
        {
        }

        public SEC_WINNT_AUTH_IDENTITY_EX(string user, string domain, SecureString password, DisposableList list)
        {
            Version = SEC_WINNT_AUTH_IDENTITY_VERSION;
            Length = Marshal.SizeOf(this);
            User = user;
            UserLength = user?.Length ?? 0;
            Domain = domain;
            DomainLength = domain?.Length ?? 0;
            if (password != null)
            {
                Password = list.AddResource(new SecureStringMarshal(password));
                PasswordLength = password.Length;
            }
            Flags = SecWinNtAuthIdentityFlags.Unicode;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class SecHandle
    {
        public IntPtr dwLower;
        public IntPtr dwUpper;
    }

    internal enum SecStatusCode : uint
    {
        Success = 0,
        ContinueNeeded = 0x00090312,
        CompleteNeeded = 0x00090313,
        CompleteAndContinue = 0x00090314,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SecPkgInfo
    {
        public SecPkgCapabilityFlag fCapabilities;
        public short wVersion;
        public short wRPCID;
        public int cbMaxToken;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Name;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Comment;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class OptionalLuid
    {
        public Luid luid;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal delegate void TreeSetNamedSecurityProgress(string pObjectName, Win32Error Status,
        ref ProgressInvokeSetting pInvokeSetting, IntPtr Args, [MarshalAs(UnmanagedType.Bool)] bool SecuritySet);

    [StructLayout(LayoutKind.Sequential)]
    internal struct INHERITED_FROM
    {
        public int GenerationGap;
        public IntPtr AncestorName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CENTRAL_ACCESS_POLICY
    {
        public IntPtr CAPID;
        public UnicodeStringOut Name;
        public UnicodeStringOut Description;
        public UnicodeStringOut ChangeId;
        public uint Flags;
        public int CAPECount;
        public IntPtr CAPEs; // PCENTRAL_ACCESS_POLICY_ENTRY
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CENTRAL_ACCESS_POLICY_ENTRY
    {
        public UnicodeStringOut Name;
        public UnicodeStringOut Description;
        public UnicodeStringOut ChangeId;
        public int LengthAppliesTo;
        public IntPtr AppliesTo;
        public int LengthSD;
        public IntPtr SD;
        public int LengthStagedSD;
        public IntPtr StagedSD;
        public uint Flags;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal delegate bool AuthzAccessCheckCallback(
        IntPtr hAuthzClientContext,
        IntPtr pAce,
        IntPtr pArgs,
        [MarshalAs(UnmanagedType.Bool)] out bool pbAceApplicable);

    [StructLayout(LayoutKind.Sequential)]
    internal struct AUTHZ_ACCESS_REPLY
    {
        public int ResultListLength;
        public IntPtr GrantedAccessMask; // PACCESS_MASK.
        public IntPtr SaclEvaluationResults; // PDWORD
        public IntPtr Error; // PDWORD
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct AUTHZ_ACCESS_REQUEST
    {
        public AccessMask DesiredAccess;
        public IntPtr PrincipalSelfSid;
        public IntPtr ObjectTypeList;
        public int ObjectTypeListLength;
        public IntPtr OptionalArguments;
    }

    internal enum AUTHZ_CONTEXT_INFORMATION_CLASS
    {
        AuthzContextInfoUserSid = 1,
        AuthzContextInfoGroupsSids,
        AuthzContextInfoRestrictedSids,
        AuthzContextInfoPrivileges,
        AuthzContextInfoExpirationTime,
        AuthzContextInfoServerContext,
        AuthzContextInfoIdentifier,
        AuthzContextInfoSource,
        AuthzContextInfoAll,
        AuthzContextInfoAuthenticationId,
        AuthzContextInfoSecurityAttributes,
        AuthzContextInfoDeviceSids,
        AuthzContextInfoUserClaims,
        AuthzContextInfoDeviceClaims,
        AuthzContextInfoAppContainerSid,
        AuthzContextInfoCapabilitySids
    }

    [Flags]
    internal enum AuthZAccessCheckFlags
    {
        None = 0,
        NoDeepCopySD = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct AUDIT_POLICY_INFORMATION
    {
        public Guid AuditSubCategoryGuid;
        public int AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct POLICY_AUDIT_SID_ARRAY
    {
        public int UsersCount;
        public IntPtr UserSidArray;
    }

    internal static class SecurityNativeMethods
    {
        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode AcquireCredentialsHandle(
            string pszPrincipal,
            string pszPackage,
            SecPkgCredFlags fCredentialUse,
            OptionalLuid pvLogonId,
            SafeBuffer pAuthData,
            IntPtr pGetKeyFn,
            IntPtr pvGetKeyArgument,
            [Out] SecHandle phCredential,
            [Out] LargeInteger ptsExpiry
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode FreeCredentialsHandle([In, Out] SecHandle phCredential);

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode InitializeSecurityContext(
            [In] SecHandle phCredential,
            [In] SecHandle phContext,
            string pszTargetName,
            InitializeContextReqFlags fContextReq,
            int Reserved1,
            SecDataRep TargetDataRep,
            SecBufferDesc pInput,
            int Reserved2,
            [Out] SecHandle phNewContext,
            [In, Out] SecBufferDesc pOutput,
            out InitializeContextRetFlags pfContextAttr,
            [Out] LargeInteger ptsExpiry
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode CompleteAuthToken(SecHandle phContext,
            SecBufferDesc pToken
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode DeleteSecurityContext(
            SecHandle phContext
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode AcceptSecurityContext(
            [In] SecHandle phCredential,
            [In] SecHandle phContext,
            SecBufferDesc pInput,
            AcceptContextReqFlags fContextReq,
            SecDataRep TargetDataRep,
            [In, Out] SecHandle phNewContext,
            [In, Out] SecBufferDesc pOutput,
            out AcceptContextRetFlags pfContextAttr,
            [Out] LargeInteger ptsExpiry
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode QuerySecurityContextToken(SecHandle phContext, out SafeKernelObjectHandle Token);

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode FreeContextBuffer(
          IntPtr pvContextBuffer
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode EnumerateSecurityPackages(
            out int pcPackages,
            out IntPtr ppPackageInfo
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode QuerySecurityPackageInfo(
            string pPackageName,
            out IntPtr ppPackageInfo
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode ImpersonateSecurityContext(
          SecHandle phContext
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode RevertSecurityContext(
            SecHandle phContext
        );

        [DllImport("Ntdsapi.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error DsMakeSpn(
            string ServiceClass,
            string ServiceName,
            string InstanceName,
            ushort InstancePort,
            string Referrer,
            ref int pcSpnLength,
            [In, Out] StringBuilder pszSpn
        );

        [DllImport("Ntdsapi.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error DsCrackSpn(
            string pszSpn,
            [In, Out] OptionalInt32 pcServiceClass,
            [In, Out] StringBuilder ServiceClass,
            [In, Out] OptionalInt32 pcServiceName,
            [In, Out] StringBuilder ServiceName,
            [In, Out] OptionalInt32 pcInstanceName,
            [In, Out] StringBuilder InstanceName,
            [In, Out] OptionalUInt16 pInstancePort
        );


        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error SetSecurityInfo(
            SafeHandle handle,
            SeObjectType ObjectType,
            SecurityInformation SecurityInfo,
            byte[] psidOwner,
            byte[] psidGroup,
            byte[] pDacl,
            byte[] pSacl
        );


        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error SetNamedSecurityInfo(
            string pObjectName,
            SeObjectType ObjectType,
            SecurityInformation SecurityInfo,
            byte[] psidOwner,
            byte[] psidGroup,
            byte[] pDacl,
            byte[] pSacl
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error TreeSetNamedSecurityInfo(
            string pObjectName,
            SeObjectType ObjectType,
            SecurityInformation SecurityInfo,
            byte[] psidOwner,
            byte[] psidGroup,
            byte[] pDacl,
            byte[] pSacl,
            TreeSecInfo dwAction,
            TreeSetNamedSecurityProgress fnProgress,
            ProgressInvokeSetting ProgressInvokeSetting,
            IntPtr Args
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error TreeResetNamedSecurityInfo(
            string pObjectName,
            SeObjectType ObjectType,
            SecurityInformation SecurityInfo,
            byte[] psidOwner,
            byte[] psidGroup,
            byte[] pDacl,
            byte[] pSacl,
            [MarshalAs(UnmanagedType.Bool)] bool KeepExplicit,
            TreeSetNamedSecurityProgress fnProgress,
            ProgressInvokeSetting ProgressInvokeSetting,
            IntPtr Args
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error GetInheritanceSource(
            string pObjectName,
            SeObjectType ObjectType,
            SecurityInformation SecurityInfo,
            bool Container,
            SafeGuidArrayBuffer pObjectClassGuids,
            int GuidCount,
            byte[] pAcl,
            IntPtr pfnArray, // PFN_OBJECT_MGR_FUNCTS
            ref GenericMapping pGenericMapping,
            [Out] INHERITED_FROM[] pInheritArray
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FreeInheritedFromArray(
          INHERITED_FROM[] pInheritArray,
          ushort AceCnt,
          IntPtr pfnArray // PFN_OBJECT_MGR_FUNCTS
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error GetNamedSecurityInfo(
            string pObjectName,
            SeObjectType ObjectType,
            SecurityInformation SecurityInfo,
            OptionalPointer ppsidOwner,
            OptionalPointer ppsidGroup,
            OptionalPointer ppDacl,
            OptionalPointer ppSacl,
            out SafeLocalAllocBuffer ppSecurityDescriptor
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error GetSecurityInfo(
            SafeHandle handle,
            SeObjectType ObjectType,
            SecurityInformation SecurityInfo,
            OptionalPointer ppsidOwner,
            OptionalPointer ppsidGroup,
            OptionalPointer ppDacl,
            OptionalPointer ppSacl,
            out SafeLocalAllocBuffer ppSecurityDescriptor
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaFreeMemory(
            IntPtr Buffer
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaGetAppliedCAPIDs(
          UnicodeString SystemName,
          out SafeLsaMemoryBuffer CAPIDs,
          out int CAPIDCount
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaQueryCAPs(
          IntPtr CAPIDs,
          int CAPIDCount,
          out SafeLsaMemoryBuffer CAPs,
          out uint CAPCount
        );

        [DllImport("authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeResourceManager(
          AuthZResourceManagerInitializeFlags Flags,
          AuthzAccessCheckCallback pfnDynamicAccessCheck,
          IntPtr pfnComputeDynamicGroups,
          IntPtr pfnFreeDynamicGroups,
          string szResourceManagerName,
          out SafeAuthZResourceManagerHandle phAuthzResourceManager
        );

        [DllImport("authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzFreeResourceManager(
            IntPtr hAuthzResourceManager
        );

        [DllImport("authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeContextFromSid(
          AuthZContextInitializeSidFlags Flags,
          SafeSidBufferHandle UserSid,
          SafeAuthZResourceManagerHandle hAuthzResourceManager,
          LargeInteger pExpirationTime,
          Luid Identifier,
          IntPtr DynamicGroupArgs,
          out SafeAuthZClientContextHandle phAuthzClientContext
        );

        [DllImport("authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeContextFromToken(
            int Flags,
            SafeKernelObjectHandle TokenHandle,
            SafeAuthZResourceManagerHandle hAuthzResourceManager,
            LargeInteger pExpirationTime,
            Luid Identifier,
            IntPtr DynamicGroupArgs,
            out SafeAuthZClientContextHandle phAuthzClientContext
        );

        [DllImport("authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeContextFromAuthzContext(
            int Flags,
            SafeAuthZClientContextHandle hAuthzClientContext,
            LargeInteger pExpirationTime,
            Luid Identifier,
            IntPtr DynamicGroupArgs,
            out SafeAuthZClientContextHandle phNewAuthzClientContext
        );

        [DllImport("authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzFreeContext(
            IntPtr hAuthzClientContext
        );

        [DllImport("authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzAccessCheck(
            AuthZAccessCheckFlags Flags,
            SafeAuthZClientContextHandle hAuthzClientContext,
            ref AUTHZ_ACCESS_REQUEST pRequest,
            IntPtr hAuditEvent,
            SafeBuffer pSecurityDescriptor,
            IntPtr[] OptionalSecurityDescriptorArray,
            int OptionalSecurityDescriptorCount,
            ref AUTHZ_ACCESS_REPLY pReply,
            IntPtr phAccessCheckResults
        );

        [DllImport("authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzSetAppContainerInformation(
          SafeAuthZClientContextHandle hAuthzClientContext,
          SafeSidBufferHandle pAppContainerSid,
          int CapabilityCount,
          SafeBuffer pCapabilitySids
        );

        [DllImport("authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzModifySids(
                SafeAuthZClientContextHandle hAuthzClientContext,
                AUTHZ_CONTEXT_INFORMATION_CLASS SidClass,
                AuthZSidOperation[] pSidOperations,
                SafeTokenGroupsBuffer pSids
            );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern void AuditFree(IntPtr Buffer);

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditEnumerateCategories(
              out SafeAuditBuffer ppAuditCategoriesArray,
              out uint pdwCountReturned
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditEnumerateSubCategories(
          OptionalGuid pAuditCategoryGuid,
          bool bRetrieveAllSubCategories,
          out SafeAuditBuffer ppAuditSubCategoriesArray,
          out uint pdwCountReturned
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditLookupCategoryName(
            ref Guid pAuditCategoryGuid,
            out SafeAuditBuffer ppszCategoryName
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditLookupSubCategoryName(
            ref Guid pAuditCategoryGuid,
            out SafeAuditBuffer ppszCategoryName
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditQuerySystemPolicy(
          Guid[] pSubCategoryGuids,
          int dwPolicyCount,
          out SafeAuditBuffer ppAuditPolicy
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditSetSystemPolicy(
            AUDIT_POLICY_INFORMATION[] pAuditPolicy,
            int dwPolicyCount
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditQuerySecurity(
            SecurityInformation SecurityInformation,
            out SafeAuditBuffer ppSecurityDescriptor
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditSetSecurity(
            SecurityInformation SecurityInformation,
            SafeBuffer pSecurityDescriptor
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditQueryGlobalSacl(
          string ObjectTypeName,
          out SafeAuditBuffer Acl
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditSetGlobalSacl(
          string ObjectTypeName,
          SafeBuffer Acl
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditLookupCategoryGuidFromCategoryId(
          AuditPolicyEventType AuditCategoryId,
          out Guid pAuditCategoryGuid
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditEnumeratePerUserPolicy(
            out SafeAuditBuffer ppAuditSidArray
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditQueryPerUserPolicy(
            SafeSidBufferHandle pSid,
            Guid[] pSubCategoryGuids,
            int dwPolicyCount,
            out SafeAuditBuffer ppAuditPolicy
        );

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool AuditSetPerUserPolicy(
            SafeSidBufferHandle pSid,
            AUDIT_POLICY_INFORMATION[] pAuditPolicy,
            int dwPolicyCount
        );

        public static SecStatusCode CheckResult(this SecStatusCode result)
        {
            ((NtStatus)(uint)result).ToNtException();
            return result;
        }
    }
}
