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
using NtApiDotNet.Win32.Security.Credential;
using NtApiDotNet.Win32.Security.Credential.AuthIdentity;
using NtApiDotNet.Win32.Security.Policy;
using NtApiDotNet.Win32.Security.Sam;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32.Security.Native
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal delegate void TreeSetNamedSecurityProgress(string pObjectName, Win32Error Status,
        ref ProgressInvokeSetting pInvokeSetting, IntPtr Args, [MarshalAs(UnmanagedType.Bool)] bool SecuritySet);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal delegate bool AuthzAccessCheckCallback(
        IntPtr hAuthzClientContext,
        IntPtr pAce,
        IntPtr pArgs,
        [MarshalAs(UnmanagedType.Bool)] out bool pbAceApplicable);

    internal delegate NtStatus SecurityEnumDelegate<H, B>(H handle, ref int context, 
        out B buffer, int max_count, out int entries_read);

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
        internal static extern SecStatusCode AddCredentials(
            [In] SecHandle hCredentials,
            string pszPrincipal,
            string pszPackage,
            SecPkgCredFlags fCredentialUse,
            SafeBuffer pAuthData,
            IntPtr pGetKeyFn,
            IntPtr pvGetKeyArgument,
            [Out] LargeInteger ptsExpiry
        );

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
        internal static extern SecStatusCode SetCredentialsAttributes(
            [In] SecHandle phCredential,
            SECPKG_CRED_ATTR ulAttribute,
            SafeBuffer pBuffer,
            int cbBuffer
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

        [DllImport("Secur32.dll")]
        internal static extern SecStatusCode ApplyControlToken(
          [In] SecHandle phContext,
          [In] SecBufferDesc pInput
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
        internal static extern SecStatusCode MakeSignature(
          [In] SecHandle phContext,
          int fQOP,
          SecBufferDesc pMessage,
          int MessageSeqNo
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode VerifySignature(
            [In] SecHandle phContext,
            SecBufferDesc pMessage,
            int MessageSeqNo,
            out int pfQOP
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode EncryptMessage(
            [In] SecHandle phContext,
            SecurityQualityOfProtectionFlags fQOP,
            SecBufferDesc pMessage,
            int MessageSeqNo
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode DecryptMessage(
            [In] SecHandle phContext,
            SecBufferDesc pMessage,
            int MessageSeqNo,
            out SecurityQualityOfProtectionFlags pfQOP
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

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode ExportSecurityContext(
          SecHandle phContext,
          SecPkgContextExportFlags fFlags,
          [In, Out] SecBuffer pPackedContext,
          out SafeKernelObjectHandle pToken
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode ImportSecurityContext(
            string pszPackage,
            SecBuffer pPackedContext,
            SafeKernelObjectHandle Token,
            [Out] SecHandle phContext
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode SspiMarshalAuthIdentity(
          SafeBuffer AuthIdentity, // PSEC_WINNT_AUTH_IDENTITY_OPAQUE 
          out int AuthIdentityLength,
          out SafeLocalAllocBuffer AuthIdentityByteArray
        );

        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error SspiPromptForCredentials(
          string pszTargetName,
          in CREDUI_INFO pUiInfo,
          Win32Error dwAuthError,
          string pszPackage,
          SafeBuffer pInputAuthIdentity, // PSEC_WINNT_AUTH_IDENTITY_OPAQUE
          out SafeSecWinNtAuthIdentityBuffer ppAuthIdentity, // PSEC_WINNT_AUTH_IDENTITY_OPAQUE*
          ref int pfSave,
          int dwFlags
        );

        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredPackAuthenticationBuffer(
            int dwFlags,
            string pszUserName,
            SecureStringMarshalBuffer pszPassword,
            [Out] byte[] pPackedCredentials,
            ref int pcbPackedCredentials
        );

        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredUnPackAuthenticationBuffer(
          int dwFlags,
          byte[] pAuthBuffer,
          int cbAuthBuffer,
          StringBuilder pszUserName,
          ref int pcchMaxUserName,
          StringBuilder pszDomainName,
          ref int pcchMaxDomainName,
          StringBuilder pszPassword,
          ref int pcchMaxPassword
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern void SspiFreeAuthIdentity(
            IntPtr AuthData
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode SspiCopyAuthIdentity(
          SafeBuffer AuthData,
          out SafeSecWinNtAuthIdentityBuffer AuthDataCopy
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode SspiUnmarshalAuthIdentity(
          int AuthIdentityLength,
          byte[] AuthIdentityByteArray,
          out SafeSecWinNtAuthIdentityBuffer ppAuthIdentity
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.U1)]
        internal static extern bool SspiIsAuthIdentityEncrypted(
            SafeSecWinNtAuthIdentityBuffer EncryptedAuthData
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode SspiDecryptAuthIdentityEx(
            SecWinNtAuthIdentityEncryptionOptions Options,
            SafeBuffer EncryptedAuthData
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode SspiEncryptAuthIdentityEx(
            SecWinNtAuthIdentityEncryptionOptions Options,
            SafeBuffer AuthData
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode SspiExcludePackage(
            SafeBuffer AuthIdentity,
            string pszPackageName,
            out SafeSecWinNtAuthIdentityBuffer ppNewAuthIdentity
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode SspiEncodeAuthIdentityAsStrings(
           SafeBuffer pAuthIdentity,
           out SafeLocalAllocBuffer ppszUserName,
           out SafeLocalAllocBuffer ppszDomainName,
           out SafeLocalAllocBuffer ppszPackedCredentialsString
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode SspiEncodeStringsAsAuthIdentity(
          string pszUserName,
          string pszDomainName,
          string pszPackedCredentialsString,
          out SafeSecWinNtAuthIdentityBuffer ppAuthIdentity
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode SspiValidateAuthIdentity(
            SafeBuffer AuthData
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern void SspiZeroAuthIdentity(
            IntPtr AuthData
        );

        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error CredUIPromptForWindowsCredentials(
          in CREDUI_INFO pUiInfo,
          Win32Error dwAuthError,
          ref uint pulAuthPackage,
          [In] byte[] pvInAuthBuffer,
          int ulInAuthBufferSize,
          out SafeCoTaskMemBuffer ppvOutAuthBuffer,
          out int pulOutAuthBufferSize,
          ref int pfSave,
          uint dwFlags
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
        internal static extern bool AuthzInitializeRemoteResourceManager(in AUTHZ_RPC_INIT_INFO_CLIENT pRpcInitInfo, 
            out SafeAuthZResourceManagerHandle phAuthzResourceManager);

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

        [DllImport("authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzGetInformationFromContext(
          SafeAuthZClientContextHandle hAuthzClientContext,
          AUTHZ_CONTEXT_INFORMATION_CLASS InfoClass,
          int BufferSize,
          out int pSizeRequired,
          SafeBuffer Buffer
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

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaEnumerateLogonSessions(
          out int LogonSessionCount,
          out SafeLsaReturnBufferHandle LogonSessionList
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaGetLogonSessionData(
          ref Luid LogonId,
          out SafeLsaReturnBufferHandle ppLogonSessionData
        );

        [DllImport("Secur32.dll")]
        internal static extern NtStatus LsaConnectUntrusted(out SafeLsaLogonHandle handle);

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaRegisterLogonProcess(
          LsaString LogonProcessName,
          out SafeLsaLogonHandle LsaHandle,
          out uint SecurityMode // PLSA_OPERATIONAL_MODE
        );

        [DllImport("Secur32.dll")]
        internal static extern NtStatus LsaLookupAuthenticationPackage(SafeLsaLogonHandle LsaHandle, LsaString PackageName, out uint AuthenticationPackage);

        [DllImport("Secur32.dll")]
        internal static extern NtStatus LsaLogonUser(
            SafeLsaLogonHandle LsaHandle, 
            LsaString OriginName, 
            SecurityLogonType LogonType, 
            uint AuthenticationPackage,
            SafeBuffer AuthenticationInformation,
            int AuthenticationInformationLength,
            SafeTokenGroupsBuffer LocalGroups,
            TokenSource SourceContext,
            out SafeLsaReturnBufferHandle ProfileBuffer,
            out int ProfileBufferLength,
            out Luid LogonId,
            out SafeKernelObjectHandle Token,
            QUOTA_LIMITS Quotas,
            out NtStatus SubStatus
        );

        [DllImport("Secur32.dll")]
        internal static extern NtStatus LsaFreeReturnBuffer(IntPtr Buffer);

        [DllImport("Advapi32.dll")]
        internal static extern bool AllocateLocallyUniqueId(out Luid Luid);

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool LogonUser(string lpszUsername, string lpszDomain, SecureStringMarshalBuffer lpszPassword, SecurityLogonType dwLogonType,
            Logon32Provider dwLogonProvider, out SafeKernelObjectHandle phToken);

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool LogonUserExExW(
              string lpszUsername,
              string lpszDomain,
              SecureStringMarshalBuffer lpszPassword,
              SecurityLogonType dwLogonType,
              Logon32Provider dwLogonProvider,
              SafeTokenGroupsBuffer pTokenGroups,
              out SafeKernelObjectHandle phToken,
              [Out] OptionalPointer ppLogonSid,
              [Out] OptionalPointer ppProfileBuffer,
              [Out] OptionalPointer pdwProfileLength,
              [Out] QUOTA_LIMITS pQuotaLimits
            );

        [DllImport("Advapi32.dll")]
        internal static extern NtStatus LsaClose(IntPtr handle);

        [DllImport("Secur32.dll")]
        internal static extern NtStatus LsaDeregisterLogonProcess(
          IntPtr LsaHandle
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaOpenPolicy(
          UnicodeString SystemName,
          ObjectAttributes ObjectAttributes,
          LsaPolicyAccessRights DesiredAccess,
          out SafeLsaHandle PolicyHandle
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaEnumerateAccountRights(
          SafeLsaHandle PolicyHandle,
          SafeSidBufferHandle AccountSid,
          out SafeLsaMemoryBuffer UserRights,
          out int CountOfRights
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaEnumerateAccountsWithUserRight(
          SafeLsaHandle PolicyHandle,
          UnicodeString UserRight,
          out SafeLsaMemoryBuffer Buffer,
          out int CountReturned
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaAddAccountRights(
            SafeLsaHandle PolicyHandle,
            SafeSidBufferHandle AccountSid,
            [In] UnicodeStringIn[] UserRights,
            int CountOfRights
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaRemoveAccountRights(
            SafeLsaHandle PolicyHandle,
            SafeSidBufferHandle AccountSid,
            [MarshalAs(UnmanagedType.U1)] bool AllRights,
            [In] UnicodeStringIn[] UserRights,
            int CountOfRights
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaCallAuthenticationPackage(
              SafeLsaLogonHandle LsaHandle,
              uint AuthenticationPackage,
              SafeBuffer ProtocolSubmitBuffer,
              int SubmitBufferLength,
              out SafeLsaReturnBufferHandle ProtocolReturnBuffer,
              out int ReturnBufferLength,
              out NtStatus ProtocolStatus
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaManageSidNameMapping(
            LSA_SID_NAME_MAPPING_OPERATION_TYPE OperationType,
            SafeBuffer OperationInput,
            out SafeLsaMemoryBuffer OperationOutput
        );

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode QueryContextAttributesEx(
          SecHandle phContext,
          SECPKG_ATTR ulAttribute,
          SafeBuffer pBuffer,
          int cbBuffer
        );

        [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode QueryContextAttributes(
          SecHandle phContext,
          SECPKG_ATTR ulAttribute,
          SafeBuffer pBuffer
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaLookupSids(
            SafeLsaHandle PolicyHandle,
            int Count,
            IntPtr[] Sids,
            out SafeLsaMemoryBuffer ReferencedDomains,
            out SafeLsaMemoryBuffer Names
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaLookupSids2(
            SafeLsaHandle PolicyHandle,
            LsaLookupSidOptionFlags LookupOptions,
            int Count,
            IntPtr[] Sids,
            out SafeLsaMemoryBuffer ReferencedDomains,
            out SafeLsaMemoryBuffer Names
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaLookupNames2(
            SafeLsaHandle PolicyHandle,
            LsaLookupNameOptionFlags Flags,
            int Count,
            UnicodeStringIn[] Names,
            out SafeLsaMemoryBuffer ReferencedDomains,
            out SafeLsaMemoryBuffer Sids // PLSA_TRANSLATED_SID
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaStorePrivateData(
            SafeLsaHandle PolicyHandle,
            [In] UnicodeString KeyName,
            UnicodeStringBytesSafeBuffer PrivateData
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaRetrievePrivateData(
            SafeLsaHandle PolicyHandle,
            [In] UnicodeString KeyName,
            out SafeLsaMemoryBuffer PrivateData // PLSA_UNICODE_STRING
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaOpenSecret(
            SafeLsaHandle PolicyHandle,
            [In] UnicodeString SecretName,
            LsaSecretAccessRights DesiredAccess,
            out SafeLsaHandle SecretHandle
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaQuerySecret(
            SafeLsaHandle SecretHandle,
            out SafeLsaMemoryBuffer CurrentValue,
            LargeInteger CurrentValueSetTime,
            out SafeLsaMemoryBuffer OldValue,
            LargeInteger OldValueSetTime
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaCreateSecret(
            SafeLsaHandle PolicyHandle,
            [In] UnicodeString SecretName,
            LsaSecretAccessRights DesiredAccess,
            out SafeLsaHandle SecretHandle
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaSetSecret(
            SafeLsaHandle SecretHandle,
            UnicodeStringBytesSafeBuffer CurrentValue,
            UnicodeStringBytesSafeBuffer OldValue
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaCreateAccount(
            SafeLsaHandle PolicyHandle,
            SafeSidBufferHandle AccountSid,
            LsaAccountAccessRights DesiredAccess,
            out SafeLsaHandle AccountHandle
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaOpenAccount(
            SafeLsaHandle PolicyHandle,
            SafeSidBufferHandle AccountSid,
            LsaAccountAccessRights DesiredAccess,
            out SafeLsaHandle AccountHandle
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaGetSystemAccessAccount(
            SafeLsaHandle AccountHandle,
            out LsaSystemAccessFlags SystemAccess
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaSetSystemAccessAccount(
            SafeLsaHandle AccountHandle,
            LsaSystemAccessFlags SystemAccess
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaEnumeratePrivilegesOfAccount(
            SafeLsaHandle AccountHandle,
            out SafeLsaMemoryBuffer Privileges // PPRIVILEGE_SET 
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaEnumerateAccounts(
            SafeLsaHandle PolicyHandle,
            ref int EnumerationContext,
            out SafeLsaMemoryBuffer EnumerationBuffer, // PLSAPR_ACCOUNT_INFORMATION
            int PreferedMaximumLength,
            out int EntriesRead
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaEnumerateTrustedDomainsEx(
            SafeLsaHandle PolicyHandle,
            ref int EnumerationContext,
            out SafeLsaMemoryBuffer Buffer,
            int PreferedMaximumLength,
            out int CountReturned
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaOpenTrustedDomain(
            SafeLsaHandle PolicyHandle,
            SafeSidBufferHandle TrustedDomainSid,
            LsaTrustedDomainAccessRights DesiredAccess,
            out SafeLsaHandle TrustedDomainHandle
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaOpenTrustedDomainByName(
            SafeLsaHandle PolicyHandle,
            UnicodeString TrustedDomainName,
            LsaTrustedDomainAccessRights DesiredAccess,
            out SafeLsaHandle TrustedDomainHandle
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaQueryInfoTrustedDomain(
            SafeLsaHandle TrustedDomainHandle,
            TRUSTED_INFORMATION_CLASS InformationClass,
            out SafeLsaMemoryBuffer Buffer
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaQueryTrustedDomainInfo(
            SafeLsaHandle PolicyHandle,
            SafeSidBufferHandle TrustedDomainSid,
            TRUSTED_INFORMATION_CLASS InformationClass,
            out SafeLsaMemoryBuffer Buffer
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaQueryTrustedDomainInfoByName(
            SafeLsaHandle PolicyHandle,
            UnicodeString TrustedDomainName,
            TRUSTED_INFORMATION_CLASS InformationClass,
            out SafeLsaMemoryBuffer Buffer
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaDeleteObject(
            SafeLsaHandle ObjectHandle
        );

        [DllImport("Crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CertFreeCertificateContext(
            IntPtr pCertContext
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CredEnumerate(
            string Filter,
            CredentialEnumerateFlags Flags,
            out int Count,
            out SafeCredBuffer Credential
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CredRead(
            string TargetName,
            CredentialType Type,
            int Flags,
            out SafeCredBuffer Credential
        );

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredBackupCredentials(SafeKernelObjectHandle Token, 
            string FilePath, IntPtr Key, int KeySize, int KeyEncoded);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredMarshalCredential(
            CredMarshalType CredType,
            SafeBuffer Credential,
            out SafeCredBuffer MarshaledCredential // LPWSTR* 
        );

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredUnmarshalCredential(
          string MarshaledCredential,
          out CredMarshalType CredType,
          out SafeCredBuffer Credential
        );

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredProtect(
            [MarshalAs(UnmanagedType.Bool)] bool fAsSelf,
            string pszCredentials,
            int cchCredentials,
            [Out] byte[] pszProtectedCredentials,
            ref int pcchMaxChars,
            out CredentialProtectionType ProtectionType
        );

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("api-ms-win-security-credentials-l2-1-1.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredProtectEx(
            CredentialProtectFlag Flags,
            [In] byte[] pszCredentials,
            int cchCredentials,
            [Out] byte[] pszProtectedCredentials,
            ref int pcchMaxChars,
            out CredentialProtectionType ProtectionType
        );

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredUnprotect(
            [MarshalAs(UnmanagedType.Bool)] bool fAsSelf,
            string pszProtectedCredentials,
            int cchProtectedCredentials,
            [Out] byte[] pszCredentials,
            ref int pcchMaxChars
        );

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("api-ms-win-security-credentials-l2-1-1.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredUnprotectEx(
           CredentialUnprotectFlag Flags,
            string pszProtectedCredentials,
            int cchProtectedCredentials,
            [Out] byte[] pszCredentials,
            ref int pcchMaxChars
        );

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredIsProtected(
            string pszProtectedCredentials,
            out CredentialProtectionType pProtectionType
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern void CredFree(
            IntPtr Buffer
        );

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredWrite(
          in CREDENTIAL Credential,
          CredentialWriteFlags Flags
        );

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredDelete(
          string TargetName,
          CredentialType Type,
          int Flags
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaQuerySecurityObject(
            SafeLsaHandle ObjectHandle,
            SecurityInformation SecurityInformation,
            out SafeLsaMemoryBuffer SecurityDescriptor
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus LsaSetSecurityObject(
            SafeLsaHandle ObjectHandle,
            SecurityInformation SecurityInformation,
            SafeBuffer SecurityDescriptor
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamConnect(
            UnicodeString ServerName,
            out SafeSamHandle ServerHandle,
            AccessMask DesiredAccess,
            ObjectAttributes ObjectAttributes
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamFreeMemory(
            IntPtr Buffer
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamCloseHandle(
            IntPtr SamHandle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamSetSecurityObject(
            SafeSamHandle ObjectHandle,
            SecurityInformation SecurityInformation,
            SafeBuffer SecurityDescriptor
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamQuerySecurityObject(
            SafeSamHandle ObjectHandle,
            SecurityInformation SecurityInformation,
            out SafeSamMemoryBuffer SecurityDescriptor
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamEnumerateDomainsInSamServer(
            SafeSamHandle ServerHandle,
            ref int EnumerationContext,
            out SafeSamMemoryBuffer Buffer,
            int PreferedMaximumLength,
            out int CountReturned
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamLookupDomainInSamServer(
            SafeSamHandle ServerHandle,
            UnicodeString Name,
            out SafeSamMemoryBuffer DomainId
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamRidToSid(
            SafeSamHandle ObjectHandle,
            uint Rid,
            out SafeSamMemoryBuffer Sid
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamOpenDomain(
            SafeSamHandle ServerHandle,
            SamDomainAccessRights DesiredAccess,
            SafeSidBufferHandle DomainId,
            out SafeSamHandle DomainHandle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamLookupNamesInDomain(
            SafeSamHandle DomainHandle,
            int Count,
            [In] UnicodeStringIn[] Names,
            out SafeSamMemoryBuffer RelativeIds, // PULONG
            out SafeSamMemoryBuffer Use // PSID_NAME_USE
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamLookupIdsInDomain(
            SafeSamHandle DomainHandle,
            int Count,
            uint[] RelativeIds,
            out SafeSamMemoryBuffer Names, // PUNICODE_STRING
            out SafeSamMemoryBuffer Use // PSID_NAME_USE
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamEnumerateUsersInDomain(
            SafeSamHandle DomainHandle,
            ref int EnumerationContext,
            UserAccountControlFlags UserAccountControl,
            out SafeSamMemoryBuffer Buffer, // PSAM_RID_ENUMERATION *
            int PreferedMaximumLength,
            out int CountReturned
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamEnumerateGroupsInDomain(
            SafeSamHandle DomainHandle,
            ref int EnumerationContext,
            out SafeSamMemoryBuffer Buffer, // PSAM_RID_ENUMERATION
            int PreferedMaximumLength,
            out int CountReturned
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamEnumerateAliasesInDomain(
            SafeSamHandle DomainHandle,
            ref int EnumerationContext,
            out SafeSamMemoryBuffer Buffer, // PSAM_RID_ENUMERATION
            int PreferedMaximumLength,
            out int CountReturned
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamOpenUser(
            SafeSamHandle DomainHandle,
            SamUserAccessRights DesiredAccess,
            uint UserId,
            out SafeSamHandle UserHandle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamCreateUser2InDomain(
            SafeSamHandle DomainHandle,
            UnicodeString AccountName,
            UserAccountControlFlags AccountType,
            SamUserAccessRights DesiredAccess,
            out SafeSamHandle UserHandle,
            out SamUserAccessRights GrantedAccess,
            out uint RelativeId
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamQueryInformationDomain(
            SafeSamHandle DomainHandle,
            DomainInformationClass DomainInformationClass,
            out SafeSamMemoryBuffer Buffer
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamSetInformationDomain(
            SafeSamHandle DomainHandle,
            DomainInformationClass DomainInformationClass,
            SafeBuffer DomainInformation
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamOpenGroup(
            SafeSamHandle DomainHandle,
            SamGroupAccessRights DesiredAccess,
            uint GroupId,
            out SafeSamHandle GroupHandle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamOpenAlias(
            SafeSamHandle DomainHandle,
            SamAliasAccessRights DesiredAccess,
            uint AliasId,
            out SafeSamHandle AliasHandle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamGetMembersInGroup(
            SafeSamHandle GroupHandle,
            out SafeSamMemoryBuffer MemberIds, // PULONG *
            out SafeSamMemoryBuffer Attributes, // PULONG *
            out int MemberCount
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamGetMembersInAlias(
            SafeSamHandle AliasHandle,
            out SafeSamMemoryBuffer MemberIds, // PSID **
            out int MemberCount
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamQueryInformationUser(
            SafeSamHandle UserHandle,
            UserInformationClass UserInformationClass,
            out SafeSamMemoryBuffer Buffer
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamSetInformationUser(
            SafeSamHandle UserHandle,
            UserInformationClass UserInformationClass,
            SafeBuffer Buffer
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamChangePasswordUser(
            SafeSamHandle UserHandle,
            UnicodeStringSecure OldPassword,
            UnicodeStringSecure NewPassword
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamiChangePasswordUser(
            SafeSamHandle UserHandle, bool LmPresent, byte[] OldLM, byte[] NewLM,
            bool NtPresent, byte[] OldNt, byte[] NewNt);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamGetGroupsForUser(
            SafeSamHandle UserHandle,
            out SafeSamMemoryBuffer Groups, // PGROUP_MEMBERSHIP
            out int MembershipCount
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamGetAliasMembership(
            SafeSamHandle DomainHandle,
            int PassedCount,
            IntPtr[] Sids, // PSID
            out int MembershipCount,
            out SafeSamMemoryBuffer Aliases // PULONG
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamCreateGroupInDomain(
            SafeSamHandle DomainHandle,
            UnicodeString Name,
            SamGroupAccessRights DesiredAccess,
            out SafeSamHandle GroupHandle,
            out uint RelativeId
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamQueryInformationGroup(
            SafeSamHandle GroupHandle,
            GROUP_INFORMATION_CLASS GroupInformationClass,
            out SafeSamMemoryBuffer Buffer
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamSetInformationGroup(
            SafeSamHandle GroupHandle,
            GROUP_INFORMATION_CLASS GroupInformationClass,
            SafeBuffer Buffer
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamDeleteGroup(
            SafeSamHandle GroupHandle
        );

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus RtlMapSecurityErrorToNtStatus(SecStatusCode Error);

        [DllImport("cryptdll.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus CDLocateCSystem(Authentication.Kerberos.KerberosEncryptionType type, out IntPtr enc_engine);

        [DllImport("cryptdll.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus CDLocateCheckSum(Authentication.Kerberos.KerberosChecksumType type, out IntPtr chk_engine);

        [DllImport("cryptdll.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus CDBuildIntegrityVect(ref int count, [Out] Authentication.Kerberos.KerberosEncryptionType[] encryption_types);

        [DllImport("cryptdll.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus CDBuildVect(out int count, [Out] Authentication.Kerberos.KerberosEncryptionType[] encryption_types);

        [DllImport("cryptdll.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus CDGetIntegrityVect(out uint supported_encryption_types);

        internal static bool IsSuccess(this SecStatusCode result)
        {
            return (int)result >= 0;
        }

        internal static SecStatusCode CheckResult(this SecStatusCode result, bool throw_on_error = true)
        {
            RtlMapSecurityErrorToNtStatus(result).ToNtException(throw_on_error);
            return result;
        }

        internal static NtResult<IReadOnlyList<T>> EnumerateObjects<T, H, B, S>(H handle, SecurityEnumDelegate<H, B> func, Func<S, T> select_object,
            bool throw_on_error) where H : SafeHandle where B : SafeBufferGeneric where S : struct
        {
            int context = 0;
            List<T> ret = new List<T>();
            NtStatus status;
            int last_context = 0;
            do
            {
                status = func(handle, ref context, out B buffer, 64 * 1024, out int entries_read);
                if (!status.IsSuccess())
                {
                    if (status == NtStatus.STATUS_NO_MORE_ENTRIES)
                    {
                        break;
                    }
                    return status.CreateResultFromError<IReadOnlyList<T>>(throw_on_error);
                }

                if (entries_read == 0)
                {
                    break;
                }

                using (buffer)
                {
                    buffer.Initialize<S>((uint)entries_read);
                    foreach (var value in buffer.ReadArray<S>(0, entries_read))
                    {
                        ret.Add(select_object(value));
                    }
                }

                // This is to deal with a weird bug in SamEnumerateAliasesInDomain.
                if (context == last_context)
                {
                    break;
                }
                last_context = context;
            }
            while (true);

            return ret.AsReadOnly().CreateResult<IReadOnlyList<T>>();
        }
    }
}
