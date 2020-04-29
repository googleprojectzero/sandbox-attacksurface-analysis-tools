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
using NtApiDotNet.Win32.Security.Policy;
using System;
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
            TOKEN_SOURCE SourceContext,
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
        internal static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, SecurityLogonType dwLogonType,
            int dwLogonProvider, out SafeKernelObjectHandle phToken);

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool LogonUserExExW(
              string lpszUsername,
              string lpszDomain,
              string lpszPassword,
              SecurityLogonType dwLogonType,
              int dwLogonProvider,
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

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode QueryContextAttributesEx(
          SecHandle phContext,
          SECPKG_ATTR ulAttribute,
          SafeBuffer pBuffer,
          int cbBuffer
        );

        public static SecStatusCode CheckResult(this SecStatusCode result)
        {
            ((NtStatus)(uint)result).ToNtException();
            return result;
        }
    }
}
