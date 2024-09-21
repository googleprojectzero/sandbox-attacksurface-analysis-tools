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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authorization
{
    /// <summary>
    /// Class to represent an AuthZ client context.
    /// </summary>
    public sealed class AuthZContext : IDisposable
    {
        #region Private Members
        private readonly SafeAuthZClientContextHandle _handle;

        private AuthZContext(SafeAuthZClientContextHandle handle, bool remote)
        {
            _handle = handle;
            Remote = remote;
        }

        private static AUTHZ_CONTEXT_INFORMATION_CLASS SidTypeToInfoClass(AuthZGroupSidType type)
        {
            switch (type)
            {
                case AuthZGroupSidType.Device:
                    return AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoDeviceSids;
                case AuthZGroupSidType.Restricted:
                    return AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoRestrictedSids;
                case AuthZGroupSidType.Capability:
                    return AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoCapabilitySids;
                default:
                    return AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoGroupsSids;
            }
        }

        private static AUTHZ_CONTEXT_INFORMATION_CLASS AttrTypeToInfoClass(AuthZSecurityAttributeType type)
        {
            switch (type)
            {
                case AuthZSecurityAttributeType.Device:
                    return AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoDeviceClaims;
                case AuthZSecurityAttributeType.User:
                    return AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoUserClaims;
                default:
                    return AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoSecurityAttributes;
            }
        }

        private static AuthZAccessCheckResult[] CreateResult(int count, SafeBuffer error, SafeBuffer access,
            ObjectTypeEntry[] object_types, NtType type)
        {
            int[] error_array = new int[count];
            error.ReadArray(0, error_array, 0, count);
            AccessMask[] access_array = new AccessMask[count];
            access.ReadArray(0, access_array, 0, count);
            return Enumerable.Range(0, count).Select(i => new AuthZAccessCheckResult(type, (Win32Error)error_array[i],
                access_array[i], object_types?[i])).ToArray();
        }

        private NtResult<SafeStructureInOutBuffer<T>> QueryBuffer<T>(AUTHZ_CONTEXT_INFORMATION_CLASS info_class, bool throw_on_error) where T : new()
        {
            if (SecurityNativeMethods.AuthzGetInformationFromContext(_handle, info_class, 0, out int required_size, SafeHGlobalBuffer.Null))
            {
                return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<SafeStructureInOutBuffer<T>>(throw_on_error);
            }

            var err = Win32Utils.GetLastWin32Error();
            if (err != Win32Error.ERROR_INSUFFICIENT_BUFFER)
                return err.CreateResultFromDosError<SafeStructureInOutBuffer<T>>(throw_on_error);

            using (var buffer = new SafeStructureInOutBuffer<T>(required_size, false))
            {
                return SecurityNativeMethods.AuthzGetInformationFromContext(_handle, info_class, 
                    buffer.Length, out required_size, buffer).CreateWin32Result(throw_on_error, () => buffer.Detach());
            }
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get AuthZ user
        /// </summary>
        public UserGroup User => GetUser(true).Result;

        /// <summary>
        /// Get AuthZ context groups.
        /// </summary>
        public UserGroup[] Groups => GetGroups(AuthZGroupSidType.Normal, true).Result;

        /// <summary>
        /// Get AuthZ context restricted SIDs.
        /// </summary>
        public UserGroup[] RestrictedSids => GetGroups(AuthZGroupSidType.Restricted, true).Result;

        /// <summary>
        /// Get AuthZ context device groups.
        /// </summary>
        public UserGroup[] DeviceGroups => GetGroups(AuthZGroupSidType.Device, true).Result;

        /// <summary>
        /// Get AuthZ context capability SIDs.
        /// </summary>
        public UserGroup[] Capabilities => GetGroups(AuthZGroupSidType.Capability, true).Result;

        /// <summary>
        /// Get AuthZ context's security attributes
        /// </summary>
        public ClaimSecurityAttribute[] SecurityAttributes => GetSecurityAttributes(AuthZSecurityAttributeType.Token, true).Result;

        /// <summary>
        /// Get AuthZ context's device claims.
        /// </summary>
        public ClaimSecurityAttribute[] DeviceClaimAttributes => GetSecurityAttributes(AuthZSecurityAttributeType.Device, true).Result;

        /// <summary>
        /// Get AuthZ context's user claims.
        /// </summary>
        public ClaimSecurityAttribute[] UserClaimAttributes => GetSecurityAttributes(AuthZSecurityAttributeType.User, true).Result;

        /// <summary>
        /// Get list of privileges for the AuthZ context.
        /// </summary>
        /// <returns>The list of privileges</returns>
        /// <exception cref="NtException">Thrown if can't query privileges</exception>
        public TokenPrivilege[] Privileges => GetPrivileges(true).Result;

        /// <summary>
        /// Get AppContainer SID.
        /// </summary>
        public Sid AppContainerSid => GetAppContainerSid(false).GetResultOrDefault(null);

        /// <summary>
        /// Indicates if this context is connected to a remote access server.
        /// </summary>
        public bool Remote { get; }

        #endregion

        #region Public Methods

        /// <summary>
        /// Set AppContainer Information to Context.
        /// </summary>
        /// <param name="package_sid">The package SID.</param>
        /// <param name="capabilities">List of capabilities.</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetAppContainer(Sid package_sid, IEnumerable<UserGroup> capabilities, bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var sid_buffer = list.AddResource(package_sid.ToSafeBuffer());
                var cap_sids = capabilities?.ToArray() ?? new UserGroup[0];
                SafeTokenGroupsBuffer cap_buffer = list.AddResource(SafeTokenGroupsBuffer.Create(cap_sids));
                SafeBuffer buffer = cap_sids.Length > 0 ? cap_buffer.Data : SafeHGlobalBuffer.Null;
                if (!SecurityNativeMethods.AuthzSetAppContainerInformation(_handle,
                    sid_buffer, cap_sids.Length, buffer))
                {
                    return NtObjectUtils.MapDosErrorToStatus().ToNtException(throw_on_error);
                }
                return NtStatus.STATUS_SUCCESS;
            }
        }

        /// <summary>
        /// Set AppContainer Information to Context.
        /// </summary>
        /// <param name="package_sid">The package SID.</param>
        /// <param name="capabilities">List of capabilities.</param>
        public void SetAppContainer(Sid package_sid, IEnumerable<UserGroup> capabilities)
        {
            SetAppContainer(package_sid, capabilities, true);
        }

        /// <summary>
        /// Modify groups in the context.
        /// </summary>
        /// <param name="type">The type of group to modify.</param>
        /// <param name="groups">The list of groups to modify.</param>
        /// <param name="operations">The list of operations. Should be same size of group list.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus ModifyGroups(AuthZGroupSidType type, IEnumerable<UserGroup> groups, IEnumerable<AuthZSidOperation> operations, bool throw_on_error)
        {
            if (groups is null)
            {
                throw new ArgumentNullException(nameof(groups));
            }

            if (operations is null)
            {
                throw new ArgumentNullException(nameof(operations));
            }

            UserGroup[] group_array = groups.ToArray();
            AuthZSidOperation[] ops_array = operations.ToArray();
            if (group_array.Length != ops_array.Length)
            {
                throw new ArgumentException("Groups and Operations must be the same length.");
            }

            using (var buffer = SafeTokenGroupsBuffer.Create(groups))
            {
                if (!SecurityNativeMethods.AuthzModifySids(_handle, SidTypeToInfoClass(type),
                    ops_array, buffer))
                {
                    return NtObjectUtils.MapDosErrorToStatus().ToNtException(throw_on_error);
                }
            }
            return NtStatus.STATUS_SUCCESS;
        }

        /// <summary>
        /// Modify groups in the context.
        /// </summary>
        /// <param name="type">The type of group to modify.</param>
        /// <param name="groups">The list of groups to modify.</param>
        /// <param name="operations">The list of operations. Should be same size of group list.</param>
        public void ModifyGroups(AuthZGroupSidType type, IEnumerable<UserGroup> groups, IEnumerable<AuthZSidOperation> operations)
        {
            ModifyGroups(type, groups, operations, true);
        }

        /// <summary>
        /// Modify groups in the context.
        /// </summary>
        /// <param name="type">The type of group to modify.</param>
        /// <param name="groups">The list of SIDs to modify.</param>
        /// <param name="attributes">The attributes for the SIDs.</param>
        /// <param name="operation">The operation for the SIDs.</param>
        public void ModifyGroups(AuthZGroupSidType type, IEnumerable<Sid> groups, GroupAttributes attributes, AuthZSidOperation operation)
        {
            if (groups is null)
            {
                throw new ArgumentNullException(nameof(groups));
            }

            ModifyGroups(type, groups.Select(s => new UserGroup(s, attributes)), groups.Select(_ => operation));
        }

        /// <summary>
        /// Modify groups in the context.
        /// </summary>
        /// <param name="type">The type of group to modify.</param>
        /// <param name="groups">The list of SIDs to modify.</param>
        /// <param name="operation">The operation for the SIDs.</param>
        public void ModifyGroups(AuthZGroupSidType type, IEnumerable<Sid> groups, AuthZSidOperation operation)
        {
            ModifyGroups(type, groups, GroupAttributes.Enabled, operation);
        }

        /// <summary>
        /// Add a SID to the context.
        /// </summary>
        /// <param name="sid">The SID to add.</param>
        public void AddSid(Sid sid)
        {
            ModifyGroups(AuthZGroupSidType.Normal, new Sid[] { sid }, AuthZSidOperation.Add);
        }

        /// <summary>
        /// Add a Device SID to the context.
        /// </summary>
        /// <param name="sid">The SID to add.</param>
        public void AddDeviceSid(Sid sid)
        {
            ModifyGroups(AuthZGroupSidType.Device, new Sid[] { sid }, AuthZSidOperation.Add);
        }

        /// <summary>
        /// Add a Device SID to the context.
        /// </summary>
        /// <param name="sid">The SID to add.</param>
        public void AddRestrictedSid(Sid sid)
        {
            ModifyGroups(AuthZGroupSidType.Restricted, new Sid[] { sid }, AuthZSidOperation.Add);
        }

        /// <summary>
        /// Add a list of SIDs to the context.
        /// </summary>
        /// <param name="sids">The list of SIDS.</param>
        public void AddSids(IEnumerable<Sid> sids)
        {
            ModifyGroups(AuthZGroupSidType.Normal, sids, AuthZSidOperation.Add);
        }

        /// <summary>
        /// Get list of groups for the AuthZ context.
        /// </summary>
        /// <param name="group_type">The group type.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of groups.</returns>
        public NtResult<UserGroup[]> GetGroups(AuthZGroupSidType group_type, bool throw_on_error)
        {
            using (var buffer = QueryBuffer<TokenGroups>(SidTypeToInfoClass(group_type), throw_on_error))
            {
                return buffer.Map(groups =>
                {
                    TokenGroups result = groups.Result;
                    SidAndAttributes[] sids = new SidAndAttributes[result.GroupCount];
                    groups.Data.ReadArray(0, sids, 0, result.GroupCount);
                    return sids.Select(s => s.ToUserGroup()).ToArray();
                }
                );
            }
        }

        /// <summary>
        /// Get list of groups for the AuthZ context.
        /// </summary>
        /// <param name="group_type">The group type.</param>
        /// <returns>The list of groups.</returns>
        public UserGroup[] GetGroups(AuthZGroupSidType group_type)
        {
            return GetGroups(group_type, true).Result;
        }

        /// <summary>
        /// Get the user from the AuthZ context.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The user group information.</returns>
        public NtResult<UserGroup> GetUser(bool throw_on_error)
        {
            using (var user = QueryBuffer<TokenUser>(AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoUserSid, throw_on_error))
            {
                if (!user.IsSuccess)
                    return user.Cast<UserGroup>();
                return user.Result.Result.User.ToUserGroup().CreateResult();
            }
        }

        /// <summary>
        /// Get the AppContainer SID from the AuthZ context.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The AppContainer SID.</returns>
        public NtResult<Sid> GetAppContainerSid(bool throw_on_error)
        {
            using (var acsid = QueryBuffer<TokenAppContainerInformation>(AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoAppContainerSid, throw_on_error))
            {
                if (!acsid.IsSuccess)
                    return acsid.Cast<Sid>();
                IntPtr ptr = acsid.Result.Result.TokenAppContainer;
                if (ptr == IntPtr.Zero)
                    return NtStatus.STATUS_INVALID_SID.CreateResultFromError<Sid>(throw_on_error);
                return Sid.Parse(acsid.Result.Result.TokenAppContainer, throw_on_error);
            }
        }

        /// <summary>
        /// Get AuthZ context's security attributes
        /// </summary>
        /// <param name="type">Specify the type of security attributes to query.</param>
        /// <param name="throw_on_error">Throw on error.</param>
        /// <returns>The security attributes.</returns>
        public NtResult<ClaimSecurityAttribute[]> GetSecurityAttributes(AuthZSecurityAttributeType type, bool throw_on_error)
        {
            var info_class = AttrTypeToInfoClass(type);
            using (var buf = QueryBuffer< ClaimSecurityAttributesInformation>(info_class, throw_on_error))
            {
                if (!buf.IsSuccess)
                    return buf.Cast<ClaimSecurityAttribute[]>();
                int struct_size = Marshal.SizeOf(typeof(ClaimSecurityAttributeV1));
                ClaimSecurityAttributesInformation r = buf.Result.Result;
                List<ClaimSecurityAttribute> attributes = new List<ClaimSecurityAttribute>();
                if (r.AttributeCount > 0)
                {
                    int count = r.AttributeCount;
                    IntPtr buffer = r.pAttributeV1;
                    while (count > 0)
                    {
                        attributes.Add(new ClaimSecurityAttribute(buffer, false));
                        count--;
                        buffer += struct_size;
                    }
                }
                return new NtResult<ClaimSecurityAttribute[]>(NtStatus.STATUS_SUCCESS, attributes.ToArray());
            }
        }

        /// <summary>
        /// Get token privileges.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of privileges.</returns>
        public NtResult<TokenPrivilege[]> GetPrivileges(bool throw_on_error)
        {
            using (var result = QueryBuffer<TokenPrivileges>(AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoPrivileges, throw_on_error))
            {
                if (!result.IsSuccess)
                    return result.Cast<TokenPrivilege[]>();
                var buffer = result.Result;
                int count = buffer.Result.PrivilegeCount;
                LuidAndAttributes[] attrs = new LuidAndAttributes[count];
                buffer.Data.ReadArray(0, attrs, 0, count);
                return attrs.Select(a => new TokenPrivilege(a.Luid, a.Attributes)).ToArray().CreateResult();
            }
        }

        /// <summary>
        /// Perform an Access Check.
        /// </summary>
        /// <param name="sd">The security descriptor for the check.</param>
        /// <param name="optional_sd">Optional list of security descriptors to merge.</param>
        /// <param name="desired_access">The desired access.</param>
        /// <param name="principal">Optional Principal SID.</param>
        /// <param name="object_types">Optional list of object types.</param>
        /// <param name="type">NT Type for access checking.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of access check results.</returns>
        /// <remarks>The list of object types is restricted to 256 entries for remote access checks.</remarks>
        public NtResult<AuthZAccessCheckResult[]> AccessCheck(SecurityDescriptor sd, IEnumerable<SecurityDescriptor> optional_sd,
            AccessMask desired_access, Sid principal, IEnumerable<ObjectTypeEntry> object_types, NtType type,
            bool throw_on_error)
        {
            if (sd is null)
            {
                throw new ArgumentNullException(nameof(sd));
            }

            if (type is null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            using (var list = new DisposableList())
            {
                AUTHZ_ACCESS_REQUEST request = new AUTHZ_ACCESS_REQUEST();
                request.DesiredAccess = desired_access;
                if (principal != null)
                {
                    request.PrincipalSelfSid = list.AddResource(principal.ToSafeBuffer()).DangerousGetHandle();
                }

                int result_count = 1;
                var object_list = NtSecurity.ConvertObjectTypes(object_types, list);
                if (object_list?.Length > 0)
                {
                    result_count = object_list.Length;
                    request.ObjectTypeList = list.AddResource(object_list.ToBuffer()).DangerousGetHandle();
                    request.ObjectTypeListLength = object_list.Length;
                }
                var sd_buffer = list.AddResource(sd.ToSafeBuffer());
                int optional_sd_count = optional_sd?.Count() ?? 0;
                IntPtr[] optional_sd_buffers = null;
                if (optional_sd_count > 0)
                {
                    optional_sd_buffers = optional_sd.Select(s => list.AddResource(s.ToSafeBuffer()).DangerousGetHandle()).ToArray();
                }
                AUTHZ_ACCESS_REPLY reply = new AUTHZ_ACCESS_REPLY();
                reply.ResultListLength = result_count;
                var error_buffer = list.AddResource(new int[result_count].ToBuffer());
                reply.Error = error_buffer.DangerousGetHandle();
                var access_buffer = list.AddResource(new AccessMask[result_count].ToBuffer());
                reply.GrantedAccessMask = access_buffer.DangerousGetHandle();
                var audit_buffer = list.AddResource(new int[result_count].ToBuffer());
                reply.SaclEvaluationResults = audit_buffer.DangerousGetHandle();

                return SecurityNativeMethods.AuthzAccessCheck(AuthZAccessCheckFlags.None, _handle,
                        ref request, IntPtr.Zero, sd_buffer, optional_sd_buffers, optional_sd_count,
                        ref reply, IntPtr.Zero).CreateWin32Result(throw_on_error,
                        () => CreateResult(result_count, error_buffer, access_buffer, object_types?.ToArray(), type));
            }
        }

        /// <summary>
        /// Perform an Access Check.
        /// </summary>
        /// <param name="sd">The security descriptor for the check.</param>
        /// <param name="optional_sd">Optional list of security descriptors to merge.</param>
        /// <param name="desired_access">The desired access.</param>
        /// <param name="principal">Optional Principal SID.</param>
        /// <param name="object_types">Optional list of object types.</param>
        /// <param name="type">NT Type for access checking.</param>
        /// <returns>The list of access check results.</returns>
        /// <remarks>The list of object types is restricted to 256 entries for remote access checks.</remarks>
        public AuthZAccessCheckResult[] AccessCheck(SecurityDescriptor sd, IEnumerable<SecurityDescriptor> optional_sd,
            AccessMask desired_access, Sid principal, IEnumerable<ObjectTypeEntry> object_types, NtType type)
        {
            return AccessCheck(sd, optional_sd, desired_access, principal, object_types, type, true).Result;
        }

        /// <summary>
        /// Dispose client context.
        /// </summary>
        public void Dispose()
        {
            ((IDisposable)_handle).Dispose();
        }

        /// <summary>
        /// Clone the current context.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The new client context.</returns>
        public NtResult<AuthZContext> Clone(bool throw_on_error)
        {
            return SecurityNativeMethods.AuthzInitializeContextFromAuthzContext(0, _handle, null, default,
                IntPtr.Zero,
                out SafeAuthZClientContextHandle new_handle)
                .CreateWin32Result(throw_on_error, () => new AuthZContext(new_handle, Remote));
        }

        /// <summary>
        /// Clone the current context.
        /// </summary>
        /// <returns>The new client context.</returns>
        public AuthZContext Clone()
        {
            return Clone(true).Result;
        }
        #endregion

        #region Internal Members
        internal static NtResult<AuthZContext> Create(SafeAuthZResourceManagerHandle resource_manager, NtToken token, bool remote, bool throw_on_error)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return SecurityNativeMethods.AuthzInitializeContextFromToken(0, token.Handle, resource_manager,
                null, default, IntPtr.Zero, out SafeAuthZClientContextHandle handle).CreateWin32Result(throw_on_error, () => new AuthZContext(handle, remote));
        }

        internal static NtResult<AuthZContext> Create(SafeAuthZResourceManagerHandle resource_manager, AuthZContextInitializeSidFlags flags, Sid sid, bool remote, bool throw_on_error)
        {
            if (sid is null)
            {
                throw new ArgumentNullException(nameof(sid));
            }

            using (var buffer = sid.ToSafeBuffer())
            {
                return SecurityNativeMethods.AuthzInitializeContextFromSid(flags, buffer, resource_manager,
                    null, default, IntPtr.Zero, out SafeAuthZClientContextHandle handle).CreateWin32Result(throw_on_error, () => new AuthZContext(handle, remote));
            }
        }

        #endregion
    }
}
