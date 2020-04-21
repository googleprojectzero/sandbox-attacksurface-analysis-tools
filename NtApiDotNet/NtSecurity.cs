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

using NtApiDotNet.Security.Policy;
using NtApiDotNet.Win32;
using NtApiDotNet.Win32.SafeHandles;
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
    /// <summary>
    /// Static class to access NT security manager routines.
    /// </summary>
    public static class NtSecurity
    {
        #region Static Methods

        /// <summary>
        /// Looks up the account name of a SID. 
        /// </summary>
        /// <param name="sid">The SID to lookup</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The name, or null if the lookup failed</returns>
        public static NtResult<string> LookupAccountSid(Sid sid, bool throw_on_error)
        {
            using (SafeSidBufferHandle sid_buffer = sid.ToSafeBuffer())
            {
                StringBuilder name = new StringBuilder(1024);
                int length = name.Capacity;
                StringBuilder domain = new StringBuilder(1024);
                int domain_length = domain.Capacity;
                if (!Win32NativeMethods.LookupAccountSid(null, sid_buffer, name,
                    ref length, domain, ref domain_length, out SidNameUse name_use))
                {
                    return NtObjectUtils.CreateResultFromDosError<string>(throw_on_error);
                }

                if (domain_length == 0)
                {
                    return name.ToString().CreateResult();
                }
                else
                {
                    return $@"{domain}\{name}".CreateResult();
                }
            }
        }

        /// <summary>
        /// Looks up the account name of a SID. 
        /// </summary>
        /// <param name="sid">The SID to lookup</param>
        /// <returns>The name, or null if the lookup failed</returns>
        public static string LookupAccountSid(Sid sid)
        {
            return LookupAccountSid(sid, false).GetResultOrDefault();
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
            if (!Win32NativeMethods.LookupAccountName(null, username, SafeHGlobalBuffer.Null, ref sid_length,
                SafeHGlobalBuffer.Null, ref domain_length, out SidNameUse name))
            {
                if (sid_length <= 0)
                {
                    throw new NtException(NtStatus.STATUS_INVALID_USER_PRINCIPAL_NAME);
                }
            }

            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(sid_length), domain = new SafeHGlobalBuffer(domain_length * 2))
            {
                if (!Win32NativeMethods.LookupAccountName(null, username, buffer, ref sid_length, domain, ref domain_length, out name))
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

            return $"{(ProcessTrustType)trust_sid.SubAuthorities[0]}-{(ProcessTrustLevel)trust_sid.SubAuthorities[1]}";
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
            using (var key = NtKey.GetCurrentUserKey(false))
            {
                if (key.IsSuccess)
                {
                    ret = ReadMoniker(key.Result, sid);
                }
            }
            
            if (ret == null)
            {
                using (var key = NtKey.GetMachineKey(false))
                {
                    if (key.IsSuccess)
                    {
                        ret = ReadMoniker(key.Result, sid);
                    }
                }
            }

            return ret;
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

        /// <summary>
        /// Convert a security descriptor to SDDL string
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="security_information">Indicates what parts of the security descriptor to include</param>
        /// <returns>The SDDL string</returns>
        /// <exception cref="NtException">Thrown if cannot convert to a SDDL string.</exception>
        public static string SecurityDescriptorToSddl(byte[] sd, SecurityInformation security_information)
        {
            using (var buffer = sd.ToBuffer())
            {
                return SecurityDescriptorToSddl(buffer, security_information, true).Result;
            }
        }

        /// <summary>
        /// Convert a security descriptor to SDDL string
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="security_information">Indicates what parts of the security descriptor to include</param>
        /// <param name="throw_on_error">True to throw on errror.</param>
        /// <returns>The SDDL string</returns>
        /// <exception cref="NtException">Thrown if cannot convert to a SDDL string.</exception>
        public static NtResult<string> SecurityDescriptorToSddl(SafeBuffer sd, SecurityInformation security_information, bool throw_on_error)
        {
            if (!Win32NativeMethods.ConvertSecurityDescriptorToStringSecurityDescriptor(sd,
                1, security_information, out SafeLocalAllocBuffer buffer, out int return_length))
            {
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<string>(throw_on_error);
            }

            using (buffer)
            {
                return Marshal.PtrToStringUni(buffer.DangerousGetHandle()).CreateResult();
            }
        }

        /// <summary>
        /// Convert an SDDL string to a binary security descriptor
        /// </summary>
        /// <param name="sddl">The SDDL string</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The binary security descriptor</returns>
        /// <exception cref="NtException">Thrown if cannot convert from a SDDL string.</exception>
        public static NtResult<SafeBuffer> SddlToSecurityDescriptorBuffer(string sddl, bool throw_on_error)
        {
            if (!Win32NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1,
                out SafeLocalAllocBuffer buffer, out int return_length))
            {
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<SafeBuffer>(throw_on_error);
            }

            buffer.Initialize((ulong)return_length);
            return buffer.CreateResult<SafeBuffer>();
        }

        /// <summary>
        /// Convert an SDDL string to a binary security descriptor
        /// </summary>
        /// <param name="sddl">The SDDL string</param>
        /// <returns>The binary security descriptor</returns>
        /// <exception cref="NtException">Thrown if cannot convert from a SDDL string.</exception>
        public static SafeBuffer SddlToSecurityDescriptorBuffer(string sddl)
        {
            return SddlToSecurityDescriptorBuffer(sddl, true).Result;
        }

        /// <summary>
        /// Convert an SDDL string to a binary security descriptor
        /// </summary>
        /// <param name="sddl">The SDDL string</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The binary security descriptor</returns>
        /// <exception cref="NtException">Thrown if cannot convert from a SDDL string.</exception>
        public static NtResult<byte[]> SddlToSecurityDescriptor(string sddl, bool throw_on_error)
        {
            if (!Win32NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1,
                out SafeLocalAllocBuffer buffer, out int return_length))
            {
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<byte[]>(throw_on_error);
            }

            using (buffer)
            {
                byte[] ret = new byte[return_length];
                Marshal.Copy(buffer.DangerousGetHandle(), ret, 0, return_length);
                return ret.CreateResult();
            }
        }

        /// <summary>
        /// Convert an SDDL string to a binary security descriptor
        /// </summary>
        /// <param name="sddl">The SDDL string</param>
        /// <returns>The binary security descriptor</returns>
        /// <exception cref="NtException">Thrown if cannot convert from a SDDL string.</exception>
        public static byte[] SddlToSecurityDescriptor(string sddl)
        {
            return SddlToSecurityDescriptor(sddl, true).Result;
        }

        /// <summary>
        /// Convert an SDDL SID string to a Sid
        /// </summary>
        /// <param name="sddl">The SDDL SID string</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The converted Sid</returns>
        /// <exception cref="NtException">Thrown if cannot convert from a SDDL string.</exception>
        public static NtResult<Sid> SidFromSddl(string sddl, bool throw_on_error)
        {
            var result = ParseSidString(sddl);
            if (result.IsSuccess)
                return result;

            // If our managed parser fails try the Win32 API.
            if (!Win32NativeMethods.ConvertStringSidToSid(sddl, out SafeLocalAllocBuffer buffer))
            {
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<Sid>(throw_on_error);
            }
            using (buffer)
            {
                return new Sid(buffer.DangerousGetHandle()).CreateResult();
            }
        }

        /// <summary>
        /// Convert an SDDL SID string to a Sid
        /// </summary>
        /// <param name="sddl">The SDDL SID string</param>
        /// <returns>The converted Sid</returns>
        /// <exception cref="NtException">Thrown if cannot convert from a SDDL string.</exception>
        public static Sid SidFromSddl(string sddl)
        {
            return SidFromSddl(sddl, true).Result;
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// This function returns a list of results rather than a single entry. It should only be used
        /// with object types.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <param name="object_types">List of object types to check against.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of access check results.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static NtResult<AccessCheckResult[]> AccessCheckWithResultList(SecurityDescriptor sd, NtToken token,
            AccessMask desired_access, Sid principal, GenericMapping generic_mapping, IEnumerable<ObjectTypeEntry> object_types,
            bool throw_on_error)
        {
            return AccessCheckWithResultList(sd, token, desired_access, principal, generic_mapping, object_types,
                NtSystemCalls.NtAccessCheckByTypeResultList, throw_on_error);
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// This function returns a list of results rather than a single entry. It should only be used
        /// with object types.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <param name="object_types">List of object types to check against.</param>
        /// <returns>The list of access check results.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessCheckResult[] AccessCheckWithResultList(SecurityDescriptor sd, NtToken token,
            AccessMask desired_access, Sid principal, GenericMapping generic_mapping, IEnumerable<ObjectTypeEntry> object_types)
        {
            return AccessCheckWithResultList(sd, token, desired_access, principal, generic_mapping, object_types, true).Result;
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <param name="object_types">List of object types to check against.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the access check.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static NtResult<AccessCheckResult> AccessCheck(SecurityDescriptor sd, NtToken token,
            AccessMask desired_access, Sid principal, GenericMapping generic_mapping, IEnumerable<ObjectTypeEntry> object_types,
            bool throw_on_error)
        {
            return AccessCheckByType(sd, token, desired_access, principal, 
                generic_mapping, object_types, NtSystemCalls.NtAccessCheckByType, throw_on_error);
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <param name="object_types">List of object types to check against.</param>
        /// <returns>The result of the access check.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessCheckResult AccessCheck(SecurityDescriptor sd, NtToken token,
            AccessMask desired_access, Sid principal, GenericMapping generic_mapping, IEnumerable<ObjectTypeEntry> object_types)
        {
            return AccessCheck(sd, token, desired_access, principal, generic_mapping, object_types, true).Result;
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <param name="object_types">List of object types to check against.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the access check.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static NtResult<AccessCheckResult<T>> AccessCheck<T>(SecurityDescriptor sd, NtToken token,
            T desired_access, Sid principal, GenericMapping generic_mapping, IEnumerable<ObjectTypeEntry> object_types,
            bool throw_on_error) where T : Enum
        {
            return AccessCheck(sd, token, (AccessMask)desired_access, principal, 
                generic_mapping, object_types, throw_on_error).Map(r => r.ToSpecificAccess<T>());
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <param name="object_types">List of object types to check against.</param>
        /// <returns>The result of the access check.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessCheckResult<T> AccessCheck<T>(SecurityDescriptor sd, NtToken token,
            T desired_access, Sid principal, GenericMapping generic_mapping, IEnumerable<ObjectTypeEntry> object_types) 
                where T : Enum
        {
            return AccessCheck(sd, token, desired_access, principal, generic_mapping, object_types, true).Result;
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the access check.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static NtResult<AccessCheckResult> AccessCheck(SecurityDescriptor sd, NtToken token,
            AccessMask desired_access, Sid principal, GenericMapping generic_mapping,
            bool throw_on_error)
        {
            return AccessCheck(sd, token, desired_access, principal, generic_mapping, null, throw_on_error);
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the access check.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static NtResult<AccessCheckResult<T>> AccessCheck<T>(SecurityDescriptor sd, NtToken token,
            T desired_access, Sid principal, GenericMapping generic_mapping,
            bool throw_on_error) where T : Enum
        {
            return AccessCheck(sd, token, desired_access, principal, generic_mapping, null, throw_on_error);
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <returns>The result of the access check.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessCheckResult AccessCheck(SecurityDescriptor sd, NtToken token,
            AccessMask desired_access, Sid principal, GenericMapping generic_mapping)
        {
            return AccessCheck(sd, token, desired_access, principal, generic_mapping, true).Result;
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access.
        /// </summary>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <returns>The result of the access check.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessCheckResult<T> AccessCheck<T>(SecurityDescriptor sd, NtToken token,
            T desired_access, Sid principal, GenericMapping generic_mapping) where T : Enum
        {
            return AccessCheck(sd, token, desired_access, principal, generic_mapping, true).Result;
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
            return AccessCheck(sd, token, access_rights, principal, generic_mapping, true).Result.GrantedAccess;
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
        /// <returns>The named resource security descriptor. Returns null if can't open the resource.</returns>
        public static SecurityDescriptor FromNamedObject(string name, string type)
        {
            using (var obj = NtObject.OpenWithType(type, name, null, AttributeFlags.CaseInsensitive, 
                GenericAccessRights.ReadControl, null, false))
            {
                if (!obj.IsSuccess)
                    return null;
                var sd = obj.Result.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
                if (!sd.IsSuccess)
                    return null;
                return sd.Result;
            }
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access and
        /// audit the result.
        /// </summary>
        /// <param name="subsystem_name">The name of the subsystem to audit.</param>
        /// <param name="handle_id">The handle ID to audit. Used when issuing a close audit.</param>
        /// <param name="object_type_name">The object type name.</param>
        /// <param name="object_name">The name of the object.</param>
        /// <param name="object_creation">Indicates if this is an object creation operation.</param>
        /// <param name="audit_type">Type of audit.</param>
        /// <param name="flags">Flags for the audit operation.</param>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <param name="object_types">List of object types to check against.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the access check.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static NtResult<AccessCheckResult> AccessCheckAudit(
            string subsystem_name,
            IntPtr handle_id,
            string object_type_name,
            string object_name,
            bool object_creation,
            AuditEventType audit_type,
            AuditAccessCheckFlags flags,
            SecurityDescriptor sd, 
            NtToken token,
            AccessMask desired_access, 
            Sid principal, 
            GenericMapping generic_mapping, 
            IEnumerable<ObjectTypeEntry> object_types,
            bool throw_on_error)
        {
            var context = new AuditAccessCheckContext(
                subsystem_name, handle_id, 
                object_type_name, object_name, object_creation,
                audit_type, flags);
            return AccessCheckByType(sd, token, desired_access, principal,
                generic_mapping, object_types, 
                context.AccessCheckByType, throw_on_error).Map(context.Map);
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access and
        /// audit the result.
        /// </summary>
        /// <param name="subsystem_name">The name of the subsystem to audit.</param>
        /// <param name="handle_id">The handle ID to audit. Used when issuing a close audit.</param>
        /// <param name="object_type_name">The object type name.</param>
        /// <param name="object_name">The name of the object.</param>
        /// <param name="object_creation">Indicates if this is an object creation operation.</param>
        /// <param name="audit_type">Type of audit.</param>
        /// <param name="flags">Flags for the audit operation.</param>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <param name="object_types">List of object types to check against.</param>
        /// <returns>The result of the access check.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessCheckResult AccessCheckAudit(
            string subsystem_name,
            IntPtr handle_id,
            string object_type_name,
            string object_name,
            bool object_creation,
            AuditEventType audit_type,
            AuditAccessCheckFlags flags,
            SecurityDescriptor sd,
            NtToken token,
            AccessMask desired_access,
            Sid principal,
            GenericMapping generic_mapping,
            IEnumerable<ObjectTypeEntry> object_types)
        {
            return AccessCheckAudit(subsystem_name,
                handle_id, object_type_name, object_name,
                object_creation, audit_type, flags, sd, token,
                desired_access, principal, generic_mapping,
                object_types, true).Result;
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access
        /// and audit. This function returns a list of results rather than a single entry. It should only
        /// be used with object types.
        /// </summary>
        /// <param name="subsystem_name">The name of the subsystem to audit.</param>
        /// <param name="handle_id">The handle ID to audit. Used when issuing a close audit.</param>
        /// <param name="object_type_name">The object type name.</param>
        /// <param name="object_name">The name of the object.</param>
        /// <param name="object_creation">Indicates if this is an object creation operation.</param>
        /// <param name="audit_type">Type of audit.</param>
        /// <param name="flags">Flags for the audit operation.</param>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <param name="object_types">List of object types to check against.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the access check.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static NtResult<AccessCheckResult[]> AccessCheckWithResultListAudit(
            string subsystem_name,
            IntPtr handle_id,
            string object_type_name,
            string object_name,
            bool object_creation,
            AuditEventType audit_type,
            AuditAccessCheckFlags flags,
            SecurityDescriptor sd,
            NtToken token,
            AccessMask desired_access,
            Sid principal,
            GenericMapping generic_mapping,
            IEnumerable<ObjectTypeEntry> object_types,
            bool throw_on_error)
        {
            var context = new AuditAccessCheckContext(
                subsystem_name, handle_id,
                object_type_name, object_name, object_creation,
                audit_type, flags);
            return AccessCheckWithResultList(sd, token, desired_access, principal,
                generic_mapping, object_types,
                context.AccessCheckWithResultList, throw_on_error).Map(r => r.Select(context.Map).ToArray());
        }

        /// <summary>
        /// Do an access check between a security descriptor and a token to determine the allowed access
        /// and audit. This function returns a list of results rather than a single entry. It should only
        /// be used with object types.
        /// </summary>
        /// <param name="subsystem_name">The name of the subsystem to audit.</param>
        /// <param name="handle_id">The handle ID to audit. Used when issuing a close audit.</param>
        /// <param name="object_type_name">The object type name.</param>
        /// <param name="object_name">The name of the object.</param>
        /// <param name="object_creation">Indicates if this is an object creation operation.</param>
        /// <param name="audit_type">Type of audit.</param>
        /// <param name="flags">Flags for the audit operation.</param>
        /// <param name="sd">The security descriptor</param>
        /// <param name="token">The access token.</param>
        /// <param name="desired_access">The set of access rights to check against</param>
        /// <param name="principal">An optional principal SID used to replace the SELF SID in a security descriptor.</param>
        /// <param name="generic_mapping">The type specific generic mapping (get from corresponding NtType entry).</param>
        /// <param name="object_types">List of object types to check against.</param>
        /// <returns>The result of the access check.</returns>
        /// <exception cref="NtException">Thrown if an error occurred in the access check.</exception>
        public static AccessCheckResult[] AccessCheckWithResultListAudit(
            string subsystem_name,
            IntPtr handle_id,
            string object_type_name,
            string object_name,
            bool object_creation,
            AuditEventType audit_type,
            AuditAccessCheckFlags flags,
            SecurityDescriptor sd,
            NtToken token,
            AccessMask desired_access,
            Sid principal,
            GenericMapping generic_mapping,
            IEnumerable<ObjectTypeEntry> object_types)
        {
            return AccessCheckWithResultListAudit(subsystem_name,
                handle_id, object_type_name, object_name,
                object_creation, audit_type, flags, sd, token,
                desired_access, principal, generic_mapping,
                object_types, true).Result;
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
        /// Checks if a SID is a logon session SID.
        /// </summary>
        /// <param name="sid">The sid to check.</param>
        /// <returns>True if a logon session sid.</returns>
        public static bool IsLogonSessionSid(Sid sid)
        {
            return sid.Authority.IsAuthority(SecurityAuthority.Nt) && sid.SubAuthorities.Count == 3 && sid.SubAuthorities[0] == 5;
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

        /// <summary>
        /// Get a capability sid by name.
        /// </summary>
        /// <param name="capability_name">The name of the capability.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The capability SID.</returns>
        public static NtResult<Sid> GetCapabilitySid(string capability_name, bool throw_on_error)
        {
            using (SafeHGlobalBuffer cap_sid = new SafeHGlobalBuffer(Sid.MaximumSidSize),
                cap_group_sid = new SafeHGlobalBuffer(Sid.MaximumSidSize))
            {
                return NtRtl.RtlDeriveCapabilitySidsFromName(
                    new UnicodeString(capability_name),
                    cap_group_sid, cap_sid)
                    .CreateResult(throw_on_error, () 
                    => CacheSidName(new Sid(cap_sid), capability_name, SidNameSource.Capability));
            }
        }

        /// <summary>
        /// Get a capability sid by name.
        /// </summary>
        /// <param name="capability_name">The name of the capability.</param>
        /// <returns>The capability SID.</returns>
        public static Sid GetCapabilitySid(string capability_name)
        {
            return GetCapabilitySid(capability_name, true).Result;
        }

        /// <summary>
        /// Get a capability group sid by name.
        /// </summary>
        /// <param name="capability_name">The name of the capability.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The capability SID.</returns>
        public static NtResult<Sid> GetCapabilityGroupSid(string capability_name, bool throw_on_error)
        {
            using (SafeHGlobalBuffer cap_sid = new SafeHGlobalBuffer(Sid.MaximumSidSize),
                cap_group_sid = new SafeHGlobalBuffer(Sid.MaximumSidSize))
            {
                return NtRtl.RtlDeriveCapabilitySidsFromName(
                    new UnicodeString(capability_name),
                    cap_group_sid, cap_sid).CreateResult(throw_on_error, 
                    () => CacheSidName(new Sid(cap_group_sid), capability_name, SidNameSource.Capability));
            }
        }

        /// <summary>
        /// Get a capability group sid by name.
        /// </summary>
        /// <param name="capability_name">The name of the capability.</param>
        /// <returns>The capability SID.</returns>
        public static Sid GetCapabilityGroupSid(string capability_name)
        {
            return GetCapabilityGroupSid(capability_name, true).Result;
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

        /// <summary>
        /// Checks if a SID is a Scoped Policy ID SID.
        /// </summary>
        /// <param name="sid">The SID to check.</param>
        /// <returns>True if a Scoped Policy ID SID.</returns>
        public static bool IsScopedPolicySid(Sid sid)
        {
            return sid.Authority.IsAuthority(SecurityAuthority.ScopedPolicyId);
        }

        /// <summary>
        /// Converts conditional ACE data to an SDDL string
        /// </summary>
        /// <param name="conditional_data">The conditional application data.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The conditional ACE string.</returns>
        public static NtResult<string> ConditionalAceToString(byte[] conditional_data, bool throw_on_error)
        {
            SecurityDescriptor sd = new SecurityDescriptor
            {
                Dacl = new Acl
                {
                    NullAcl = false
                }
            };
            sd.Dacl.Add(new Ace(AceType.AllowedCallback, AceFlags.None, 0, KnownSids.World) { ApplicationData = conditional_data });
            var sddl = sd.ToSddl(throw_on_error);
            if (!sddl.IsSuccess)
                return sddl.Cast<string>();
            var matches = ConditionalAceRegex.Match(sddl.Result);

            if (!matches.Success || matches.Groups.Count != 2)
            {
                return NtStatus.STATUS_INVALID_ACE_CONDITION.CreateResultFromError<string>(throw_on_error);

            }
            return matches.Groups[1].Value.CreateResult();
        }

        /// <summary>
        /// Converts conditional ACE data to an SDDL string
        /// </summary>
        /// <param name="conditional_data">The conditional application data.</param>
        /// <returns>The conditional ACE string.</returns>
        public static string ConditionalAceToString(byte[] conditional_data)
        {
            return ConditionalAceToString(conditional_data, true).Result;
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
        /// Evaluate a condition ACE expression.
        /// </summary>
        /// <param name="token">The Token to check against.</param>
        /// <param name="condition_sddl">The conditional expression in SDDL format.</param>
        /// <param name="resource_attributes">Specify resource attributes to add to the check.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>True if the conditional expression was a success.</returns>
        public static NtResult<bool> EvaluateConditionAce(NtToken token, string condition_sddl, IEnumerable<ClaimSecurityAttribute> resource_attributes, bool throw_on_error)
        {
            var sd = SecurityDescriptor.Parse($"O:S-1-0-0G:S-1-0-0D:(XA;;1;;;{token.User.Sid};({condition_sddl}))S:(ML;;NW;;;S-1-16-0)", throw_on_error);
            if (!sd.IsSuccess)
            {
                return sd.Cast<bool>();
            }

            if (resource_attributes?.Any() ?? false)
            {
                sd.Result.Sacl.AddRange(resource_attributes.Select(r => r.ToAce()));
            }

            return EvaluateConditionAce(token, sd.Result, throw_on_error);
        }

        /// <summary>
        /// Evaluate a condition ACE expression.
        /// </summary>
        /// <param name="token">The Token to check against.</param>
        /// <param name="condition_sddl">The conditional expression in SDDL format.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>True if the conditional expression was a success.</returns>
        public static NtResult<bool> EvaluateConditionAce(NtToken token, string condition_sddl, bool throw_on_error)
        {
            return EvaluateConditionAce(token, condition_sddl, new ClaimSecurityAttribute[0], throw_on_error);
        }

        /// <summary>
        /// Evaluate a condition ACE expression.
        /// </summary>
        /// <param name="token">The Token to check against.</param>
        /// <param name="condition_sddl">The conditional expression in SDDL format.</param>
        /// <param name="resource_attributes">Specify resource attributes to add to the check.</param>
        /// <returns>True if the conditional expression was a success.</returns>
        public static bool EvaluateConditionAce(NtToken token, string condition_sddl, 
            IEnumerable<ClaimSecurityAttribute> resource_attributes)
        {
            return EvaluateConditionAce(token, condition_sddl, resource_attributes, true).Result;
        }


        /// <summary>
        /// Evaluate a condition ACE expression.
        /// </summary>
        /// <param name="token">The Token to check against.</param>
        /// <param name="condition_sddl">The conditional expression in SDDL format.</param>
        /// <returns>True if the conditional expression was a success.</returns>
        public static bool EvaluateConditionAce(NtToken token, string condition_sddl)
        {
            return EvaluateConditionAce(token, condition_sddl, true).Result;
        }

        /// <summary>
        /// Evaluate a condition ACE expression.
        /// </summary>
        /// <param name="token">The Token to check against.</param>
        /// <param name="condition_data">The conditional expression in binary format.</param>
        /// <param name="resource_attributes">Specify resource attributes to add to the check.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>True if the conditional expression was a success.</returns>
        public static NtResult<bool> EvaluateConditionAce(NtToken token, byte[] condition_data, 
            IEnumerable<ClaimSecurityAttribute> resource_attributes, bool throw_on_error)
        {
            SecurityDescriptor sd = new SecurityDescriptor
            {
                Owner = new SecurityDescriptorSid(new Sid("S-1-0-0"), false),
                Group = new SecurityDescriptorSid(new Sid("S-1-0-0"), false),
                Dacl = new Acl
                {
                    NullAcl = false
                }
            };
            sd.Dacl.Add(new Ace(AceType.AllowedCallback,
                AceFlags.None, 1, token.User.Sid)
            { ApplicationData = condition_data });
            sd.AddMandatoryLabel(TokenIntegrityLevel.Untrusted);
            if (resource_attributes?.Any() ?? false)
            {
                sd.Sacl.AddRange(resource_attributes
                    .Select(r => r.ToAce()));
            }
            return EvaluateConditionAce(token, sd, throw_on_error);
        }

        /// <summary>
        /// Evaluate a condition ACE expression.
        /// </summary>
        /// <param name="token">The Token to check against.</param>
        /// <param name="condition_data">The conditional expression in binary format.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>True if the conditional expression was a success.</returns>
        public static NtResult<bool> EvaluateConditionAce(NtToken token, byte[] condition_data, bool throw_on_error)
        {
            return EvaluateConditionAce(token, condition_data, new ClaimSecurityAttribute[0], throw_on_error);
        }

        /// <summary>
        /// Evaluate a condition ACE expression.
        /// </summary>
        /// <param name="token">The Token to check against.</param>
        /// <param name="condition_data">The conditional expression in binary format.</param>
        /// <param name="resource_attributes">Specify resource attributes to add to the check.</param>
        /// <returns>True if the conditional expression was a success.</returns>
        public static bool EvaluateConditionAce(NtToken token, byte[] condition_data, IEnumerable<ClaimSecurityAttribute> resource_attributes)
        {
            return EvaluateConditionAce(token, condition_data, resource_attributes, true).Result;
        }

        /// <summary>
        /// Evaluate a condition ACE expression.
        /// </summary>
        /// <param name="token">The Token to check against.</param>
        /// <param name="condition_data">The conditional expression in binary format.</param>
        /// <returns>True if the conditional expression was a success.</returns>
        public static bool EvaluateConditionAce(NtToken token, byte[] condition_data)
        {
            return EvaluateConditionAce(token, condition_data, true).Result;
        }

        /// <summary>
        /// Get the cached signing level for a file.
        /// </summary>
        /// <param name="handle">The handle to the file to query.</param>
        /// <returns>The cached signing level.</returns>
        public static CachedSigningLevel GetCachedSigningLevel(SafeKernelObjectHandle handle)
        {
            return GetCachedSigningLevel(handle, true).Result;
        }

        /// <summary>
        /// Get the cached signing level for a file.
        /// </summary>
        /// <param name="handle">The handle to the file to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The cached signing level.</returns>
        public static NtResult<CachedSigningLevel> GetCachedSigningLevel(SafeKernelObjectHandle handle, bool throw_on_error)
        {
            byte[] thumb_print = new byte[0x68];
            int thumb_print_size = thumb_print.Length;

            return NtSystemCalls.NtGetCachedSigningLevel(handle, out int flags,
                out SigningLevel signing_level, thumb_print, ref thumb_print_size, out HashAlgorithm thumb_print_algo).CreateResult(throw_on_error, () =>
                {
                    Array.Resize(ref thumb_print, thumb_print_size);
                    return new CachedSigningLevel(flags, signing_level, thumb_print, thumb_print_algo);
                });
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
            SetCachedSigningLevel(handle, flags, signing_level, source_files, catalog_path, true);
        }

        /// <summary>
        /// Set the cached signing level for a file.
        /// </summary>
        /// <param name="handle">The handle to the file to set the cache on.</param>
        /// <param name="flags">Flags to set for the cache.</param>
        /// <param name="signing_level">The signing level to cache</param>
        /// <param name="source_files">A list of source file for the cache.</param>
        /// <param name="catalog_path">Optional directory path to look for catalog files.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        public static NtStatus SetCachedSigningLevel(SafeKernelObjectHandle handle,
                                                     int flags, SigningLevel signing_level,
                                                     IEnumerable<SafeKernelObjectHandle> source_files,
                                                     string catalog_path, bool throw_on_error)
        {
            IntPtr[] handles = source_files?.Select(f => f.DangerousGetHandle()).ToArray();
            int handles_count = handles == null ? 0 : handles.Length;
            if (catalog_path != null)
            {
                CachedSigningLevelInformation info = new CachedSigningLevelInformation(catalog_path);
                return NtSystemCalls.NtSetCachedSigningLevel2(flags, signing_level, handles, 
                    handles_count, handle, info).ToNtException(throw_on_error);
            }
            else
            {
                return NtSystemCalls.NtSetCachedSigningLevel(flags, signing_level, handles, 
                    handles_count, handle).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Compare two signing levels.
        /// </summary>
        /// <param name="current_level">The current level.</param>
        /// <param name="signing_level">The signing level to compare against.</param>
        /// <returns>True if the current level is above or equal to the signing level.</returns>
        public static bool CompareSigningLevel(SigningLevel current_level, SigningLevel signing_level)
        {
            return NtSystemCalls.NtCompareSigningLevel(current_level, signing_level).IsSuccess();
        }

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
            return _cached_names.AddOrUpdate(sid, s => GetNameForSidInternal(s), (s, v) => {
                if (v.LookupDenied)
                    return GetNameForSidInternal(s);
                else
                    return v;
            });
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

        /// <summary>
        /// Get a logon session SID from an ID.
        /// </summary>
        /// <param name="session_id">The logon session ID.</param>
        /// <returns>The new logon session SID.</returns>
        public static Sid GetLogonSessionSid(Luid session_id)
        {
            return new Sid(SecurityAuthority.Nt, 5, 
                (uint)session_id.HighPart, session_id.LowPart);
        }

        /// <summary>
        /// Get a new logon session SID.
        /// </summary>
        /// <returns>The new logon session SID.</returns>
        public static Sid GetLogonSessionSid()
        {
            return GetLogonSessionSid(NtSystemInfo.AllocateLocallyUniqueId());
        }

        /// <summary>
        /// Get session id from logon session SID.
        /// </summary>
        /// <param name="sid">The logon session SID.</param>
        /// <returns>The logon session ID.</returns>
        public static Luid GetLogonSessionId(Sid sid)
        {
            if (!IsLogonSessionSid(sid))
            {
                throw new ArgumentException("Must specify logon session SID", "sid");
            }
            return new Luid(sid.SubAuthorities[2], (int)sid.SubAuthorities[1]);
        }

        /// <summary>
        /// Get security descriptor as a byte array
        /// </summary>
        /// <param name="handle">Handle to the object to query.</param>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <return>The NT status result and security descriptor as a buffer.</return>
        public static NtResult<SafeHGlobalBuffer> GetSecurityDescriptor(SafeKernelObjectHandle handle, SecurityInformation security_information, bool throw_on_error)
        {
            NtStatus status = NtSystemCalls.NtQuerySecurityObject(handle, security_information, SafeHGlobalBuffer.Null, 
                0, out int return_length);
            if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
            {
                return status.CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
            }

            using (var buffer = new SafeHGlobalBuffer(return_length))
            {
                return NtSystemCalls.NtQuerySecurityObject(handle, security_information, buffer,
                    buffer.Length, out return_length).CreateResult(throw_on_error, () => buffer.Detach());
            }
        }

        /// <summary>
        /// Set the object's security descriptor
        /// </summary>
        /// <param name="handle">Handle to the object to set.</param>
        /// <param name="security_desc">The security descriptor to set.</param>
        /// <param name="security_information">What parts of the security descriptor to set</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <return>The NT status result.</return>
        public static NtStatus SetSecurityDescriptor(SafeKernelObjectHandle handle, SafeBuffer security_desc, 
            SecurityInformation security_information, bool throw_on_error)
        {
            return NtSystemCalls.NtSetSecurityObject(handle, security_information, security_desc).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Do a privilege check on a token.
        /// </summary>
        /// <param name="handle">A handle to a token object.</param>
        /// <param name="privileges">The list of privileges to check.</param>
        /// <param name="all_necessary">True to require all necessary privileges.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The privilege check result.</returns>
        public static NtResult<PrivilegeCheckResult> PrivilegeCheck(SafeKernelObjectHandle handle, IEnumerable<TokenPrivilege> privileges, bool all_necessary, bool throw_on_error)
        {
            using (var privs = new SafePrivilegeSetBuffer(privileges,
                all_necessary ? PrivilegeSetControlFlags.AllNecessary : PrivilegeSetControlFlags.None))
            {
                return NtSystemCalls.NtPrivilegeCheck(handle, privs, out bool result).CreateResult(throw_on_error, () => new PrivilegeCheckResult(privs, result));
            }
        }

        /// <summary>
        /// Get the access mask for querying a specific security information class.
        /// </summary>
        /// <param name="SecurityInformation">The information class.</param>
        /// <returns>The access mask for the information.</returns>
        public static AccessMask QuerySecurityAccessMask(SecurityInformation SecurityInformation)
        {
            AccessMask mask = 0;
            if (SecurityInformation.HasFlagSet(SecurityInformation.Backup))
                mask |= GenericAccessRights.ReadControl | GenericAccessRights.AccessSystemSecurity;
            if (SecurityInformation.HasFlagSet(SecurityInformation.Dacl |
                SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Label))
            {
                mask |= GenericAccessRights.ReadControl;
            }
            if (SecurityInformation.HasFlagSet(SecurityInformation.Attribute))
                mask |= GenericAccessRights.ReadControl;
            if (SecurityInformation.HasFlagSet(SecurityInformation.Scope))
                mask |= GenericAccessRights.ReadControl;
            if (SecurityInformation.HasFlagSet(SecurityInformation.ProcessTrustLabel))
                mask |= GenericAccessRights.ReadControl;
            if (SecurityInformation.HasFlagSet(SecurityInformation.AccessFilter))
                mask |= GenericAccessRights.ReadControl;
            if (SecurityInformation.HasFlag(SecurityInformation.Sacl))
                mask |= GenericAccessRights.AccessSystemSecurity;
            return mask;
        }

        /// <summary>
        /// Get the access mask for setting a specific security information class.
        /// </summary>
        /// <param name="SecurityInformation">The information class.</param>
        /// <returns>The access mask for the information.</returns>
        public static AccessMask SetSecurityAccessMask(SecurityInformation SecurityInformation)
        {
            AccessMask mask = 0;
            if (SecurityInformation.HasFlagSet(SecurityInformation.Backup))
                mask |= GenericAccessRights.WriteDac | GenericAccessRights.WriteOwner | GenericAccessRights.AccessSystemSecurity;
            if (SecurityInformation.HasFlagSet(SecurityInformation.Label | SecurityInformation.Owner | SecurityInformation.Group))
                mask |= GenericAccessRights.WriteOwner;
            if (SecurityInformation.HasFlagSet(SecurityInformation.Dacl))
                mask |= GenericAccessRights.WriteDac;
            if (SecurityInformation.HasFlagSet(SecurityInformation.Attribute))
                mask |= GenericAccessRights.WriteDac;
            if (SecurityInformation.HasFlagSet(SecurityInformation.Scope))
                mask |= GenericAccessRights.AccessSystemSecurity;
            if (SecurityInformation.HasFlagSet(SecurityInformation.ProcessTrustLabel))
                mask |= GenericAccessRights.WriteDac;
            if (SecurityInformation.HasFlagSet(SecurityInformation.AccessFilter))
                mask |= GenericAccessRights.WriteDac;
            if (SecurityInformation.HasFlagSet(SecurityInformation.Sacl))
                mask |= GenericAccessRights.AccessSystemSecurity;
            if (SecurityInformation.HasFlagSet(SecurityInformation.Sacl | SecurityInformation.Label | SecurityInformation.Attribute 
                | SecurityInformation.Scope | SecurityInformation.ProcessTrustLabel | SecurityInformation.AccessFilter))
            {
                if (SecurityInformation.HasFlagSet(SecurityInformation.ProtectedSacl | SecurityInformation.UnprotectedSacl))
                    mask |= GenericAccessRights.AccessSystemSecurity;
            }
            return mask;
        }

        /// <summary>
        /// Get whether an ACE type is an allowed ACE type.
        /// </summary>
        /// <param name="type">The ACE type.</param>
        /// <returns>True if an allowed ACE type.</returns>
        public static bool IsAllowedAceType(AceType type)
        {
            switch (type)
            {
                case AceType.Allowed:
                case AceType.AllowedCallback:
                case AceType.AllowedCallbackObject:
                case AceType.AllowedCompound:
                case AceType.AllowedObject:
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Get whether an ACE type is a denied ACE type.
        /// </summary>
        /// <param name="type">The ACE type.</param>
        /// <returns>True if a denied ACE type.</returns>
        public static bool IsDeniedAceType(AceType type)
        {
            switch (type)
            {
                case AceType.Denied:
                case AceType.DeniedCallback:
                case AceType.DeniedCallbackObject:
                case AceType.DeniedObject:
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Get whether an ACE type is an object ACE type.
        /// </summary>
        /// <param name="type">The ACE type.</param>
        /// <returns>True if an object ACE type.</returns>
        public static bool IsObjectAceType(AceType type)
        {
            switch (type)
            {
                case AceType.AlarmObject:
                case AceType.AlarmCallbackObject:
                case AceType.AllowedCallbackObject:
                case AceType.AllowedObject:
                case AceType.AuditCallbackObject:
                case AceType.AuditObject:
                case AceType.DeniedCallbackObject:
                case AceType.DeniedObject:
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Get whether an ACE type is an audit ACE type.
        /// </summary>
        /// <param name="type">The ACE type.</param>
        /// <returns>True if an audit ACE type.</returns>
        public static bool IsAuditAceType(AceType type)
        {
            switch (type)
            {
                case AceType.Alarm:
                case AceType.AlarmCallback:
                case AceType.AlarmCallbackObject:
                case AceType.AlarmObject:
                case AceType.Audit:
                case AceType.AuditCallback:
                case AceType.AuditCallbackObject:
                case AceType.AuditObject:
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Get whether an ACE type is used int the SACL.
        /// </summary>
        /// <param name="type">The ACE type.</param>
        /// <returns>True if a system ACE type.</returns>
        public static bool IsSystemAceType(AceType type)
        {
            return IsAuditAceType(type) ||
                type == AceType.MandatoryLabel ||
                type == AceType.ProcessTrustLabel ||
                type == AceType.ResourceAttribute ||
                type == AceType.ScopedPolicyId ||
                type == AceType.AccessFilter;
        }

        /// <summary>
        /// Get whether an ACE type is a callback type.
        /// </summary>
        /// <param name="type">The ACE type.</param>
        /// <returns>True if a callback type.</returns>
        public static bool IsCallbackAceType(AceType type)
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
        /// Convert an access rights type to a string.
        /// </summary>
        /// <param name="access">The access mask to convert</param>
        /// <param name="enum_type">The enumeration type for the string conversion</param>
        /// <returns>The string version of the access</returns>
        public static string AccessMaskToString(AccessMask access, Type enum_type)
        {
            if (!enum_type.IsEnum)
                throw new ArgumentException("Type must be an enum", nameof(enum_type));

            if (access.IsEmpty)
                return "None";

            List<string> names = new List<string>();
            uint remaining = access.Access;

            // If the valid is explicitly defined return it.
            if (Enum.IsDefined(enum_type, remaining))
            {
                return Enum.GetName(enum_type, remaining);
            }

            for (int i = 0; i < 32; ++i)
            {
                uint mask = 1U << i;

                if (mask > remaining)
                {
                    break;
                }

                if (mask == (uint)GenericAccessRights.MaximumAllowed)
                {
                    continue;
                }

                if ((remaining & mask) == 0)
                {
                    continue;
                }

                if (!Enum.IsDefined(enum_type, mask))
                {
                    continue;
                }

                names.Add(Enum.GetName(enum_type, mask));
                remaining &= ~mask;
            }

            if (remaining != 0)
            {
                names.Add($"0x{remaining:X}");
            }

            if (names.Count == 0)
            {
                names.Add("None");
            }

            return string.Join("|", names);
        }

        /// <summary>
        /// Convert an access rights type to a string.
        /// </summary>
        /// <param name="access">The access mask to convert</param>
        /// <returns>The string version of the access</returns>
        public static string AccessMaskToString(Enum access)
        {
            return AccessMaskToString(access, access.GetType());
        }

        /// <summary>
        /// Convert an enumerable access rights to a string
        /// </summary>
        /// <param name="access">The access mask.</param>
        /// <param name="enum_type">Enum type to convert to string.</param>
        /// <param name="generic_mapping">Generic mapping for object type.</param>
        /// <param name="map_to_generic">True to try and convert to generic rights where possible.</param>
        /// <returns>The string format of the access rights. Will return Full Access if not a generic access and has all rights and None if no access.</returns>
        public static string AccessMaskToString(AccessMask access, Type enum_type, GenericMapping generic_mapping, bool map_to_generic)
        {
            if (map_to_generic)
            {
                // Map mask then unmap back to Generic Rights.
                access = generic_mapping.UnmapMask(generic_mapping.MapMask(access));
            }
            else if(!access.HasGenericAccess && generic_mapping.HasAll(access))
            {
                return "Full Access";
            }

            return AccessMaskToString(access, enum_type);
        }

        /// <summary>
        /// Get a Process Trust Level SID.
        /// </summary>
        /// <param name="type">The Trust Type.</param>
        /// <param name="level">The Trust Level.</param>
        /// <returns>The Process Trust Level SID.</returns>
        public static Sid GetTrustLevelSid(ProcessTrustType type, ProcessTrustLevel level)
        {
            return new Sid(SecurityAuthority.ProcessTrust, (uint)type, (uint)level);
        }

        /// <summary>
        /// Generate audit event for an object open.
        /// </summary>
        /// <param name="subsystem_name">The subsystem name.</param>
        /// <param name="handle_id">Handle ID.</param>
        /// <param name="object_type_name">The typename of the object.</param>
        /// <param name="object_name">The name of the object.</param>
        /// <param name="security_descriptor">The security descriptor set for the object.</param>
        /// <param name="client_token">The client token used to open the object.</param>
        /// <param name="desired_access">Desired access for the open.</param>
        /// <param name="granted_access">Granted access from the open.</param>
        /// <param name="privileges">Privileges used to open the object.</param>
        /// <param name="object_creation">True if the object was created.</param>
        /// <param name="access_granted">Specify whether access was granted.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>A value indicating whether an event need to be generated on close.</returns>
        public static NtResult<bool> OpenObjectAudit(
            string subsystem_name,
            IntPtr handle_id,
            string object_type_name,
            string object_name,
            SecurityDescriptor security_descriptor,
            NtToken client_token,
            AccessMask desired_access,
            AccessMask granted_access,
            IEnumerable<TokenPrivilege> privileges,
            bool object_creation,
            bool access_granted,
            bool throw_on_error)
        {
            if (subsystem_name is null)
            {
                throw new ArgumentNullException(nameof(subsystem_name));
            }

            if (object_type_name is null)
            {
                throw new ArgumentNullException(nameof(object_type_name));
            }

            if (object_name is null)
            {
                throw new ArgumentNullException(nameof(object_name));
            }

            if (security_descriptor is null)
            {
                throw new ArgumentNullException(nameof(security_descriptor));
            }

            if (client_token is null)
            {
                throw new ArgumentNullException(nameof(client_token));
            }

            if (privileges is null)
            {
                throw new ArgumentNullException(nameof(privileges));
            }

            using (var list = new DisposableList())
            {
                var buffer = list.AddResource(new SafePrivilegeSetBuffer(privileges, PrivilegeSetControlFlags.None));
                var sd_buffer = list.AddResource(security_descriptor.ToSafeBuffer());

                return NtSystemCalls.NtOpenObjectAuditAlarm(
                    subsystem_name.ToUnicodeString(),
                    handle_id, object_type_name.ToUnicodeString(),
                    object_name.ToUnicodeString(), sd_buffer,
                    client_token.Handle, desired_access,
                    granted_access, buffer, object_creation,
                    access_granted, out bool generate_on_close)
                    .CreateResult(throw_on_error, () => generate_on_close);
            }
        }

        /// <summary>
        /// Generate audit event for an object open.
        /// </summary>
        /// <param name="subsystem_name">The subsystem name.</param>
        /// <param name="handle_id">Handle ID.</param>
        /// <param name="object_type_name">The typename of the object.</param>
        /// <param name="object_name">The name of the object.</param>
        /// <param name="security_descriptor">The security descriptor set for the object.</param>
        /// <param name="client_token">The client token used to open the object.</param>
        /// <param name="desired_access">Desired access for the open.</param>
        /// <param name="granted_access">Granted access from the open.</param>
        /// <param name="privileges">Privileges used to open the object.</param>
        /// <param name="object_creation">True if the object was created.</param>
        /// <param name="access_granted">Specify whether access was granted.</param>
        /// <returns>A value indicating whether an event need to be generated on close.</returns>
        public static bool OpenObjectAudit(
            string subsystem_name,
            IntPtr handle_id,
            string object_type_name,
            string object_name,
            SecurityDescriptor security_descriptor,
            NtToken client_token,
            AccessMask desired_access,
            AccessMask granted_access,
            IEnumerable<TokenPrivilege> privileges,
            bool object_creation,
            bool access_granted)
        {
            return OpenObjectAudit(subsystem_name, handle_id,
                object_type_name, object_name, security_descriptor,
                client_token, desired_access, granted_access,
                privileges, object_creation, access_granted, true).Result;
        }

        /// <summary>
        /// Generate audit event for an object close.
        /// </summary>
        /// <param name="subsystem_name">The subsystem name.</param>
        /// <param name="handle_id">Handle ID.</param>
        /// <param name="generate_on_close">True indicates to generate on close.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus CloseObjectAudit(
            string subsystem_name,
            IntPtr handle_id,
            bool generate_on_close,
            bool throw_on_error)
        {
            return NtSystemCalls.NtCloseObjectAuditAlarm(
                new UnicodeString(subsystem_name),
                handle_id,
                generate_on_close).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Generate audit event for an object close.
        /// </summary>
        /// <param name="subsystem_name">The subsystem name.</param>
        /// <param name="handle_id">Handle ID.</param>
        /// <param name="generate_on_close">True indicates to generate on close.</param>
        /// <returns>The NT status code.</returns>
        public static void CloseObjectAudit(
            string subsystem_name,
            IntPtr handle_id,
            bool generate_on_close)
        {
            CloseObjectAudit(subsystem_name, handle_id, 
                generate_on_close, true);
        }

        /// <summary>
        /// Generate audit event for an object deleted.
        /// </summary>
        /// <param name="subsystem_name">The subsystem name.</param>
        /// <param name="handle_id">Handle ID.</param>
        /// <param name="generate_on_close">True indicates to generate on close.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus DeleteObjectAudit(
            string subsystem_name,
            IntPtr handle_id,
            bool generate_on_close,
            bool throw_on_error)
        {
            return NtSystemCalls.NtDeleteObjectAuditAlarm(
                new UnicodeString(subsystem_name),
                handle_id,
                generate_on_close).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Generate audit event for an object deleted.
        /// </summary>
        /// <param name="subsystem_name">The subsystem name.</param>
        /// <param name="handle_id">Handle ID.</param>
        /// <param name="generate_on_close">True indicates to generate on close.</param>
        public static void DeleteObjectAudit(
            string subsystem_name,
            IntPtr handle_id,
            bool generate_on_close)
        {
            DeleteObjectAudit(subsystem_name, handle_id, 
                generate_on_close, true);
        }

        /// <summary>
        /// Generate audit event for a privileges used with an object.
        /// </summary>
        /// <param name="subsystem_name">The subsystem name.</param>
        /// <param name="handle_id">Handle ID.</param>
        /// <param name="client_token">The client token used.</param>
        /// <param name="desired_access">Desired access for the object.</param>
        /// <param name="privileges">Privileges used to open the object.</param>
        /// <param name="access_granted">Specify whether access was granted.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus PrivilegeObjectAudit(
            string subsystem_name,
            IntPtr handle_id,
            NtToken client_token,
            AccessMask desired_access,
            IEnumerable<TokenPrivilege> privileges,
            bool access_granted,
            bool throw_on_error
        )
        {
            if (subsystem_name is null)
            {
                throw new ArgumentNullException(nameof(subsystem_name));
            }

            if (client_token is null)
            {
                throw new ArgumentNullException(nameof(client_token));
            }

            if (privileges is null)
            {
                throw new ArgumentNullException(nameof(privileges));
            }

            using (var buffer = new SafePrivilegeSetBuffer(privileges, PrivilegeSetControlFlags.None))
            {
                return NtSystemCalls.NtPrivilegeObjectAuditAlarm(
                    new UnicodeString(subsystem_name),
                    handle_id, client_token.Handle,
                    desired_access, buffer,
                    access_granted).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Generate audit event for a privileges used with an object.
        /// </summary>
        /// <param name="subsystem_name">The subsystem name.</param>
        /// <param name="handle_id">Handle ID.</param>
        /// <param name="client_token">The client token used.</param>
        /// <param name="desired_access">Desired access for the object.</param>
        /// <param name="privileges">Privileges used to open the object.</param>
        /// <param name="access_granted">Specify whether access was granted.</param>
        public static void PrivilegeObjectAudit(
            string subsystem_name,
            IntPtr handle_id,
            NtToken client_token,
            AccessMask desired_access,
            IEnumerable<TokenPrivilege> privileges,
            bool access_granted
        )
        {
            PrivilegeObjectAudit(subsystem_name, handle_id,
                client_token, desired_access, privileges,
                access_granted, true);
        }

        /// <summary>
        /// Generate audit event for a privileges used by a client.
        /// </summary>
        /// <param name="subsystem_name">The subsystem name.</param>
        /// <param name="client_token">The client token used.</param>
        /// <param name="service_name">The name of the service.</param>
        /// <param name="privileges">Privileges used in the operation.</param>
        /// <param name="access_granted">Specify whether access was granted.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus PrivilegedServiceAudit(
            string subsystem_name,
            string service_name,
            NtToken client_token,
            IEnumerable<TokenPrivilege> privileges,
            bool access_granted,
            bool throw_on_error
        )
        {
            if (subsystem_name is null)
            {
                throw new ArgumentNullException(nameof(subsystem_name));
            }

            if (client_token is null)
            {
                throw new ArgumentNullException(nameof(client_token));
            }

            if (privileges is null)
            {
                throw new ArgumentNullException(nameof(privileges));
            }

            if (service_name is null)
            {
                throw new ArgumentNullException(nameof(service_name));
            }

            using (var buffer = new SafePrivilegeSetBuffer(privileges, PrivilegeSetControlFlags.None))
            {
                return NtSystemCalls.NtPrivilegedServiceAuditAlarm(
                    new UnicodeString(subsystem_name),
                    new UnicodeString(service_name),
                    client_token.Handle, buffer,
                    access_granted).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Generate audit event for a privileges used by a client.
        /// </summary>
        /// <param name="subsystem_name">The subsystem name.</param>
        /// <param name="client_token">The client token used.</param>
        /// <param name="service_name">The name of the service.</param>
        /// <param name="privileges">Privileges used in the operation.</param>
        /// <param name="access_granted">Specify whether access was granted.</param>
        public static void PrivilegedServiceAudit(
            string subsystem_name,
            string service_name,
            NtToken client_token,
            IEnumerable<TokenPrivilege> privileges,
            bool access_granted
        )
        {
            PrivilegedServiceAudit(subsystem_name, service_name,
                client_token, privileges,
                access_granted, true);
        }

        #endregion

        #region Static Properties
        /// <summary>
        /// Get GenericMapping for standard access rights.
        /// </summary>
        public static GenericMapping StandardAccessMapping => new GenericMapping()
                                                                    {
                                                                        GenericRead = 0x20000,
                                                                        GenericWrite = 0x10D0000,
                                                                        GenericExecute = 0x100000,
                                                                        GenericAll = 0x11F0000,
                                                                    };
        #endregion

        #region Internal Members
        internal static Sid CacheSidName(Sid sid, string name, SidNameSource source)
        {
            _cached_names.TryAdd(sid, new SidName(name, source));
            return sid;
        }

        internal static ObjectTypeList[] ConvertObjectTypes(IEnumerable<ObjectTypeEntry> object_types, DisposableList list)
        {
            if (object_types == null || !object_types.Any())
                return null;

            return object_types.Select(o => o.ToStruct(list)).ToArray();
        }

        #endregion

        #region Private Members

        private static Dictionary<Sid, string> _known_capabilities = null;
        private static Dictionary<Sid, string> _device_capabilities;
        private static readonly Regex ConditionalAceRegex = new Regex(@"^D:\(XA;;;;;WD;\((.+)\)\)$");
        private static readonly ConcurrentDictionary<Sid, SidName> _cached_names = new ConcurrentDictionary<Sid, SidName>();
        private static readonly Dictionary<Sid, string> _known_sids = new Dictionary<Sid, string>()
        {
            // S-1-5-86-1544737700-199408000-2549878335-3519669259-381336952
            { new Sid(SecurityAuthority.Nt, 86, 1544737700, 199408000, 2549878335, 3519669259, 381336952), "WMI_LOCAL_SERVICE" },
            // "S-1-5-86-615999462-62705297-2911207457-59056572-3668589837"
            { new Sid(SecurityAuthority.Nt, 86, 615999462, 62705297, 2911207457, 59056572, 3668589837), "WMI_NETWORK_SERVICE" },
            // "S-1-5-96-0"
            { new Sid(SecurityAuthority.Nt, 96, 0), @"Font Driver Host\Font Driver Host Group" },
        };

        private static string UpperCaseString(string name)
        {
            StringBuilder result = new StringBuilder(name);
            if (result.Length > 0)
            {
                result[0] = char.ToUpper(result[0]);
            }
            return result.ToString();
        }

        private static bool IsDwmSid(Sid sid)
        {
            Sid base_sid = new Sid(SecurityAuthority.Nt, 90, 0);
            if (!sid.StartsWith(base_sid))
            {
                return false;
            }
            return sid.SubAuthorities.Count
                == base_sid.SubAuthorities.Count + 1;
        }

        private static bool IsUmdfSid(Sid sid)
        {
            Sid base_sid = new Sid(SecurityAuthority.Nt, 96, 0);
            if (!sid.StartsWith(base_sid))
            {
                return false;
            }
            return sid.SubAuthorities.Count
                == base_sid.SubAuthorities.Count + 1;
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
                    if (char.IsUpper(name[index]))
                    {
                        parts.Add(name.Substring(start, index - start));
                        start = index;
                    }
                    index++;
                }

                parts.Add(name.Substring(start));
                parts[0] = UpperCaseString(parts[0]);
            }

            return $@"NAMED CAPABILITIES{(group ? " GROUP" : "")}\{string.Join(" ", parts)}";
        }

        private static SidName GetNameForSidInternal(Sid sid)
        {
            bool lookup_denied = false;
            var account_name = LookupAccountSid(sid, false);
            if (account_name.IsSuccess)
            {
                return new SidName(account_name.Result, SidNameSource.Account);
            }

            if (account_name.Status.MapNtStatusToDosError() == Win32Error.ERROR_ACCESS_DENIED)
            {
                // Only handle the case where the thread is impersonating.
                lookup_denied = NtThread.Current.Impersonating;
            }

            string name;
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
            else if (_known_sids.ContainsKey(sid))
            {
                return new SidName(_known_sids[sid], SidNameSource.WellKnown);
            }
            else if (IsDwmSid(sid))
            {
                return new SidName($@"Window Manager\DWM-{sid.SubAuthorities.Last()}", SidNameSource.WellKnown);
            }
            else if (IsUmdfSid(sid))
            {
                return new SidName($@"Font Driver Host\UMFD-{sid.SubAuthorities.Last()}", SidNameSource.WellKnown);
            }
            else if (IsScopedPolicySid(sid))
            {
                var caps = CentralAccessPolicy.ParseFromRegistry(false);
                if (caps.IsSuccess)
                {
                    foreach (var cap in caps.Result)
                    {
                        if (cap.CapId == sid)
                        {
                            return new SidName($@"CAP\{cap.Name}", SidNameSource.ScopedPolicyId);
                        }
                    }
                }
            }

            // If lookup was denied then try and request next time.
            return new SidName(sid.ToString(), SidNameSource.Sddl, lookup_denied);
        }

        private static Dictionary<Sid, string> GetKnownCapabilitySids()
        {
            if (_known_capabilities == null)
            {
                Dictionary<Sid, string> known_capabilities = new Dictionary<Sid, string>();
                try
                {
                    foreach (string name in SecurityCapabilities.KnownCapabilityNames)
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
                            parent_moniker_string = ReadMoniker(rootkey, sid) ?? string.Empty;
                        }

                        return $"{parent_moniker_string.TrimEnd('\0')}/{moniker.Result.ToString().TrimEnd('\0')}";
                    }
                }
            }
            return null;
        }

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

        private static NtResult<NtToken> DuplicateForAccessCheck(NtToken token, bool throw_on_error)
        {
            if (token.IsPseudoToken)
            {
                // This is a pseudo token, pass along as no need to duplicate.
                return token.CreateResult();
            }

            if (token.TokenType == TokenType.Primary)
            {
                return token.DuplicateToken(TokenType.Impersonation,
                    SecurityImpersonationLevel.Identification, TokenAccessRights.Query, throw_on_error);
            }
            else if (!token.IsAccessGranted(TokenAccessRights.Query))
            {
                return token.Duplicate(TokenAccessRights.Query, throw_on_error);
            }
            else
            {
                // If we've got query access rights already just create a shallow clone.
                return token.ShallowClone().CreateResult();
            }
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
            HashAlgorithm thumbprint_algo = (HashAlgorithm)reader.ReadInt32();
            int hash_size = reader.ReadInt32();
            HashAlgorithm hash_algo = (HashAlgorithm)reader.ReadInt32();
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

        private static void GetCapabilitySids(string capability_name, out Sid capability_sid, out Sid capability_group_sid)
        {
            using (SafeHGlobalBuffer cap_sid = new SafeHGlobalBuffer(Sid.MaximumSidSize),
                    cap_group_sid = new SafeHGlobalBuffer(Sid.MaximumSidSize))
            {
                NtRtl.RtlDeriveCapabilitySidsFromName(
                    new UnicodeString(capability_name),
                    cap_group_sid, cap_sid).ToNtException();
                capability_sid = new Sid(cap_sid);
                capability_group_sid = new Sid(cap_group_sid);
            }
        }

        private static ObjectTypeEntry GetDefaultObjectType(this IEnumerable<ObjectTypeEntry> object_types)
        {
            if (object_types == null)
                return new ObjectTypeEntry();
            return object_types.FirstOrDefault() ?? new ObjectTypeEntry();
        }

        private static NtResult<Sid> ParseSidString(string sddl)
        {
            if (!sddl.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
            {
                return NtStatus.STATUS_INVALID_SID.CreateResultFromError<Sid>(false);
            }

            string[] parts = sddl.Substring(4).Split('-');
            if (parts.Length == 0)
            {
                return NtStatus.STATUS_INVALID_SID.CreateResultFromError<Sid>(false);
            }

            if (!long.TryParse(parts[0], out long auth_value))
            {
                return NtStatus.STATUS_INVALID_SID.CreateResultFromError<Sid>(false);
            }

            var authority = new SidIdentifierAuthority(auth_value);
            uint[] sub_authority = new uint[parts.Length - 1];
            for (int i = 1; i < parts.Length; ++i)
            {
                if (!uint.TryParse(parts[i], out uint result))
                {
                    return NtStatus.STATUS_INVALID_SID.CreateResultFromError<Sid>(false);
                }
                sub_authority[i - 1] = result;
            }
            return new Sid(authority, sub_authority).CreateResult();
        }

        private static NtResult<bool> EvaluateConditionAce(NtToken token, SecurityDescriptor sd, bool throw_on_error)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));
            GenericMapping mapping = new GenericMapping() {
                GenericRead = 0,
                GenericWrite = 0,
                GenericExecute = 1,
                GenericAll = 1
            };
            return AccessCheck(sd, token, 1, null, mapping, throw_on_error).Map(r => r.IsSuccess && r.GrantedAccess == 1);
        }

        private sealed class AuditAccessCheckContext
        {
            private readonly string _subsystem_name;
            private readonly IntPtr _handle_id;
            private readonly string _object_type_name;
            private readonly string _object_name;
            private readonly bool _object_creation;
            private readonly AuditEventType _audit_type;
            private readonly AuditAccessCheckFlags _flags;
            private bool _generate_on_close;

            public AuditAccessCheckContext(
                string subsystem_name,
                IntPtr handle_id,
                string object_type_name,
                string object_name,
                bool object_creation, 
                AuditEventType audit_type,
                AuditAccessCheckFlags flags)
            {
                _subsystem_name = subsystem_name ?? throw new ArgumentNullException(nameof(subsystem_name));
                _handle_id = handle_id;
                _object_type_name = object_type_name ?? throw new ArgumentNullException(nameof(object_type_name));
                _object_name = object_name ?? throw new ArgumentNullException(nameof(object_name));
                _object_creation = object_creation;
                _audit_type = audit_type;
                _flags = flags;
            }

            public NtStatus AccessCheckWithResultList(
                SafeBuffer security_descriptor,
                SafeHandle self_sid,
                SafeKernelObjectHandle client_token,
                AccessMask desired_access,
                ObjectTypeList[] object_type_list,
                int object_type_list_length,
                ref GenericMapping generic_mapping,
                SafePrivilegeSetBuffer required_privileges,
                ref int buffer_length,
                AccessMask[] granted_access_list,
                NtStatus[] access_status_list)
            {
                return NtSystemCalls.NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
                    new UnicodeString(_subsystem_name), _handle_id, client_token, 
                    new UnicodeString(_object_type_name), new UnicodeString(_object_name),
                    security_descriptor, self_sid, desired_access, _audit_type, _flags, 
                    object_type_list, object_type_list_length, ref generic_mapping, _object_creation,
                    granted_access_list, access_status_list, out _generate_on_close);
            }

            public NtStatus AccessCheckByType(
                SafeBuffer security_descriptor,
                SafeHandle self_sid,
                SafeKernelObjectHandle client_token,
                AccessMask desired_access,
                [In] ObjectTypeList[] object_type_list,
                int object_type_list_length,
                ref GenericMapping generic_mapping,
                SafePrivilegeSetBuffer required_privileges,
                ref int buffer_length,
                out AccessMask granted_access,
                out NtStatus access_status)
            {
                NtToken token = NtToken.FromHandle(client_token.DangerousGetHandle(), false);
                using (token.Impersonate())
                {
                    return NtSystemCalls.NtAccessCheckByTypeAndAuditAlarm(
                        new UnicodeString(_subsystem_name), _handle_id,
                        new UnicodeString(_object_type_name), new UnicodeString(_object_name),
                        security_descriptor, self_sid, desired_access, _audit_type, _flags, object_type_list, object_type_list_length,
                        ref generic_mapping, _object_creation, out granted_access, out access_status, out _generate_on_close);
                }
            }

            public AccessCheckResult Map(AccessCheckResult result)
            {
                result.GenerateOnClose = _generate_on_close;
                return result;
            }
        }

        private delegate NtStatus AccessCheckByTypeCallback(
            SafeBuffer security_descriptor,
            SafeHandle self_sid,
            SafeKernelObjectHandle client_token,
            AccessMask desired_access,
            [In] ObjectTypeList[] object_type_list,
            int object_type_list_length,
            ref GenericMapping generic_mapping,
            SafePrivilegeSetBuffer required_privileges,
            ref int buffer_length,
            out AccessMask granted_access,
            out NtStatus access_status);

        private delegate NtStatus AccessCheckWithResultListCallback(
            SafeBuffer security_descriptor,
            SafeHandle self_sid,
            SafeKernelObjectHandle client_token,
            AccessMask desired_access,
            ObjectTypeList[] object_type_list,
            int object_type_list_length,
            ref GenericMapping generic_mapping,
            SafePrivilegeSetBuffer required_privileges,
            ref int buffer_length,
            AccessMask[] granted_access_list,
            NtStatus[] access_status_list);

        private static NtResult<AccessCheckResult> AccessCheckByType(SecurityDescriptor sd, NtToken token,
            AccessMask desired_access, Sid principal, GenericMapping generic_mapping, IEnumerable<ObjectTypeEntry> object_types,
            AccessCheckByTypeCallback callback, bool throw_on_error)
        {
            if (sd == null)
            {
                throw new ArgumentNullException("sd");
            }

            if (token == null)
            {
                throw new ArgumentNullException("token");
            }

            if (desired_access.IsEmpty)
            {
                return new AccessCheckResult(NtStatus.STATUS_ACCESS_DENIED, 0, null,
                    generic_mapping, object_types.GetDefaultObjectType(), false).CreateResult();
            }

            using (var list = new DisposableList())
            {
                var sd_buffer = list.AddResource(sd.ToSafeBuffer());
                var imp_token = list.AddResource(DuplicateForAccessCheck(token, throw_on_error));
                if (!imp_token.IsSuccess)
                {
                    return imp_token.Cast<AccessCheckResult>();
                }
                var self_sid = list.AddResource(principal?.ToSafeBuffer() ?? SafeSidBufferHandle.Null);
                var privs = list.AddResource(new SafePrivilegeSetBuffer());
                var object_type_list = ConvertObjectTypes(object_types, list);
                int repeat_count = 1;

                while (true)
                {
                    int buffer_length = privs.Length;
                    NtStatus status = callback(sd_buffer, self_sid, imp_token.Result.Handle, desired_access,
                        object_type_list, object_type_list?.Length ?? 0, ref generic_mapping, privs,
                        ref buffer_length, out AccessMask granted_access, out NtStatus result_status);
                    if (repeat_count == 0 || status != NtStatus.STATUS_BUFFER_TOO_SMALL)
                    {
                        return status.CreateResult(throw_on_error, ()
                            => new AccessCheckResult(result_status, granted_access,
                            privs, generic_mapping, object_types.GetDefaultObjectType(), false));
                    }

                    repeat_count--;
                    privs = list.AddResource(new SafePrivilegeSetBuffer(buffer_length));
                }
            }
        }

        private static NtResult<AccessCheckResult[]> AccessCheckWithResultList(SecurityDescriptor sd, NtToken token,
            AccessMask desired_access, Sid principal, GenericMapping generic_mapping, IEnumerable<ObjectTypeEntry> object_types,
            AccessCheckWithResultListCallback callback, bool throw_on_error)
        {
            if (sd == null)
            {
                throw new ArgumentNullException(nameof(sd));
            }

            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (object_types == null)
            {
                throw new ArgumentNullException(nameof(object_types));
            }

            if (!object_types.Any())
            {
                throw new ArgumentException("Must specify at least one object type.");
            }

            if (desired_access.IsEmpty)
            {
                return object_types.Select((o, i) => new AccessCheckResult(NtStatus.STATUS_ACCESS_DENIED,
                            0, null, generic_mapping, o, false)).ToArray().CreateResult();
            }

            using (var list = new DisposableList())
            {
                var sd_buffer = list.AddResource(sd.ToSafeBuffer());
                var imp_token = list.AddResource(DuplicateForAccessCheck(token, throw_on_error));
                if (!imp_token.IsSuccess)
                {
                    return imp_token.Cast<AccessCheckResult[]>();
                }
                var self_sid = list.AddResource(principal?.ToSafeBuffer() ?? SafeSidBufferHandle.Null);
                var privs = list.AddResource(new SafePrivilegeSetBuffer());
                var object_type_list = ConvertObjectTypes(object_types, list);
                int repeat_count = 1;

                while (true)
                {
                    int buffer_length = privs.Length;
                    AccessMask[] granted_access_list = new AccessMask[object_type_list.Length];
                    NtStatus[] status_list = new NtStatus[object_type_list.Length];
                    NtStatus status = callback(sd_buffer, self_sid, imp_token.Result.Handle, desired_access,
                        object_type_list, object_type_list?.Length ?? 0, ref generic_mapping, privs, ref buffer_length,
                        granted_access_list, status_list);
                    if (repeat_count == 0 || status != NtStatus.STATUS_BUFFER_TOO_SMALL)
                    {
                        return status.CreateResult(throw_on_error, ()
                            => object_types.Select((o, i) => new AccessCheckResult(status_list[i],
                            granted_access_list[i], privs, generic_mapping, o, false)).ToArray());
                    }

                    repeat_count--;
                    privs = list.AddResource(new SafePrivilegeSetBuffer(buffer_length));
                }
            }
        }

        #endregion
    }
}
