//  Copyright 2021 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Sam
{
    /// <summary>
    /// Class to represent a connection to a SAM server.
    /// </summary>
    public sealed class SamServer : SamObject
    {
        #region Private Members
        private SamServer(SafeSamHandle handle, SamServerAccessRights granted_access, string server_name)
            : base(handle, granted_access, SamUtils.SAM_SERVER_NT_TYPE_NAME, 
                  string.IsNullOrEmpty(server_name) ? "SAM Server" : $"SAM Server ({server_name})", server_name)
        {
        }

        private NtResult<SamDomain> OpenDomain(string domain_name, Sid domain_id, SamDomainAccessRights desired_access, bool throw_on_error)
        {
            using (var buffer = domain_id.ToSafeBuffer())
            {
                return SecurityNativeMethods.SamOpenDomain(Handle, desired_access, buffer,
                    out SafeSamHandle domain_handle).CreateResult(throw_on_error,
                    () => new SamDomain(domain_handle, desired_access, ServerName, domain_name, domain_id));
            }
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Enumerate domains in the SAM.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of domains.</returns>
        public NtResult<IReadOnlyList<SamRidEnumeration>> EnumerateDomains(bool throw_on_error)
        {
            return SamUtils.SamEnumerateObjects(Handle,
                SecurityNativeMethods.SamEnumerateDomainsInSamServer, 
                (SAM_RID_ENUMERATION s) => new SamRidEnumeration(s), throw_on_error);
        }

        /// <summary>
        /// Enumerate domains in the SAM.
        /// </summary>
        /// <returns>The list of domains.</returns>
        public IReadOnlyList<SamRidEnumeration> EnumerateDomains()
        {
            return EnumerateDomains(true).Result;
        }

        /// <summary>
        /// Lookup the domain SID for a domain name.
        /// </summary>
        /// <param name="name">The name of the domain.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The domain SID.</returns>
        public NtResult<Sid> LookupDomain(string name, bool throw_on_error)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new System.ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
            }

            return SecurityNativeMethods.SamLookupDomainInSamServer(Handle, new UnicodeString(name), 
                out SafeSamMemoryBuffer domain_id).CreateResult(throw_on_error, () =>
            {
                using (domain_id)
                {
                    return new Sid(domain_id);
                }
            });
        }

        /// <summary>
        /// Lookup the domain SID for a domain name.
        /// </summary>
        /// <param name="name">The name of the domain.</param>
        /// <returns>The domain SID.</returns>
        public Sid LookupDomain(string name)
        {
            return LookupDomain(name, true).Result;
        }

        /// <summary>
        /// Open a SAM domain object.
        /// </summary>
        /// <param name="domain_id">The domain SID.</param>
        /// <param name="desired_access">The desired access for the object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM domain object.</returns>
        public NtResult<SamDomain> OpenDomain(Sid domain_id, SamDomainAccessRights desired_access, bool throw_on_error)
        {
            return OpenDomain(null, domain_id, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open a SAM domain object.
        /// </summary>
        /// <param name="domain_id">The domain SID.</param>
        /// <param name="desired_access">The desired access for the object.</param>
        /// <returns>The SAM domain object.</returns>
        public SamDomain OpenDomain(Sid domain_id, SamDomainAccessRights desired_access)
        {
            return OpenDomain(domain_id, desired_access, true).Result;
        }

        /// <summary>
        /// Open a SAM domain object.
        /// </summary>
        /// <param name="name">The name of the domain.</param>
        /// <param name="desired_access">The desired access for the object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM domain object.</returns>
        public NtResult<SamDomain> OpenDomain(string name, SamDomainAccessRights desired_access, bool throw_on_error)
        {
            var domain_id = LookupDomain(name, throw_on_error);
            if (!domain_id.IsSuccess)
                return domain_id.Cast<SamDomain>();

            return OpenDomain(name.ToUpper(), domain_id.Result, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open a SAM domain object.
        /// </summary>
        /// <param name="name">The name of the domain.</param>
        /// <param name="desired_access">The desired access for the object.</param>
        /// <returns>The SAM domain object.</returns>
        public SamDomain OpenDomain(string name, SamDomainAccessRights desired_access)
        {
            return OpenDomain(name, desired_access, true).Result;
        }

        /// <summary>
        /// Enumerate and open accessible domain objects.
        /// </summary>
        /// <param name="desired_access">The desired access for the opened domains.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of accessible domains.</returns>
        public NtResult<IReadOnlyList<SamDomain>> OpenAccessibleDomains(SamDomainAccessRights desired_access, bool throw_on_error)
        {
            return EnumerateDomains(throw_on_error).Map<IReadOnlyList<SamDomain>>(e => e.Select(
                s => OpenDomain(s.Name, desired_access, false).GetResultOrDefault()).Where(a => a != null).ToList().AsReadOnly());
        }

        /// <summary>
        /// Enumerate and open accessible domain objects.
        /// </summary>
        /// <param name="desired_access">The desired access for the opened domains.</param>
        /// <returns>The list of accessible domains.</returns>
        public IReadOnlyList<SamDomain> OpenAccessibleDomains(SamDomainAccessRights desired_access)
        {
            return OpenAccessibleDomains(desired_access, true).Result;
        }

        /// <summary>
        /// Opens the builtin domain on the server.
        /// </summary>
        /// <param name="desired_access">The desired access for the object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM domain object.</returns>
        public NtResult<SamDomain> OpenBuiltinDomain(SamDomainAccessRights desired_access, bool throw_on_error)
        {
            return OpenDomain("Builtin", KnownSids.Builtin, desired_access, throw_on_error);
        }

        /// <summary>
        /// Opens the builtin domain on the server.
        /// </summary>
        /// <param name="desired_access">The desired access for the object.</param>
        /// <returns>The SAM domain object.</returns>
        public SamDomain OpenBuiltinDomain(SamDomainAccessRights desired_access)
        {
            return OpenBuiltinDomain(desired_access, true).Result;
        }

        /// <summary>
        /// Opens the user domain on the server.
        /// </summary>
        /// <param name="desired_access">The desired access for the object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM domain object.</returns>
        public NtResult<SamDomain> OpenUserDomain(SamDomainAccessRights desired_access, bool throw_on_error)
        {
            var domains = EnumerateDomains(throw_on_error);
            if (!domains.IsSuccess)
                return domains.Cast<SamDomain>();

            foreach (var domain in domains.Result)
            {
                var domain_id = LookupDomain(domain.Name, false).GetResultOrDefault();
                if (domain_id is null || domain_id == KnownSids.Builtin)
                {
                    continue;
                }

                return OpenDomain(domain.Name, domain_id, desired_access, throw_on_error);
            }
            return NtStatus.STATUS_OBJECT_NAME_NOT_FOUND.CreateResultFromError<SamDomain>(throw_on_error);
        }

        /// <summary>
        /// Opens the user domain on the server.
        /// </summary>
        /// <param name="desired_access">The desired access for the object.</param>
        /// <returns>The SAM domain object.</returns>
        public SamDomain OpenUserDomain(SamDomainAccessRights desired_access)
        {
            return OpenUserDomain(desired_access, true).Result;
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Connect to a SAM server.
        /// </summary>
        /// <param name="server_name">The name of the server. Set to null for local connection.</param>
        /// <param name="desired_access">The desired access on the SAM server.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The server connection.</returns>
        public static NtResult<SamServer> Connect(string server_name, SamServerAccessRights desired_access, bool throw_on_error)
        {
            UnicodeString name = string.IsNullOrEmpty(server_name) ? null : new UnicodeString(server_name);

            return SecurityNativeMethods.SamConnect(name, out SafeSamHandle handle, desired_access, 
                null).CreateResult(throw_on_error, () => new SamServer(handle, desired_access, server_name));
        }

        /// <summary>
        /// Connect to a SAM server.
        /// </summary>
        /// <param name="server_name">The name of the server. Set to null for local connection.</param>
        /// <param name="desired_access">The desired access on the SAM server.</param>
        /// <returns>The server connection.</returns>
        public static SamServer Connect(string server_name, SamServerAccessRights desired_access)
        {
            return Connect(server_name, desired_access, true).Result;
        }

        /// <summary>
        /// Connect to a SAM server.
        /// </summary>
        /// <param name="desired_access">The desired access on the SAM server.</param>
        /// <returns>The server connection.</returns>
        public static SamServer Connect(SamServerAccessRights desired_access)
        {
            return Connect(null, desired_access);
        }

        /// <summary>
        /// Connect to a SAM server with maximum access.
        /// </summary>
        /// <returns>The server connection.</returns>
        public static SamServer Connect()
        {
            return Connect(SamServerAccessRights.MaximumAllowed);
        }
        #endregion
    }
}
