//  Copyright 2022 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Server
{
    /// <summary>
    /// A user for the KDC server implementation.
    /// </summary>
    public sealed class KerberosKDCServerUser
    {
        /// <summary>
        /// The name of the user.
        /// </summary>
        public string UserName { get; }

        /// <summary>
        /// The user's realm. If not specified then uses the realm assigned to the KDC server.
        /// </summary>
        public string Realm { get; }

        /// <summary>
        /// The user's domain SID. If not specified then uses the SID assigned to the KDC server.
        /// </summary>
        public Sid DomainSid { get; set; }

        /// <summary>
        /// The user's RID.
        /// </summary>
        public uint UserId { get; set; }

        /// <summary>
        /// The list of domain group IDs for the user.
        /// </summary>
        public Dictionary<uint, GroupAttributes> GroupIds { get; }

        /// <summary>
        /// The primary group ID.
        /// </summary>
        public uint PrimaryGroupId { get; }

        /// <summary>
        /// The user account control flags.
        /// </summary>
        public UserAccountControlFlags UserAccountControlFlags { get; }

        /// <summary>
        /// Get or set the kerberos keys.
        /// </summary>
        public KerberosKeySet Keys { get; set; }

        /// <summary>
        /// The set of service principal names for this user.
        /// </summary>
        public HashSet<KerberosPrincipalName> ServicePrincipalNames { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="username">The username for the user.</param>
        public KerberosKDCServerUser(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException($"'{nameof(username)}' cannot be null or empty.", nameof(username));
            }

            UserAccountControlFlags = UserAccountControlFlags.NormalAccount;
            UserName = username;
            GroupIds = new Dictionary<uint, GroupAttributes>();
            Keys = new KerberosKeySet();
            ServicePrincipalNames = new HashSet<KerberosPrincipalName>();
            PrimaryGroupId = 513;
        }

        /// <summary>
        /// Add a group ID with optional attributes.
        /// </summary>
        /// <param name="rid">The RID for the group.</param>
        /// <param name="attributes">The group attributes.</param>
        public void AddGroupId(uint rid, GroupAttributes attributes = GroupAttributes.Mandatory | GroupAttributes.Enabled | GroupAttributes.EnabledByDefault)
        {
            GroupIds[rid] = attributes;
        }

        internal KerberosAuthenticationKey FindKey(IEnumerable<KerberosEncryptionType> enc_types)
        {
            if (enc_types != null)
            {
                foreach (var enc_type in enc_types)
                {
                    var key = Keys.GetKeysForEncryption(enc_type).FirstOrDefault();
                    if (key != null)
                        return key;
                }
            }

            return Keys.FirstOrDefault();
        }

        internal KerberosAuthorizationDataPACBuilder CreatePac(KerberosTime auth_time, Sid domain_sid, string realm)
        {
            domain_sid = DomainSid ?? domain_sid;

            Sid user_sid = domain_sid.CreateRelative(UserId);

            KerberosAuthorizationDataPACBuilder pac = new KerberosAuthorizationDataPACBuilder();
            KerberosAuthorizationDataPACLogonBuilder logon = new KerberosAuthorizationDataPACLogonBuilder(domain_sid)
            {
                UserAccountControl = UserAccountControlFlags,
                LogonTime = auth_time.ToDateTime(),
                PasswordLastSet = DateTime.UtcNow,
                PasswordCanChange = DateTime.UtcNow,
                LogonServer = $"DC.{realm}",
                LogonDomainName = realm.Split('.')[0],
                UserSessionKey = new byte[16],
                UserId = UserId,
                PrimaryGroupId = PrimaryGroupId,
                EffectiveName = UserName,
                FullName = UserName
            };

            foreach (var pair in GroupIds)
            {
                logon.AddGroupId(pair.Key, pair.Value);
            }

            if (!GroupIds.ContainsKey(PrimaryGroupId))
            {
                logon.AddGroupId(PrimaryGroupId, GroupAttributes.Mandatory | GroupAttributes.Enabled | GroupAttributes.EnabledByDefault);
            }

            pac.Entries.Add(logon);
            pac.Entries.Add(KerberosAuthorizationDataPACSignatureBuilder.CreateServerChecksum());
            pac.Entries.Add(KerberosAuthorizationDataPACSignatureBuilder.CreateKDCChecksum());
            KerberosAuthorizationDataPACUpnDnsInfoBuilder upn = new KerberosAuthorizationDataPACUpnDnsInfoBuilder
            {
                DnsDomainName = realm,
                UserPrincipalName = UserName,
                Flags = KerberosUpnDnsInfoFlags.Extended,
                SamName = UserName,
                Sid = user_sid
            };
            pac.Entries.Add(upn);

            KerberosAuthorizationDataPACClientInfoBuilder client_info = new KerberosAuthorizationDataPACClientInfoBuilder
            {
                ClientId = auth_time.ToDateTime().ToFileTimeUtc(),
                Name = UserName
            };
            pac.Entries.Add(client_info);
            return pac;
        }
    }
}
