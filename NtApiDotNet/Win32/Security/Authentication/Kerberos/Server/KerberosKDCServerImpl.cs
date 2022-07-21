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
using System.Net;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Server
{
    internal sealed class KerberosKDCServerImpl : KerberosKDCServerToken
    {
        private readonly KerberosKDCServerConfig _config;
        private readonly string _realm;
        private readonly string _domain;
        private readonly Sid _domain_sid;
        private readonly Dictionary<KerberosPrincipalName, KerberosKDCServerUser> _users;
        private readonly KerberosKeySet _keys;
        private readonly KerberosAuthenticationKey _krbtgt_key;
        private readonly KerberosPrincipalName _krbtgt_name;

        public KerberosKDCServerImpl(KerberosKDCServerConfig config) 
            : base(config.Listener ?? new KerberosKDCServerListenerTCP(IPAddress.Loopback, 88))
        {
            _config = config;
            _realm = config.Realm?.ToUpper();
            if (string.IsNullOrWhiteSpace(_realm))
                throw new ArgumentException("Must specify a realm.");
            _domain = _realm.Split('.')[0];
            _krbtgt_name = new KerberosPrincipalName(KerberosNameType.SRV_INST, $"krbtgt/{_realm}");
            _krbtgt_key = (_config.KrbTgtKey ?? KerberosAuthenticationKey.GenerateKey(KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96)).CloneWithName(_krbtgt_name, _realm);
            _domain_sid = config.DomainSid ?? Sid.Parse("S-1-5-21").CreateRandom(3);
            _users = config.Users.ToDictionary(u => new KerberosPrincipalName(KerberosNameType.PRINCIPAL, u.UserName));
            _keys = new KerberosKeySet();
            _keys.Add(_krbtgt_key.CloneWithName(new KerberosPrincipalName(KerberosNameType.SRV_INST, "krbtgt"), _realm));
            _keys.Add(_krbtgt_key.CloneWithName(_krbtgt_name, _realm));
            foreach (var user in _users.Values)
            {
                foreach (var key in user.Keys)
                {
                    _keys.Add(key.CloneWithName(new KerberosPrincipalName(KerberosNameType.PRINCIPAL, user.UserName), _realm));
                    foreach (var spn in user.ServicePrincipalNames)
                    {
                        _keys.Add(key.CloneWithName(spn, _realm));
                    }
                }
            }
        }

        private AuthenticationToken GetGenericError()
        {
            return GetError(KerberosErrorType.GENERIC);
        }

        private AuthenticationToken GetError(KerberosErrorType error)
        {
            return KerberosErrorAuthenticationToken.Create(KerberosTime.Now, 0, error, _realm,
                new KerberosPrincipalName(KerberosNameType.SRV_INST, "UNKNOWN"),
                KerberosTime.Now);
        }

        private KerberosExternalTicket CreateTicket(KerberosAuthenticationKey key,
            KerberosPrincipalName server_name, KerberosPrincipalName client_name,
            string realm, KerberosTime auth_time, KerberosAuthorizationDataPACBuilder pac,
            IEnumerable<KerberosEncryptionType> enc_types)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (server_name is null)
            {
                throw new ArgumentNullException(nameof(server_name));
            }

            if (client_name is null)
            {
                throw new ArgumentNullException(nameof(client_name));
            }

            if (string.IsNullOrEmpty(realm))
            {
                throw new ArgumentException($"'{nameof(realm)}' cannot be null or empty.", nameof(realm));
            }

            pac.ComputeSignatures(key, _krbtgt_key);

            KerberosAuthenticationKey ticket_key = 
                KerberosAuthenticationKey.GenerateKey(enc_types?.FirstOrDefault() ?? KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96);

            KerberosAuthorizationDataIfRelevantBuilder if_rel = new KerberosAuthorizationDataIfRelevantBuilder();
            if_rel.Entries.Add(pac);

            List<KerberosAuthorizationData> auth_data = new List<KerberosAuthorizationData>();
            auth_data.Add(if_rel.Create());

            KerberosTicketBuilder ticket_builder = new KerberosTicketBuilder(5, realm, server_name, KerberosTicketFlags.Initial, realm, client_name,
                auth_time, KerberosTime.Now, KerberosTime.MaximumTime, KerberosTime.MaximumTime, ticket_key,
                new KerberosTransitedEncoding(KerberosTransitedEncodingType.X500Compress, Array.Empty<byte>()), null, auth_data);

            var ticket_dec = ticket_builder.Create();
            var ticket = ticket_dec.Encrypt(key);
            return KerberosCredential.Create(ticket, ticket_dec.ToCredentialInfo()).ToExternalTicket();
        }

        private AuthenticationToken HandleAsRequest(KerberosKDCRequestAuthenticationToken request)
        {
            string request_realm = request.Realm?.ToUpper();
            if (request_realm != _realm && request_realm != _domain)
                return GetError(KerberosErrorType.WRONG_REALM);
            if (!_users.TryGetValue(request.ClientName, out KerberosKDCServerUser user))
                return GetError(KerberosErrorType.S_PRINCIPAL_UNKNOWN);
            var key = user.FindKey(request.EncryptionTypes);
            if (key == null)
                return GetError(KerberosErrorType.NOKEY);

            KerberosTime auth_time = KerberosTime.Now;
            var pac = user.CreatePac(KerberosTime.Now, _domain_sid, _realm);
            var ticket = CreateTicket(_krbtgt_key, _krbtgt_name, request.ClientName, 
                _realm, auth_time, pac, request.EncryptionTypes);

            KerberosASReplyBuilder reply = new KerberosASReplyBuilder();
            reply.ClientName = request.ClientName;
            reply.ClientRealm = _realm;
            reply.Ticket = ticket.Ticket;
            return reply.Create();
        }

        private AuthenticationToken HandleTgsRequest(KerberosKDCRequestAuthenticationToken request)
        {
            return GetGenericError();
        }

        protected override AuthenticationToken HandleRequest(KerberosKDCRequestAuthenticationToken request)
        {
            if (request.MessageType == KerberosMessageType.KRB_AS_REQ)
                return HandleAsRequest(request);
            if (request.MessageType == KerberosMessageType.KRB_TGS_REQ)
                return HandleTgsRequest(request);
            return GetGenericError();
        }
    }
}
