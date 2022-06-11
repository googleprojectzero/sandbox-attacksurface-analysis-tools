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

using NtApiDotNet.Utilities.ASN1.Builder;
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder;
using System;
using System.Net;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// A class to make requests to a KDC.
    /// </summary>
    public sealed class KerberosKDCClient
    {
        #region Private Members
        private readonly IKerberosKDCClientTransport _transport;
        private readonly IKerberosKDCClientTransport _password_transport;

        private KerberosKDCReplyAuthenticationToken ExchangeKDCTokens(KerberosKDCRequestAuthenticationToken token)
        {
            var data = _transport.SendReceive(token.ToArray());
            if (KerberosErrorAuthenticationToken.TryParse(data, out KerberosErrorAuthenticationToken error))
                throw new KerberosKDCClientException(error);
            if (KerberosKDCReplyAuthenticationToken.TryParse(data, out KerberosKDCReplyAuthenticationToken result))
                return result;
            throw new KerberosKDCClientException("Unknown KDC reply.");
        }

        private KerberosChangePasswordStatus ChangePassword(KerberosExternalTicket ticket, ushort protocol_version, byte[] user_data)
        {
            if (_password_transport is null)
                throw new ArgumentException("Password transport not specified.");

            var auth_builder = new KerberosAuthenticatorBuilder
            {
                SequenceNumber = KerberosBuilderUtils.GetRandomNonce(),
                SubKey = KerberosAuthenticationKey.GenerateKey(ticket.SessionKey.KeyEncryption),
                ClientName = ticket.ClientName,
                ClientRealm = ticket.DomainName,
                ClientTime = KerberosTime.Now
            };

            var ap_req = KerberosAPRequestAuthenticationToken.Create(ticket.Ticket, auth_builder.Create(), 
                KerberosAPRequestOptions.None, ticket.SessionKey, raw_token: true);

            var priv_part = KerberosPrivateEncryptedPart.Create(user_data,
                    KerberosHostAddress.FromIPAddress(IPAddress.Any), auth_builder.SequenceNumber);
            var priv = KerberosPrivate.Create(priv_part.Encrypt(auth_builder.SubKey, KerberosKeyUsage.KrbPriv));
            var chpasswd = new KerberosKDCChangePasswordPacket(protocol_version, ap_req, priv);

            var bytes = _password_transport.SendReceive(chpasswd.ToArray());
            if (KerberosKDCChangePasswordPacket.TryParse(bytes, out KerberosKDCChangePasswordPacket reply_packet))
            {
                var dec_token = reply_packet.Token.Decrypt(ticket.SessionKey);
                var dec_priv = reply_packet.Message.Decrypt(auth_builder.SubKey);

                var result = new KerberosKDCChangePasswordPacket(reply_packet.ProtocolVersion, (KerberosAuthenticationToken)dec_token, (KerberosPrivate)dec_priv);
                if (!(result.Message.EncryptedPart is KerberosPrivateEncryptedPart enc_part))
                    throw new KerberosKDCClientException("Couldn't decrypt the reply.");
                if (enc_part.UserData.Length < 2)
                    throw new KerberosKDCClientException("Invalid user data.");
                return (KerberosChangePasswordStatus)((enc_part.UserData[0] << 8) | enc_part.UserData[1]);
            }
            if (KerberosErrorAuthenticationToken.TryParse(bytes, out KerberosErrorAuthenticationToken error))
                throw new KerberosKDCClientException(error);
            throw new KerberosKDCClientException("Unknown KDC reply.");
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="transport">The KDC client transport.</param>
        /// <param name="password_transport">The KDC client transport for the password server.</param>
        public KerberosKDCClient(IKerberosKDCClientTransport transport, IKerberosKDCClientTransport password_transport = null)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _password_transport = password_transport;
        }
        #endregion

        #region Public Static Members
        /// <summary>
        /// Create a TCP KDC client.
        /// </summary>
        /// <param name="hostname">The hostname of the KDC server.</param>
        /// <param name="port">The port number of the KDC server.</param>
        /// <param name="password_port">The port number of the KDC password server.</param>
        /// <returns>The created client.</returns>
        public static KerberosKDCClient CreateTCPClient(string hostname, int port = 88, int password_port = 464)
        {
            return new KerberosKDCClient(new KerberosKDCClientTransportTCP(hostname, port), 
                new KerberosKDCClientTransportTCP(hostname, password_port));
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Authenticate a user.
        /// </summary>
        /// <param name="request">The details of the AS request.</param>
        /// <returns>The AS reply.</returns>
        public KerberosASReply Authenticate(KerberosASRequest request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var as_req = request.ToBuilder();
            var reply = ExchangeKDCTokens(as_req.Create());

            // RC4 encryption uses TgsRep for the AsRep.
            if (!reply.EncryptedData.TryDecrypt(request.Key, KerberosKeyUsage.AsRepEncryptedPart, out KerberosEncryptedData reply_dec))
                reply_dec = reply.EncryptedData.Decrypt(request.Key, KerberosKeyUsage.TgsRepEncryptedPart);
            if (!KerberosKDCReplyEncryptedPart.TryParse(reply_dec.CipherText, out KerberosKDCReplyEncryptedPart reply_part))
            {
                throw new KerberosKDCClientException("Invalid KDC reply encrypted part.");
            }

            return new KerberosASReply(reply, reply_part);
        }

        /// <summary>
        /// Request a service ticket.
        /// </summary>
        /// <param name="request">The details of the TGS request.</param>
        /// <returns>The TGS reply.</returns>
        public KerberosTGSReply RequestServiceTicket(KerberosTGSRequest request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var subkey = KerberosAuthenticationKey.GenerateKey(request.SessionKey.KeyEncryption);
            var tgs_req = request.ToBuilder();
            if (tgs_req.AuthorizationData != null)
            {
                tgs_req.AuthorizationData = tgs_req.AuthorizationData.Encrypt(subkey, KerberosKeyUsage.TgsReqKdcReqBodyAuthSubkey);
            }

            var checksum = KerberosChecksum.Create(KerberosChecksumType.RSA_MD5, tgs_req.EncodeBody());
            KerberosAuthenticator authenticator = KerberosAuthenticator.Create(request.Realm, request.ClientName, KerberosTime.Now, 0, checksum, subkey,
                KerberosBuilderUtils.GetRandomNonce(), null);
            tgs_req.AddPreAuthenticationData(new KerberosPreAuthenticationDataTGSRequest(0, request.Ticket,
                authenticator.Encrypt(request.SessionKey, KerberosKeyUsage.TgsReqPaTgsReqApReq)));
            if (request.S4UUserName != null && !string.IsNullOrEmpty(request.S4URealm))
            {
                tgs_req.AddPreAuthenticationDataForUser(request.S4UUserName, request.S4URealm, request.SessionKey);
            }
            if (request.PACOptionsFlags != KerberosPreAuthenticationPACOptionsFlags.None)
            {
                tgs_req.AddPreAuthenticationData(new KerberosPreAuthenticationPACOptions(request.PACOptionsFlags));
            }

            var reply = ExchangeKDCTokens(tgs_req.Create());
            var reply_dec = reply.EncryptedData.Decrypt(subkey, KerberosKeyUsage.TgsRepEncryptedPartAuthSubkey);
            if (!KerberosKDCReplyEncryptedPart.TryParse(reply_dec.CipherText, out KerberosKDCReplyEncryptedPart reply_part))
            {
                throw new KerberosKDCClientException("Invalid KDC reply encrypted part.");
            }

            return new KerberosTGSReply(reply, reply_part);
        }

        /// <summary>
        /// Change a user's password.
        /// </summary>
        /// <param name="key">The user's authentication key.</param>
        /// <param name="new_password">The user's new password.</param>
        /// <returns>The status of the operation.</returns>
        public KerberosChangePasswordStatus ChangePassword(KerberosAuthenticationKey key, string new_password)
        {
            KerberosASRequest request = new KerberosASRequest(key, key.Name, key.Realm)
            {
                ServerName = new KerberosPrincipalName(KerberosNameType.SRV_INST, "kadmin/changepw")
            };
            return ChangePassword(Authenticate(request).ToExternalTicket(), new_password);
        }

        /// <summary>
        /// Change a user's password.
        /// </summary>
        /// <param name="ticket">The user's ticket for kadmin/changepw.</param>
        /// <param name="new_password">The user's new password.</param>
        /// <returns>The status of the operation.</returns>
        public KerberosChangePasswordStatus ChangePassword(KerberosExternalTicket ticket, string new_password)
        {
            return ChangePassword(ticket, 1, Encoding.UTF8.GetBytes(new_password));
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="tgt_ticket">The TGT ticket for the service ticket request.</param>
        /// <param name="client_name">The name of the client to change.</param>
        /// <param name="realm">The realm of the client to change.</param>
        /// <param name="new_password">The user's new password.</param>
        /// <returns>The status of the operation.</returns>
        public KerberosChangePasswordStatus SetPassword(KerberosExternalTicket tgt_ticket, KerberosPrincipalName client_name, string realm, string new_password)
        {
            if (client_name is null)
            {
                throw new ArgumentNullException(nameof(client_name));
            }

            if (realm is null)
            {
                throw new ArgumentNullException(nameof(realm));
            }

            var request = new KerberosTGSRequest(tgt_ticket.Ticket, tgt_ticket.SessionKey, tgt_ticket.ClientName, tgt_ticket.DomainName);
            request.ServerName = new KerberosPrincipalName(KerberosNameType.SRV_INST, "kadmin/changepw");
            var reply = RequestServiceTicket(request);

            DERBuilder der_builder = new DERBuilder();
            using (var seq = der_builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, Encoding.UTF8.GetBytes(new_password));
                seq.WriteContextSpecific(1, client_name);
                seq.WriteContextSpecific(2, realm);
            }

            return ChangePassword(reply.ToExternalTicket(), 0xFF80, der_builder.ToArray());
        }
        #endregion
    }
}
