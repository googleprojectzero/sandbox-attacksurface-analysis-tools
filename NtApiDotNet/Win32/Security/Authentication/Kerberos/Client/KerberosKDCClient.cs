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
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// A class to make requests to a KDC.
    /// </summary>
    public sealed class KerberosKDCClient
    {
        #region Private Members
        private readonly IKerberosKDCClientTransport _transport;

        private KerberosKDCReplyAuthenticationToken ExchangeTokens(KerberosKDCRequestAuthenticationToken token)
        {
            var reply = SendReceive(token);
            if (reply is KerberosErrorAuthenticationToken error)
                throw new KerberosKDCClientException(error);
            if (reply is KerberosKDCReplyAuthenticationToken result)
                return result;
            throw new KerberosKDCClientException("Unknown KDC reply.");
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="transport">The KDC client transport.</param>
        public KerberosKDCClient(IKerberosKDCClientTransport transport)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        }
        #endregion

        #region Public Static Members
        /// <summary>
        /// Create a TCP KDC client.
        /// </summary>
        /// <param name="hostname">The hostname of the KDC server.</param>
        /// <param name="port">The port number of the KDC server.</param>
        /// <returns>The created client.</returns>
        public static KerberosKDCClient CreateTCPClient(string hostname, int port = 88)
        {
            return new KerberosKDCClient(new KerberosKDCClientTransportTCP(hostname, port));
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
            var reply = ExchangeTokens(as_req.Create());
            var reply_dec = reply.EncryptedData.Decrypt(request.Key, KerberosKeyUsage.AsRepEncryptedPart);
            if (!KerberosKDCReplyEncryptedPart.TryParse(reply_dec.CipherText, out KerberosKDCReplyEncryptedPart reply_part))
            {
                throw new KerberosKDCClientException("Invalid KDC reply encrypted part..");
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
                authenticator.Encrypt(request.SessionKey, KerberosKeyUsage.TgsReqPaTgaReqApReq)));
            if (request.S4UUserName != null && !string.IsNullOrEmpty(request.S4URealm))
            {
                tgs_req.AddPreAuthenticationDataForUser(request.S4UUserName, request.S4URealm, request.SessionKey);
            }
            if (request.PACOptionsFlags != KerberosPreAuthenticationPACOptionsFlags.None)
            {
                tgs_req.AddPreAuthenticationData(new KerberosPreAuthenticationPACOptions(request.PACOptionsFlags));
            }

            var reply = ExchangeTokens(tgs_req.Create());
            var reply_dec = reply.EncryptedData.Decrypt(subkey, KerberosKeyUsage.TgsRepEncryptionPartAuthSubkey);
            if (!KerberosKDCReplyEncryptedPart.TryParse(reply_dec.CipherText, out KerberosKDCReplyEncryptedPart reply_part))
            {
                throw new KerberosKDCClientException("Invalid KDC reply encrypted part..");
            }

            return new KerberosTGSReply(reply, reply_part);
        }

        /// <summary>
        /// Method to send and receive Kerberos authentication tokens to the KDC.
        /// </summary>
        /// <param name="token">The output request token.</param>
        /// <returns>Returns either a <see cref="KerberosKDCReplyAuthenticationToken"/> or a <see cref="KerberosErrorAuthenticationToken"/>.</returns>
        public KerberosAuthenticationToken SendReceive(KerberosAuthenticationToken token)
        {
            var data = _transport.SendReceive(token.ToArray());
            if (!KerberosAuthenticationToken.TryParse(data, 0, false, out KerberosAuthenticationToken ret))
                throw new InvalidDataException("Invalid KDC data.");
            return ret;
        }
        #endregion
    }
}
