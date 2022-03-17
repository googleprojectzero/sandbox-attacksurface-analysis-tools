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
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// A class to make requests to a KDC.
    /// </summary>
    public sealed class KerberosKDCClient
    {
        #region Private Members
        private readonly string _hostname;
        private readonly int _port;

        private KerberosKDCClient(string hostname, int port)
        {
            _hostname = hostname;
            _port = port;
        }

        private KerberosKDCReplyAuthenticationToken ExchangeTokens(KerberosKDCRequestAuthenticationToken token)
        {
            using (var socket = new TcpClient(_hostname, _port))
            {
                using (var stm = socket.GetStream())
                {
                    BinaryWriter writer = new BinaryWriter(stm, Encoding.ASCII, true);
                    byte[] data = token.ToArray();
                    writer.Write(IPAddress.HostToNetworkOrder(data.Length));
                    writer.Write(data);
                    BinaryReader reader = new BinaryReader(stm, Encoding.ASCII, true);
                    int return_length = IPAddress.NetworkToHostOrder(reader.ReadInt32());
                    data = reader.ReadAllBytes(return_length);
                    if (!KerberosKDCReplyAuthenticationToken.TryParse(data, out KerberosKDCReplyAuthenticationToken reply))
                    {
                        if (KerberosErrorAuthenticationToken.TryParse(data, out KerberosErrorAuthenticationToken error))
                        {
                            throw new KerberosKDCClientException(error);
                        }
                        throw new KerberosKDCClientException("Unknown KDC reply.");
                    }

                    return reply;
                }
            }
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
            return new KerberosKDCClient(hostname, port);
        }
        #endregion

        #region Public Methods
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
        #endregion

    }
}
