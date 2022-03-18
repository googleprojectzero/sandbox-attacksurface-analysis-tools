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
using NtApiDotNet.Win32.Security.Buffers;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// A basic implementation of a client authentication context using an existing Keberos credential.
    /// </summary>
    public sealed class KerberosClientAuthenticationContext : IClientAuthenticationContext
    {
        #region Private Members
        private readonly KerberosExternalTicket _ticket;
        private readonly KerberosAuthenticationKey _subkey;
        private readonly KerberosChecksumGSSApiFlags _gssapi_flags;
        private long _send_sequence_number;
        private long _recv_sequence_number;

        private static KerberosChecksumGSSApiFlags ConvertRequestToGSSAPI(InitializeContextReqFlags request_attributes)
        {
            KerberosChecksumGSSApiFlags ret = KerberosChecksumGSSApiFlags.None;
            if (request_attributes.HasFlagSet(InitializeContextReqFlags.Confidentiality))
                ret |= KerberosChecksumGSSApiFlags.Confidentiality;
            if (request_attributes.HasFlagSet(InitializeContextReqFlags.ExtendedError))
                ret |= KerberosChecksumGSSApiFlags.ExtendedError;
            if (request_attributes.HasFlagSet(InitializeContextReqFlags.MutualAuth))
                ret |= KerberosChecksumGSSApiFlags.Mutual;
            if (request_attributes.HasFlagSet(InitializeContextReqFlags.ReplayDetect))
                ret |= KerberosChecksumGSSApiFlags.Replay | KerberosChecksumGSSApiFlags.Integrity;
            if (request_attributes.HasFlagSet(InitializeContextReqFlags.SequenceDetect))
                ret |= KerberosChecksumGSSApiFlags.Sequence | KerberosChecksumGSSApiFlags.Integrity;
            if (request_attributes.HasFlagSet(InitializeContextReqFlags.Integrity))
                ret |= KerberosChecksumGSSApiFlags.Integrity;
            if (request_attributes.HasFlagSet(InitializeContextReqFlags.Delegate))
                ret |= KerberosChecksumGSSApiFlags.Delegate;

            return ret;
        }

        private bool UseSequenceNumber()
        {
            return _gssapi_flags.HasFlagSet(KerberosChecksumGSSApiFlags.Replay) || _gssapi_flags.HasFlagSet(KerberosChecksumGSSApiFlags.Sequence);
        }

        private const int CHECKSUM_HEADER_SIZE = 16;

        private byte[] GenerateChecksumHeader()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write(new byte[] {
                0x04, 0x04, // TOK_ID
                0x00,       // Flags
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF // Filler
            });

            if (UseSequenceNumber())
            {
                writer.Write(_send_sequence_number++.SwapEndian());
            }
            else
            {
                writer.Write(0L);
            }
            return stm.ToArray();
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="ticket">The kerberos ticket for the target.</param>
        /// <param name="request_attributes">Request attributes for the context.</param>
        public KerberosClientAuthenticationContext(KerberosExternalTicket ticket, InitializeContextReqFlags request_attributes)
        {
            if (ticket is null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }

            _ticket = ticket;
            _subkey = KerberosAuthenticationKey.GenerateKey(_ticket.SessionKey.KeyEncryption);
            _gssapi_flags = ConvertRequestToGSSAPI(request_attributes);
            bool mutual_auth_required = _gssapi_flags.HasFlagSet(KerberosChecksumGSSApiFlags.Mutual);
            var cksum = new KerberosChecksumGSSApi(_gssapi_flags, new byte[16]);
            int sequence_number = KerberosBuilderUtils.GetRandomNonce();
            _send_sequence_number = _recv_sequence_number = sequence_number;

            var authenticator = KerberosAuthenticator.Create(_ticket.TargetDomainName, _ticket.ClientName,
                KerberosTime.Now, 0, cksum, _subkey, sequence_number, null);
            Token = KerberosAPRequestAuthenticationToken.Create(_ticket.Ticket,
                authenticator, mutual_auth_required ? KerberosAPRequestOptions.MutualAuthRequired : 0, authenticator_key: _ticket.SessionKey);
            Done = !mutual_auth_required;
        }
        #endregion

        #region IClientAuthenticationContext Implementation.
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        public SecPkgLastClientTokenStatus LastTokenStatus => Done ? SecPkgLastClientTokenStatus.Yes : SecPkgLastClientTokenStatus.No;

        public AuthenticationToken Token { get; private set; }

        public bool Done { get; private set; }

        public long Expiry => long.MaxValue;

        public byte[] SessionKey => (byte[])_subkey.Key.Clone();

        public string PackageName => AuthenticationPackage.KERBEROS_NAME;

        public int MaxSignatureSize => CHECKSUM_HEADER_SIZE + _subkey.ChecksumSize;

        public int SecurityTrailerSize => throw new NotImplementedException();

        public void Continue(AuthenticationToken token)
        {
            Continue(token, Array.Empty<SecurityBuffer>());
        }

        public void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input)
        {
            Continue(token, additional_input, Array.Empty<SecurityBuffer>());
        }

        public void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input, IEnumerable<SecurityBuffer> additional_output)
        {
            Continue(additional_input, additional_output);
        }

        public void Continue(IEnumerable<SecurityBuffer> input_buffers, IEnumerable<SecurityBuffer> additional_output)
        {
            Done = true;
            Token = null;
        }

        public void Continue()
        {
            Continue(Array.Empty<SecurityBuffer>(), Array.Empty<SecurityBuffer>());
        }

        public byte[] DecryptMessage(EncryptedMessage message, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public void DecryptMessage(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public void DecryptMessageNoSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
        }

        public EncryptedMessage EncryptMessage(byte[] message, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public byte[] EncryptMessage(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public void EncryptMessageNoSignature(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public ExportedSecurityContext Export()
        {
            throw new NotImplementedException();
        }

        public AuthenticationPackage GetAuthenticationPackage()
        {
            return AuthenticationPackage.FromName(AuthenticationPackage.KERBEROS_NAME);
        }

        public byte[] MakeSignature(byte[] message, int sequence_no)
        {
            return MakeSignature(new SecurityBuffer[]
                { new SecurityBufferInOut(SecurityBufferType.Data,
                    message) }, sequence_no);
        }

        public byte[] MakeSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            foreach (var buffer in messages.Where(b => b.Type == SecurityBufferType.Data && !b.ReadOnly))
            {
                writer.Write(buffer.ToArray());
            }

            byte[] header = GenerateChecksumHeader();
            writer.Write(header);


            byte[] hash = _subkey.ComputeHash(stm.ToArray(), KerberosKeyUsage.InitiatorSign);
            byte[] ret = new byte[header.Length + hash.Length];
            Buffer.BlockCopy(header, 0, ret, 0, header.Length);
            Buffer.BlockCopy(hash, 0, ret, header.Length, hash.Length);
            return ret;
        }

        public bool VerifySignature(byte[] message, byte[] signature, int sequence_no)
        {
            return VerifySignature(new SecurityBuffer[]
                { new SecurityBufferInOut(SecurityBufferType.Data,
                    message) }, signature, sequence_no);
        }

        public bool VerifySignature(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (signature.Length < MaxSignatureSize)
            {
                throw new ArgumentException("Signature token is too small.");
            }

            if (BitConverter.ToUInt64(signature, 0) != 0xFFFFFFFFFF010404U)
            {
                return false;
            }

            if (UseSequenceNumber())
            {
                if (BitConverter.ToInt64(signature, 8) != _recv_sequence_number++.SwapEndian())
                {
                    return false;
                }
            }

            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            foreach (var buffer in messages.Where(b => b.Type == SecurityBufferType.Data && !b.ReadOnly))
            {
                writer.Write(buffer.ToArray());
            }
            writer.Write(signature, 0, CHECKSUM_HEADER_SIZE);
            byte[] hash = _subkey.ComputeHash(stm.ToArray(), KerberosKeyUsage.AcceptorSign);
            byte[] verify_hash = new byte[_subkey.ChecksumSize];
            Buffer.BlockCopy(signature, 16, verify_hash, 0, verify_hash.Length);
            return NtObjectUtils.EqualByteArray(hash, verify_hash);
        }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
        #endregion
    }
}
