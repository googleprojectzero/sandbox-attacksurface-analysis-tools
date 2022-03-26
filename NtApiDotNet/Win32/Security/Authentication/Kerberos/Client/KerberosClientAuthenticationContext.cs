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
                ret |= KerberosChecksumGSSApiFlags.Confidentiality | KerberosChecksumGSSApiFlags.Integrity 
                    | KerberosChecksumGSSApiFlags.Replay | KerberosChecksumGSSApiFlags.Sequence;
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

        private const int SECURITY_HEADER_SIZE = 16;

        private byte[] GenerateAESChecksumHeader()
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

        private byte[] GenerateWrapHeader()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write(new byte[] {
                0x05, 0x04, // TOK_ID
                0x02,       // Flags
                0xFF,       // Filler
                0, 0,       // Extra Count
                0, 0        // Right rotation count
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

        private void EncryptMessageNoSignatureAES(IEnumerable<SecurityBuffer> messages)
        {
            // The message buffer gets the last X bytes of the encrypted data. The rest goes into the signature.
            // To make it simpler you could rotate the bytes, but that isn't really necessary for us as we're not putting that much effort in.
            List<ISecurityBufferInOut> data_buffers = messages.Where(b => b.Type == SecurityBufferType.Data && !b.ReadOnly)
                                                        .OfType<ISecurityBufferInOut>().ToList();
            if (data_buffers.Count == 0)
                throw new ArgumentException("Must specify a buffer to encrypt.");
            ISecurityBufferOut token_buffer = messages.Where(b => b.Type == SecurityBufferType.Token && !b.ReadOnly)
                                            .OfType<ISecurityBufferOut>().FirstOrDefault();
            if (token_buffer == null)
                throw new ArgumentException("Must specify a buffer for the token signature.");

            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            foreach (var buffer in data_buffers)
            {
                writer.Write(buffer.ToArray());
            }
            byte[] header = GenerateWrapHeader();
            writer.Write(header);

            byte[] cipher_text = _subkey.Encrypt(stm.ToArray(), KerberosKeyUsage.InitiatorSeal);
            stm = new MemoryStream(cipher_text);
            BinaryReader reader = new BinaryReader(stm);
            byte[] confounder = reader.ReadAllBytes(16);
            foreach (var buffer in data_buffers)
            {
                byte[] data = reader.ReadAllBytes(buffer.Size);
                buffer.Update(SecurityBufferType.Data, data);
            }

            stm = new MemoryStream();
            writer = new BinaryWriter(stm);
            header[7] = 0x1C;
            writer.Write(header);
            writer.Write(reader.ReadToEnd());
            writer.Write(confounder);
            token_buffer.Update(SecurityBufferType.Token, stm.ToArray());
        }

        private void DecryptMessageNoSignatureAES(IEnumerable<SecurityBuffer> messages)
        {
            List<ISecurityBufferInOut> data_buffers = messages.Where(b => b.Type == SecurityBufferType.Data && !b.ReadOnly)
                                                        .OfType<ISecurityBufferInOut>().ToList();
            if (data_buffers.Count == 0)
                throw new ArgumentException("Must specify a buffer to encrypt.");
            ISecurityBufferIn token_buffer = messages.Where(b => b.Type == SecurityBufferType.Token)
                                            .OfType<ISecurityBufferIn>().FirstOrDefault();
            if (token_buffer == null)
                throw new ArgumentException("Must specify a buffer for the token signature.");

            byte[] signature = token_buffer.ToArray();

            if (signature.Length < SecurityTrailerSize)
            {
                throw new ArgumentException("Encryption token is too small.");
            }

            Array.Resize(ref signature, SecurityTrailerSize);

            if (BitConverter.ToUInt64(signature, 0) != 0x1C000000FF030405U)
            {
                throw new ArgumentException("Invalid signature buffer header.");
            }

            if (UseSequenceNumber())
            {
                if (BitConverter.ToInt64(signature, 8) != _recv_sequence_number++.SwapEndian())
                {
                    throw new ArgumentException("Invalid sequence number.");
                }
            }

            MemoryStream stm = new MemoryStream();
            // Confounder.
            stm.Write(signature, signature.Length - 16, 16);
            foreach (var buffer in data_buffers)
            {
                byte[] ba = buffer.ToArray();
                stm.Write(ba, 0, ba.Length);
            }
            stm.Write(signature, 16, signature.Length - 32);

            byte[] plain_text = _subkey.Decrypt(stm.ToArray(), KerberosKeyUsage.AcceptorSeal);
            stm = new MemoryStream(plain_text);
            BinaryReader reader = new BinaryReader(stm);
            foreach (var buffer in data_buffers)
            {
                buffer.Update(SecurityBufferType.Data, reader.ReadAllBytes(buffer.Size));
            }

            _ = reader.ReadAllBytes(16);
            // We should perhaps verify the trailing header to be sure?
        }

        private byte[] MakeSignatureAES(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            foreach (var buffer in messages.Where(b => b.Type == SecurityBufferType.Data && !b.ReadOnly))
            {
                writer.Write(buffer.ToArray());
            }

            byte[] header = GenerateAESChecksumHeader();
            writer.Write(header);
            byte[] hash = _subkey.ComputeHash(stm.ToArray(), KerberosKeyUsage.InitiatorSign);
            byte[] ret = new byte[header.Length + hash.Length];
            Buffer.BlockCopy(header, 0, ret, 0, header.Length);
            Buffer.BlockCopy(hash, 0, ret, header.Length, hash.Length);
            return ret;
        }

        private bool VerifySignatureAES(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
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
            writer.Write(signature, 0, SECURITY_HEADER_SIZE);
            byte[] hash = _subkey.ComputeHash(stm.ToArray(), KerberosKeyUsage.AcceptorSign);
            byte[] verify_hash = new byte[_subkey.ChecksumSize];
            Buffer.BlockCopy(signature, 16, verify_hash, 0, verify_hash.Length);
            return NtObjectUtils.EqualByteArray(hash, verify_hash);
        }
        #endregion

        #region Constructors

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="ticket">The kerberos ticket for the target.</param>
        /// <param name="request_attributes">Request attributes for the context.</param>
        /// <param name="config">Additional configuration for the context..</param>
        public KerberosClientAuthenticationContext(KerberosExternalTicket ticket, InitializeContextReqFlags request_attributes, 
            KerberosClientAuthenticationContextConfig config = null)
        {
            if (ticket is null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }

            _ticket = ticket;

            _subkey = config?.SubKey ?? KerberosAuthenticationKey.GenerateKey(config?.SubKeyEncryptionType ?? _ticket.SessionKey.KeyEncryption);
            _gssapi_flags = ConvertRequestToGSSAPI(request_attributes);
            bool mutual_auth_required = _gssapi_flags.HasFlagSet(KerberosChecksumGSSApiFlags.Mutual);
            var cksum = new KerberosChecksumGSSApi(_gssapi_flags, config?.ChannelBinding ?? new byte[16]);
            int sequence_number = KerberosBuilderUtils.GetRandomNonce();
            _send_sequence_number = _recv_sequence_number = sequence_number;

            KerberosAPRequestOptions opts = KerberosAPRequestOptions.None;
            if (mutual_auth_required)
                opts |= KerberosAPRequestOptions.MutualAuthRequired;
            if (config.SessionKeyTicket != null)
                opts |= KerberosAPRequestOptions.UseSessionKey;

            var authenticator = KerberosAuthenticator.Create(_ticket.TargetDomainName, _ticket.ClientName,
                KerberosTime.Now, 0, cksum, _subkey, sequence_number, null);
            Token = KerberosAPRequestAuthenticationToken.Create(_ticket.Ticket,
                authenticator, opts, authenticator_key: _ticket.SessionKey);
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

        public int MaxSignatureSize => SECURITY_HEADER_SIZE + _subkey.ChecksumSize;

        public int SecurityTrailerSize => (SECURITY_HEADER_SIZE * 2) + _subkey.AdditionalEncryptionSize;

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
            if (message is null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            SecurityBuffer buffer = new SecurityBufferInOut(SecurityBufferType.Data, message.Message);
            DecryptMessage(new[] { buffer }, message.Signature, sequence_no);
            return buffer.ToArray();
        }

        public void DecryptMessage(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            if (messages is null)
            {
                throw new ArgumentNullException(nameof(messages));
            }

            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            List<SecurityBuffer> sig_buffers = new List<SecurityBuffer>(messages);
            sig_buffers.Add(new SecurityBufferInOut(SecurityBufferType.Token | SecurityBufferType.ReadOnly, signature));
            DecryptMessageNoSignature(sig_buffers, sequence_no);
        }

        public void DecryptMessageNoSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            switch (_subkey.KeyEncryption)
            {
                case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                    DecryptMessageNoSignatureAES(messages);
                    break;
                default:
                    throw new InvalidDataException($"Unsupported encryption algorithm {_subkey.KeyEncryption}");
            }
        }

        public void Dispose()
        {
        }

        public EncryptedMessage EncryptMessage(byte[] message, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            if (message is null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            SecurityBuffer buffer = new SecurityBufferInOut(SecurityBufferType.Data, message);
            var signature = EncryptMessage(new[] { buffer }, quality_of_protection, sequence_no);
            return new EncryptedMessage(buffer.ToArray(), signature);
        }

        public byte[] EncryptMessage(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            if (messages is null)
            {
                throw new ArgumentNullException(nameof(messages));
            }

            List<SecurityBuffer> sig_buffers = new List<SecurityBuffer>(messages);
            var out_sig_buffer = new SecurityBufferOut(SecurityBufferType.Token, SecurityTrailerSize);
            sig_buffers.Add(out_sig_buffer);
            EncryptMessageNoSignature(sig_buffers, quality_of_protection, sequence_no);
            return out_sig_buffer.ToArray();
        }

        public void EncryptMessageNoSignature(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            if (quality_of_protection != SecurityQualityOfProtectionFlags.None)
                throw new ArgumentException("Quality of protection flags unsupported.", nameof(quality_of_protection));
            switch (_subkey.KeyEncryption)
            {
                case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                    EncryptMessageNoSignatureAES(messages);
                    break;
                default:
                    throw new InvalidDataException($"Unsupported encryption algorithm {_subkey.KeyEncryption}");
            }
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
            switch (_subkey.KeyEncryption)
            {
                case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                    return MakeSignatureAES(messages, sequence_no);
                default:
                    throw new InvalidDataException($"Unsupported encryption algorithm {_subkey.KeyEncryption}");
            }
        }

        public bool VerifySignature(byte[] message, byte[] signature, int sequence_no)
        {
            return VerifySignature(new SecurityBuffer[]
                { new SecurityBufferInOut(SecurityBufferType.Data,
                    message) }, signature, sequence_no);
        }

        public bool VerifySignature(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            switch (_subkey.KeyEncryption)
            {
                case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                    return VerifySignatureAES(messages, signature, sequence_no);
                default:
                    throw new InvalidDataException($"Unsupported encryption algorithm {_subkey.KeyEncryption}");
            }
        }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
        #endregion
    }
}
