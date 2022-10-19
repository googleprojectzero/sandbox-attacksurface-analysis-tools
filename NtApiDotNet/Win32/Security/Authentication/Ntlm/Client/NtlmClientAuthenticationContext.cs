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

using NtApiDotNet.Utilities.Security;
using NtApiDotNet.Win32.Security.Authentication.Ntlm.Builder;
using NtApiDotNet.Win32.Security.Buffers;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm.Client
{
    /// <summary>
    /// Client authentication context for NTLM.
    /// </summary>
    /// <remarks>Only supports NTLMv2.</remarks>
    public sealed class NtlmClientAuthenticationContext : IClientAuthenticationContext
    {
        #region Private Members
        private readonly NtHashAuthenticationCredentials _credentials;
        private readonly string _target_name;
        private readonly NtlmClientAuthenticationContextConfig _config;
        private NtlmNegotiateFlags _nego_flags;
        private byte[] _session_key;
        private byte[] _client_signing_key;
        private byte[] _server_signing_key;
        private int _client_seq_no;
        private int _server_seq_no;
        private ARC4 _client_rc4;
        private ARC4 _server_rc4;

        private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        private static byte[] GenerateRandomValue(int length)
        {
            byte[] ret = new byte[length];
            _rng.GetBytes(ret);
            return ret;
        }

        private static byte[] GetKey(byte[] session_key, int key_length, string mode)
        {
            MemoryStream stm = new MemoryStream();
            stm.Write(session_key, 0, key_length);
            byte[] mode_bytes = Encoding.ASCII.GetBytes($"session key to {mode} key magic constant\0");
            stm.Write(mode_bytes, 0, mode_bytes.Length);
            return MD5.Create().ComputeHash(stm.ToArray());
        }

        private static byte[] CalculateHMACMD5(byte[] key, byte[] data)
        {
            return new HMACMD5(key).ComputeHash(data);
        }

        private static byte[] GetSignKey(NtlmNegotiateFlags negflags, byte[] session_key, bool client)
        {
            if (!negflags.HasFlagSet(NtlmNegotiateFlags.ExtendedSessionSecurity))
                return new byte[0];

            if (client)
            {
                return GetKey(session_key, session_key.Length, "client-to-server signing");
            }
            return GetKey(session_key, session_key.Length, "server-to-client signing");
        }

        private static byte[] GetSealKey(NtlmNegotiateFlags negflags, byte[] session_key, bool client)
        {
            if (negflags.HasFlagSet(NtlmNegotiateFlags.ExtendedSessionSecurity))
            {
                int length = 5;
                if (negflags.HasFlagSet(NtlmNegotiateFlags.Key128Bit))
                {
                    length = session_key.Length;
                }
                else if (negflags.HasFlagSet(NtlmNegotiateFlags.Key56Bit))
                {
                    length = 7;
                }
                if (client)
                {
                    return GetKey(session_key, length, "client-to-server sealing");
                }
                return GetKey(session_key, length, "server-to-client sealing");
            }
            return session_key;
        }

        private static byte[] ConcatBytes(byte[] a, params byte[][] b)
        {
            MemoryStream stm = new MemoryStream();
            stm.Write(a, 0, a.Length);
            foreach (var x in b)
            {
                stm.Write(x, 0, x.Length);
            }
            return stm.ToArray();
        }

        private static Version GetVersion()
        {
            var ret = Environment.OSVersion.Version;
            return new Version(ret.Major, ret.Minor, ret.Build, 0xF);
        }

        private static NtlmNegotiateFlags MapToNegotiateFlags(InitializeContextReqFlags request_attributes)
        {
            NtlmNegotiateFlags flags = 0;

            if (request_attributes.HasFlagSet(InitializeContextReqFlags.Identify))
                flags |= NtlmNegotiateFlags.Identity;
            if (request_attributes.HasFlagSet(InitializeContextReqFlags.Integrity)
                || request_attributes.HasFlagSet(InitializeContextReqFlags.ReplayDetect)
                || request_attributes.HasFlagSet(InitializeContextReqFlags.SequenceDetect))
            {
                flags |= NtlmNegotiateFlags.Signing | NtlmNegotiateFlags.KeyExchange;
            }
            if (request_attributes.HasFlagSet(InitializeContextReqFlags.Confidentiality))
            {
                flags |= NtlmNegotiateFlags.Seal | NtlmNegotiateFlags.KeyExchange;
            }
            return flags;
        }

        private static InitializeContextRetFlags MapFromNegotiateflags(NtlmNegotiateFlags flags)
        {
            InitializeContextRetFlags ret = InitializeContextRetFlags.None;
            if (flags.HasFlagSet(NtlmNegotiateFlags.Signing))
                ret |= InitializeContextRetFlags.Integrity | InitializeContextRetFlags.ReplayDetect | InitializeContextRetFlags.SequenceDetect;
            if (flags.HasFlagSet(NtlmNegotiateFlags.Seal))
                ret |= InitializeContextRetFlags.Confidentiality;
            if (flags.HasFlagSet(NtlmNegotiateFlags.Anonymous))
                ret |= InitializeContextRetFlags.NullSession;
            return ret;
        }

        private void CreateNegotiateToken()
        {
            NtlmNegotiateFlags flags = MapToNegotiateFlags(RequestAttributes);
            flags |= NtlmNegotiateFlags.NTLM | NtlmNegotiateFlags.Unicode | NtlmNegotiateFlags.Oem | NtlmNegotiateFlags.RequestTarget 
                | NtlmNegotiateFlags.ExtendedSessionSecurity | NtlmNegotiateFlags.AlwaysSign 
                | NtlmNegotiateFlags.Key128Bit | NtlmNegotiateFlags.Version;

            Token = new NtlmNegotiateAuthenticationTokenBuilder
            {
                Flags = flags,
                Version = GetVersion()
            }.Create();
        }

        private void CreateAuthenticateToken(NtlmChallengeAuthenticationToken challenge_token)
        {
            if (challenge_token == null)
                throw new InvalidDataException("Expected NTLM CHALLENGE token from server.");
            NtlmAuthenticateAuthenticationTokenBuilderBase builder;
            NtlmNegotiateFlags nego_flags = challenge_token.Flags & ~(NtlmNegotiateFlags.KeyExchange | NtlmNegotiateFlags.Version |
                NtlmNegotiateFlags.TargetTypeDomain | NtlmNegotiateFlags.TargetTypeServer | NtlmNegotiateFlags.TargetTypeShare);
            AuthenticationToken nego_token = Token;
            byte[] session_base_key;
            if (_credentials == null)
            {
                builder = new NtlmAuthenticateAuthenticationTokenBuilder
                {
                    LmChallengeResponse = new byte[1],
                    NtChallengeResponse = Array.Empty<byte>(),
                    Flags = nego_flags | NtlmNegotiateFlags.Anonymous
                };
                session_base_key = new byte[16];
            }
            else
            {
                var timestamp = challenge_token.TargetInfo.OfType<NtlmAvPairTimestamp>().FirstOrDefault();
                var time = timestamp?.Value ?? DateTime.Now;
                NtlmAuthenticateAuthenticationTokenV2Builder builderv2 = new NtlmAuthenticateAuthenticationTokenV2Builder();
                builderv2.LmChallengeResponse = new byte[24];
                builderv2.Timestamp = time.ToFileTime();
                builderv2.ClientChallenge = GenerateRandomValue(8);
                builderv2.Flags = challenge_token.Flags | NtlmNegotiateFlags.TargetInfo;
                builderv2.TargetInfo.AddRange(challenge_token.TargetInfo);
                if (timestamp == null)
                {
                    builderv2.TargetInfo.Add(new NtlmAvPairTimestamp(time.ToFileTime()));
                }
                MsvAvFlags av_flags = MsvAvFlags.MessageIntegrity;
                bool add_target_name = !string.IsNullOrEmpty(_target_name);
                if (RequestAttributes.HasFlagSet(InitializeContextReqFlags.UnverifiedTargetName) && add_target_name)
                    av_flags |= MsvAvFlags.TargetSPNUntrusted;
                builderv2.TargetInfo.Add(new NtlmAvPairFlags(av_flags));
                if (add_target_name)
                {
                    builderv2.TargetInfo.Add(new NtlmAvPairString(MsAvPairType.TargetName, _target_name));
                }
                byte[] channel_binding = _config?.ChannelBinding?.ComputeHash() ?? new byte[16];
                builderv2.TargetInfo.Add(new NtlmAvPairBytes(MsAvPairType.ChannelBindings, channel_binding));
                byte[] nt_owf = _credentials.NtOWFv2();
                builderv2.CalculateNtProofResponse(nt_owf, challenge_token.ServerChallenge);
                session_base_key = CalculateHMACMD5(nt_owf, builderv2.NTProofResponse);
                builder = builderv2;
            }

            builder.Flags = nego_flags;
            builder.UserName = _credentials?.UserName ?? string.Empty;
            builder.Domain = _credentials?.Domain ?? string.Empty;
            builder.Workstation = Environment.MachineName;
            builder.Version = GetVersion();

            byte[] key_exchange_key = session_base_key;
            byte[] exported_session_key;
            bool has_signing = nego_flags.HasFlagSet(NtlmNegotiateFlags.Signing);
            bool has_sealing = nego_flags.HasFlagSet(NtlmNegotiateFlags.Seal);
            if (has_signing || has_sealing)
            {
                exported_session_key = GenerateRandomValue(16);
                builder.EncryptedSessionKey = ARC4.Transform(exported_session_key, key_exchange_key);
                _client_signing_key = GetSignKey(nego_flags, exported_session_key, true);
                _server_signing_key = GetSignKey(nego_flags, exported_session_key, false);
                _client_rc4 = new ARC4(GetSealKey(nego_flags, exported_session_key, true));
                _server_rc4 = new ARC4(GetSealKey(nego_flags, exported_session_key, false));
            }
            else
            {
                exported_session_key = key_exchange_key;
            }

            builder.MessageIntegrityCode = new byte[16];
            var auth_token = builder.Create();
            byte[] to_sign = ConcatBytes(nego_token.ToArray(), challenge_token.ToArray(), auth_token.ToArray());
            builder.MessageIntegrityCode = CalculateHMACMD5(exported_session_key, to_sign);
            Token = builder.Create();
            _session_key = exported_session_key;
            ReturnAttributes = MapFromNegotiateflags(auth_token.Flags);
            _nego_flags = nego_flags;
        }

        private void ContinueInternal(byte[] token)
        {
            if (Done)
                return;
            if (Token == null)
            {
                CreateNegotiateToken();
            }
            else
            {
                if (token is null)
                    throw new InvalidDataException("Missing NTLM token from server.");
                if (!NtlmAuthenticationToken.TryParse(token, 0, true, out NtlmAuthenticationToken challenge_token))
                    throw new InvalidDataException("Invalid NTLM token from server.");
                CreateAuthenticateToken(challenge_token as NtlmChallengeAuthenticationToken);
            }
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="credentials">The user's credentials. Can only be null if using the NullSession request attribute flag.</param>
        /// <param name="target_name">The target name for the authentication.</param>
        /// <param name="config">Additional configuration for the authentication context.</param>
        /// <param name="request_attributes">Request attributes for the context.</param>
        /// <param name="initialize">True to initialize the security context.</param>
        public NtlmClientAuthenticationContext(AuthenticationCredentials credentials, InitializeContextReqFlags request_attributes, 
            string target_name = null, NtlmClientAuthenticationContextConfig config = null, bool initialize = true)
        {
            if (!request_attributes.HasFlagSet(InitializeContextReqFlags.NullSession))
            {
                if (credentials is UserCredentials user_creds)
                {
                    _credentials = new NtHashAuthenticationCredentials(user_creds);
                }
                else
                {
                    _credentials = credentials as NtHashAuthenticationCredentials ??
                        throw new ArgumentException("Must specify credentals for NTLM authentication.", nameof(credentials));
                }
            }

            RequestAttributes = request_attributes;
            _target_name = target_name;
            _config = config;
            if (initialize)
            {
                Continue();
            }
        }
        #endregion

        #region IClientAuthenticationContext Implementation.
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        public SecPkgLastClientTokenStatus LastTokenStatus => Done ? SecPkgLastClientTokenStatus.Yes : SecPkgLastClientTokenStatus.No;

        public InitializeContextReqFlags RequestAttributes { get; }

        public InitializeContextRetFlags ReturnAttributes { get; private set; }

        public AuthenticationToken Token { get; private set; }

        public bool Done => Token is NtlmAuthenticateAuthenticationToken;

        public long Expiry => long.MaxValue;

        public byte[] SessionKey => _session_key ?? Array.Empty<byte>();

        public string PackageName => AuthenticationPackage.NTLM_NAME;

        public int MaxSignatureSize => 16;

        public int SecurityTrailerSize => 16;

        public X509Certificate2 LocalCertificate => null;

        public X509Certificate2 RemoteCertificate => null;

        public int StreamHeaderSize => 0;

        public int StreamTrailerSize => 0;

        public int StreamBufferCount => 0;

        public int StreamMaxMessageSize => 0;

        public int StreamBlockSize => 0;

        public void Continue(AuthenticationToken token)
        {
            ContinueInternal(token?.ToArray());
        }

        public void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input)
        {
            ContinueInternal(token?.ToArray());
        }

        public void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input, IEnumerable<SecurityBuffer> additional_output)
        {
            ContinueInternal(token?.ToArray());
        }

        public void Continue(IEnumerable<SecurityBuffer> input_buffers, IEnumerable<SecurityBuffer> additional_output)
        {
            var token_buffer = input_buffers?.FirstOrDefault(b => b.Type == SecurityBufferType.Token);
            ContinueInternal(token_buffer?.ToArray());
        }

        public void Continue()
        {
            ContinueInternal(null);
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
            if (!Done || !ReturnAttributes.HasFlagSet(InitializeContextRetFlags.Confidentiality))
                throw new InvalidOperationException("Sealing not supported.");

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
            byte[] plain_text = _server_rc4.Transform(data_buffers.ToByteArray());
            data_buffers.UpdateDataBuffers(plain_text);
            byte[] to_verify = messages.ToByteArray();
            if (!VerifySignature(to_verify, signature, sequence_no))
                throw new InvalidDataException("Signature is invalid.");
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
            if (!Done || !ReturnAttributes.HasFlagSet(InitializeContextRetFlags.Confidentiality))
                throw new InvalidOperationException("Sealing not supported.");

            List<ISecurityBufferInOut> data_buffers = messages.Where(b => b.Type == SecurityBufferType.Data && !b.ReadOnly)
                                                        .OfType<ISecurityBufferInOut>().ToList();
            if (data_buffers.Count == 0)
                throw new ArgumentException("Must specify a buffer to encrypt.");
            ISecurityBufferOut token_buffer = messages.Where(b => b.Type == SecurityBufferType.Token && !b.ReadOnly)
                                            .OfType<ISecurityBufferOut>().FirstOrDefault();
            if (token_buffer == null)
                throw new ArgumentException("Must specify a buffer for the token signature.");

            byte[] cipher_text = _client_rc4.Transform(data_buffers.ToByteArray());
            byte[] to_sign = messages.ToByteArray();
            data_buffers.UpdateDataBuffers(cipher_text);
            token_buffer.Update(SecurityBufferType.Token, MakeSignature(to_sign, sequence_no));
        }

        public ExportedSecurityContext Export()
        {
            throw new NotImplementedException();
        }

        public AuthenticationPackage GetAuthenticationPackage()
        {
            return new NtlmManagedAuthenticationPackage();
        }

        public byte[] MakeSignature(byte[] message, int sequence_no)
        {
            if (message is null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            return MakeSignature(new[] { new SecurityBufferInOut(SecurityBufferType.Data, message) }, sequence_no);
        }

        public byte[] MakeSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            if (messages is null)
            {
                throw new ArgumentNullException(nameof(messages));
            }

            if (!Done || !ReturnAttributes.HasFlagSet(InitializeContextRetFlags.Integrity))
                throw new InvalidOperationException("Signing not supported.");

            byte[] to_sign = messages.Where(b => b.Type == SecurityBufferType.Data).ToByteArray();
            byte[] seq_no = BitConverter.GetBytes(_client_seq_no++);
            byte[] signature = CalculateHMACMD5(_client_signing_key, ConcatBytes(seq_no, to_sign));
            if (_nego_flags.HasFlagSet(NtlmNegotiateFlags.ExtendedSessionSecurity))
            {
                signature = _client_rc4.Transform(signature, 0, 8);
            }
            byte[] ret = new byte[16];
            ret[0] = 1;
            Buffer.BlockCopy(signature, 0, ret, 4, 8);
            Buffer.BlockCopy(seq_no, 0, ret, 12, 4);
            return ret;
        }

        public bool VerifySignature(byte[] message, byte[] signature, int sequence_no)
        {
            if (message is null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            return VerifySignature(new[] { new SecurityBufferInOut(SecurityBufferType.Data, message) }, signature, sequence_no);
        }

        public bool VerifySignature(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            if (messages is null)
            {
                throw new ArgumentNullException(nameof(messages));
            }

            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (!Done || !ReturnAttributes.HasFlagSet(InitializeContextRetFlags.Integrity))
                throw new InvalidOperationException("Signing not supported.");

            if (signature.Length < 16)
                return false;

            if (BitConverter.ToInt32(signature, 0) != 1)
                return false;

            if (BitConverter.ToInt32(signature, 12) != _server_seq_no)
                return false;

            byte[] data = messages.Where(b => b.Type == SecurityBufferType.Data).ToByteArray();
            byte[] seq_no = BitConverter.GetBytes(_server_seq_no++);
            byte[] calc_sig = CalculateHMACMD5(_server_signing_key, ConcatBytes(seq_no, data));
            byte[] cmp_sig = new byte[8];
            Buffer.BlockCopy(signature, 4, cmp_sig, 0, 8);
            if (_nego_flags.HasFlagSet(NtlmNegotiateFlags.ExtendedSessionSecurity))
            {
                cmp_sig = _server_rc4.Transform(cmp_sig);
            }

            return NtObjectUtils.EqualByteArray(calc_sig, cmp_sig, 8);
        }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
        #endregion
    }
}
