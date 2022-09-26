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
                ret |= InitializeContextRetFlags.Integrity;
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
                Version = NtlmClientUtils.GetVersion()
            }.Create();
        }

        private void CreateAuthenticateToken(NtlmChallengeAuthenticationToken challenge_token)
        {
            if (challenge_token == null)
                throw new InvalidDataException("Expected NTLM CHALLENGE token from server.");
            NtlmAuthenticateAuthenticationTokenBuilderBase builder;
            NtlmNegotiateFlags negflags = challenge_token.Flags & ~(NtlmNegotiateFlags.KeyExchange | NtlmNegotiateFlags.Version |
                NtlmNegotiateFlags.TargetTypeDomain | NtlmNegotiateFlags.TargetTypeServer | NtlmNegotiateFlags.TargetTypeShare);
            AuthenticationToken nego_token = Token;
            byte[] session_base_key;
            if (_credentials == null)
            {
                builder = new NtlmAuthenticateAuthenticationTokenBuilder
                {
                    LmChallengeResponse = new byte[1],
                    NtChallengeResponse = Array.Empty<byte>(),
                    Flags = negflags | NtlmNegotiateFlags.Anonymous
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
                builderv2.ClientChallenge = NtlmClientUtils.GenerateRandomValue(8);
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
                byte[] channel_binding = new byte[16];
                if (_config?.ChannelBinding != null)
                {
                    channel_binding = MD5.Create().ComputeHash(_config.ChannelBinding);
                }
                builderv2.TargetInfo.Add(new NtlmAvPairBytes(MsAvPairType.ChannelBindings, channel_binding));
                byte[] nt_owf = _credentials.NtOWFv2();
                builderv2.CalculateNtProofResponse(nt_owf, challenge_token.ServerChallenge);
                session_base_key = NtlmClientUtils.CalculateHMACMD5(nt_owf, builderv2.NTProofResponse);
                builder = builderv2;
            }

            builder.Flags = negflags;
            builder.UserName = _credentials?.UserName ?? string.Empty;
            builder.Domain = _credentials?.Domain ?? string.Empty;
            builder.Workstation = Environment.MachineName;
            builder.Version = NtlmClientUtils.GetVersion();

            byte[] key_exchange_key = session_base_key;
            byte[] exported_session_key;
            if (negflags.HasFlagSet(NtlmNegotiateFlags.Signing) || negflags.HasFlagSet(NtlmNegotiateFlags.Seal))
            {
                exported_session_key = NtlmClientUtils.GenerateRandomValue(16);
                builder.EncryptedSessionKey = ARC4.Transform(exported_session_key, key_exchange_key);
            }
            else
            {
                exported_session_key = key_exchange_key;
            }

            builder.MessageIntegrityCode = new byte[16];
            var auth_token = builder.Create();
            byte[] to_sign = NtlmClientUtils.ConcatBytes(nego_token.ToArray(), challenge_token.ToArray(), auth_token.ToArray());
            builder.MessageIntegrityCode = NtlmClientUtils.CalculateHMACMD5(exported_session_key, to_sign);
            Token = builder.Create();
            SessionKey = exported_session_key;
            ReturnAttributes = MapFromNegotiateflags(auth_token.Flags);
        }

        private void ContinueInternal(byte[] token)
        {
            if (Done)
                return;
            if (token is null)
                throw new InvalidDataException("Missing NTLM token from server.");
            if (!NtlmAuthenticationToken.TryParse(token, 0, true, out NtlmAuthenticationToken challenge_token))
                throw new InvalidDataException("Invalid NTLM token from server.");
            CreateAuthenticateToken(challenge_token as NtlmChallengeAuthenticationToken);
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
        public NtlmClientAuthenticationContext(AuthenticationCredentials credentials, InitializeContextReqFlags request_attributes, 
            string target_name = null, NtlmClientAuthenticationContextConfig config = null)
        {
            if (credentials is UserCredentials user_creds)
            {
                _credentials = new NtHashAuthenticationCredentials(user_creds);
            }
            else
            {
                _credentials = credentials as NtHashAuthenticationCredentials;
                if (_credentials == null && !request_attributes.HasFlagSet(InitializeContextReqFlags.NullSession))
                {
                    throw new ArgumentException("Must specify credentals for NTLM authentication.", nameof(credentials));
                }
            }

            RequestAttributes = request_attributes;
            _target_name = target_name;
            _config = config;
            CreateNegotiateToken();
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

        public byte[] SessionKey { get; private set; }

        public string PackageName => AuthenticationPackage.NTLM_NAME;

        public int MaxSignatureSize => 16;

        public int SecurityTrailerSize => 16;

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
            return AuthenticationPackage.FromName(AuthenticationPackage.NTLM_NAME);
        }

        public byte[] MakeSignature(byte[] message, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public byte[] MakeSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public bool VerifySignature(byte[] message, byte[] signature, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public bool VerifySignature(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            throw new NotImplementedException();
        }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
        #endregion
    }
}
