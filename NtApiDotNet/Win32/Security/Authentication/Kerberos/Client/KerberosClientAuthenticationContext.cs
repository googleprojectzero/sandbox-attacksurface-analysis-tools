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
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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

        public int MaxSignatureSize => throw new NotImplementedException();

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
