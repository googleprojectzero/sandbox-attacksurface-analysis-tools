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

using NtApiDotNet.Win32.Security.Buffers;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to delegate calls to authentication context APIs.
    /// </summary>
    public abstract class AuthenticationContextDelegate<T> : IAuthenticationContext where T : IAuthenticationContext
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        protected T _context;

        private protected AuthenticationContextDelegate(T context)
        {
            _context = context;
        }

        public virtual AuthenticationToken Token => _context.Token;

        public virtual bool Done => _context.Done;

        public virtual long Expiry => _context.Expiry;

        public virtual byte[] SessionKey => _context.SessionKey;

        public virtual string PackageName => _context.PackageName;

        public virtual int MaxSignatureSize => _context.MaxSignatureSize;

        public virtual int SecurityTrailerSize => _context.SecurityTrailerSize;

        public int StreamHeaderSize => _context.StreamHeaderSize;

        public int StreamTrailerSize => _context.StreamTrailerSize;

        public int StreamBufferCount => _context.StreamBufferCount;

        public int StreamMaxMessageSize => _context.StreamMaxMessageSize;

        public int StreamBlockSize => _context.StreamBlockSize;

        public virtual void Continue(AuthenticationToken token)
        {
            _context.Continue(token);
        }

        public virtual void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input)
        {
            _context.Continue(token, additional_input);
        }

        public virtual void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input, IEnumerable<SecurityBuffer> additional_output)
        {
            _context.Continue(token, additional_input, additional_output);
        }

        public virtual void Continue(IEnumerable<SecurityBuffer> input_buffers, IEnumerable<SecurityBuffer> additional_output)
        {
            _context.Continue(input_buffers, additional_output);
        }

        public virtual void Continue()
        {
            _context.Continue();
        }

        public virtual byte[] DecryptMessage(EncryptedMessage message, int sequence_no)
        {
            return _context.DecryptMessage(message, sequence_no);
        }

        public virtual void DecryptMessage(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            _context.DecryptMessage(messages, signature, sequence_no);
        }

        public virtual void DecryptMessageNoSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            _context.DecryptMessageNoSignature(messages, sequence_no);
        }

        public virtual void Dispose()
        {
            _context.Dispose();
        }

        public virtual EncryptedMessage EncryptMessage(byte[] message, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            return _context.EncryptMessage(message, quality_of_protection, sequence_no);
        }

        public virtual byte[] EncryptMessage(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            return _context.EncryptMessage(messages, quality_of_protection, sequence_no);
        }

        public virtual void EncryptMessageNoSignature(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            _context.EncryptMessageNoSignature(messages, quality_of_protection, sequence_no);
        }

        public virtual ExportedSecurityContext Export()
        {
            return _context.Export();
        }

        public virtual AuthenticationPackage GetAuthenticationPackage()
        {
            return _context.GetAuthenticationPackage();
        }

        public virtual byte[] MakeSignature(byte[] message, int sequence_no)
        {
            return _context.MakeSignature(message, sequence_no);
        }

        public virtual byte[] MakeSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            return _context.MakeSignature(messages, sequence_no);
        }

        public virtual bool VerifySignature(byte[] message, byte[] signature, int sequence_no)
        {
            return _context.VerifySignature(message, signature, sequence_no);
        }

        public virtual bool VerifySignature(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            return _context.VerifySignature(messages, signature, sequence_no);
        }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
