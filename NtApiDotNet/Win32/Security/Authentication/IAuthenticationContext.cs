﻿//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Interface for authentication contexts.
    /// </summary>
    public interface IAuthenticationContext : IDisposable
    {
        /// <summary>
        /// The current authentication token.
        /// </summary>
        AuthenticationToken Token { get; }

        /// <summary>
        /// Whether the authentication is done.
        /// </summary>
        bool Done { get; }

        /// <summary>
        /// Expiry of the authentication.
        /// </summary>
        long Expiry { get; }

        /// <summary>
        /// Session key for the context.
        /// </summary>
        byte[] SessionKey { get; }

        /// <summary>
        /// Make a signature for this context.
        /// </summary>
        /// <param name="message">The message to sign.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The signature blob.</returns>
        byte[] MakeSignature(byte[] message, int sequence_no);

        /// <summary>
        /// Verify a signature for this context.
        /// </summary>
        /// <param name="message">The message to verify.</param>
        /// <param name="signature">The signature blob for the message.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>True if the signature is valid, otherwise false.</returns>
        bool VerifySignature(byte[] message, byte[] signature, int sequence_no);

        /// <summary>
        /// Make a signature for this context.
        /// </summary>
        /// <param name="messages">The message buffers to sign.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The signature blob.</returns>
        byte[] MakeSignature(IEnumerable<SecurityBuffer> messages, int sequence_no);

        /// <summary>
        /// Verify a signature for this context.
        /// </summary>
        /// <param name="messages">The messages to verify.</param>
        /// <param name="signature">The signature blob for the message.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>True if the signature is valid, otherwise false.</returns>
        bool VerifySignature(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no);

        /// <summary>
        /// Encrypt a message for this context.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="quality_of_protection">Quality of protection flags.</param>
        /// <returns>The encrypted message.</returns>
        /// <param name="sequence_no">The sequence number.</param>
        EncryptedMessage EncryptMessage(byte[] message, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no);

        /// <summary>
        /// Encrypt a message for this context.
        /// </summary>
        /// <param name="messages">The messages to encrypt.</param>
        /// <param name="quality_of_protection">Quality of protection flags.</param>
        /// <returns>The signature for the messages.</returns>
        /// <remarks>The messages are encrypted in place. You can add buffers with the ReadOnly flag to prevent them being encrypted.</remarks>
        /// <param name="sequence_no">The sequence number.</param>
        byte[] EncryptMessage(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no);

        /// <summary>
        /// Encrypt a message for this context with no specific signature.
        /// </summary>
        /// <param name="messages">The messages to encrypt.</param>
        /// <param name="quality_of_protection">Quality of protection flags.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <remarks>The messages are encrypted in place. You can add buffers with the ReadOnly flag to prevent them being encrypted. 
        /// If you need to return a signature then it must be specified in a buffer.</remarks>
        void EncryptMessageNoSignature(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no);

        /// <summary>
        /// Decrypt a message for this context.
        /// </summary>
        /// <param name="message">The message to decrypt.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The decrypted message.</returns>
        byte[] DecryptMessage(EncryptedMessage message, int sequence_no);

        /// <summary>
        /// Decrypt a message for this context.
        /// </summary>
        /// <param name="messages">The messages to decrypt.</param>
        /// <param name="signature">The signature for the messages.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <remarks>The messages are decrypted in place. You can add buffers with the ReadOnly flag to prevent them being decrypted.</remarks>
        void DecryptMessage(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no);

        /// <summary>
        /// Decrypt a message for this context.
        /// </summary>
        /// <param name="messages">The messages to decrypt.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <remarks>The messages are decrypted in place. You can add buffers with the ReadOnly flag to prevent them being decrypted.
        /// If you need to specify a signature you need to add a buffer.</remarks>
        void DecryptMessageNoSignature(IEnumerable<SecurityBuffer> messages, int sequence_no);

        /// <summary>
        /// Export and delete the current security context.
        /// </summary>
        /// <returns>The exported security context.</returns>
        /// <remarks>The security context will not longer be usable afterwards.</remarks>
        ExportedSecurityContext Export();

        /// <summary>
        /// Query the context's package info.
        /// </summary>
        /// <returns>The authentication package info,</returns>
        AuthenticationPackage GetAuthenticationPackage();

        /// <summary>
        /// Get the name of the authentication package.
        /// </summary>
        string PackageName { get; }

        /// <summary>
        /// Continue the authentication with the token.
        /// </summary>
        /// <param name="token">The token to continue authentication.</param>
        void Continue(AuthenticationToken token);

        /// <summary>
        /// Continue the authentication..
        /// </summary>
        /// <param name="token">The token to continue authentication.</param>
        /// <param name="additional_input">Additional input buffers for the continue, does not need to include the token.</param>
        void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input);

        /// <summary>
        /// Continue the authentication.
        /// </summary>
        /// <param name="token">The token to continue authentication.</param>
        /// <param name="additional_input">Additional input buffers for the continue, does not need to include the token.</param>
        /// <param name="additional_output">Specify additional output buffers, does not need to include the token.</param>
        void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input, IEnumerable<SecurityBuffer> additional_output);

        /// <summary>
        /// Continue the authentication.
        /// </summary>
        /// <param name="input_buffers">Additional input buffers for the continue. Does not contain a token.</param>
        /// <param name="additional_output">Specify additional output buffers, does not need to include the token.</param>
        /// <remarks>This sends the input buffers directly to the initialize call, it does not contain any token.</remarks>
        void Continue(IEnumerable<SecurityBuffer> input_buffers, IEnumerable<SecurityBuffer> additional_output);

        /// <summary>
        /// Continue the authentication. Will not pass any buffers to the accept call.
        /// </summary>
        void Continue();

        /// <summary>
        /// Get the maximum signature size of this context.
        /// </summary>
        int MaxSignatureSize { get; }

        /// <summary>
        /// Get the size of the security trailer for this context.
        /// </summary>
        int SecurityTrailerSize { get; }
    }
}
