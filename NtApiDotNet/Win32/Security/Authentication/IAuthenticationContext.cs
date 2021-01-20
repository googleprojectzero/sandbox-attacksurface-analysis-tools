//  Copyright 2020 Google Inc. All Rights Reserved.
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
    /// Interface for authentication contexts.
    /// </summary>
    public interface IAuthenticationContext
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
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The encrypted message.</returns>
        EncryptedMessage EncryptMessage(byte[] message, int sequence_no);

        /// <summary>
        /// Decrypt a message for this context.
        /// </summary>
        /// <param name="message">The message to decrypt.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The decrypted message.</returns>
        byte[] DecryptMessage(EncryptedMessage message, int sequence_no);
    }
}
