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

using NtApiDotNet.Utilities.Data;
using NtApiDotNet.Win32.Security.Buffers;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Security.Cryptography.X509Certificates;

namespace NtApiDotNet.Win32.Security.Authentication.CredSSP
{
    /// <summary>
    /// Class to represent a security buffer containing the TSSSP server certificate.
    /// </summary>
    public sealed class SecurityBufferTSSSPCertificate : SecurityBuffer
    {
        /// <summary>
        /// The server certificate to use.
        /// </summary>
        public X509Certificate Certificate { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="certificate">The server certificate to use.</param>
        public SecurityBufferTSSSPCertificate(X509Certificate certificate) 
            : base(SecurityBufferType.Token | SecurityBufferType.ReadOnly)
        {
            Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        }

        /// <summary>
        /// Convert to buffer back to an array.
        /// </summary>
        /// <returns>The buffer as an array.</returns>
        public override byte[] ToArray()
        {
            byte[] ba = Certificate.Export(X509ContentType.Cert);
            DataWriter writer = new DataWriter();
            writer.Write(3);
            writer.Write(ba.Length);
            writer.Write(ba);
            writer.Write(0);
            return writer.ToArray();
        }

        internal override void FromBuffer(SecBuffer _)
        {
        }

        internal override SecBuffer ToBuffer(DisposableList list)
        {
            return SecBuffer.Create(Type, ToArray(), list);
        }
    }
}
