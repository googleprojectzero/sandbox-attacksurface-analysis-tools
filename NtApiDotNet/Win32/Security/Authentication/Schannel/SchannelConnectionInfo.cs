//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32.Security.Native;

namespace NtApiDotNet.Win32.Security.Authentication.Schannel
{
    /// <summary>
    /// Negotiated connection information for Schannel.
    /// </summary>
    public sealed class SchannelConnectionInfo
    {
        /// <summary>
        /// The protocol used by Schannel.
        /// </summary>
        public SchannelProtocolType Protocol { get; }
        /// <summary>
        /// The negotitated cipher algorithm.
        /// </summary>
        public SchannelAlgorithmType CipherAlgorithm { get; }
        /// <summary>
        /// The negotiated cipher strength in bits.
        /// </summary>
        public int CipherStrength { get; }
        /// <summary>
        /// The negotiated hash algorithm.
        /// </summary>
        public SchannelAlgorithmType HashAlgorithm { get; }
        /// <summary>
        /// The negotiated hash string.
        /// </summary>
        public int HashStrength { get; }
        /// <summary>
        /// The negotiated key exchange algorithm.
        /// </summary>
        public SchannelAlgorithmType ExchangeAlgorithm { get; }
        /// <summary>
        /// The negotiated key exchange strength.
        /// </summary>
        public int ExchangeStrength { get; }

        internal SchannelConnectionInfo(SecPkgContext_ConnectionInfo info)
        {
            Protocol = (SchannelProtocolType)info.dwProtocol;
            CipherAlgorithm = (SchannelAlgorithmType)info.aiCipher;
            CipherStrength = info.dwCipherStrength;
            HashAlgorithm = (SchannelAlgorithmType)info.aiHash;
            HashStrength = info.dwHashStrength;
            ExchangeAlgorithm = (SchannelAlgorithmType)info.aiExch;
            ExchangeStrength = info.dwExchStrength;
        }
    }
}
