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

using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authenticode
{
    /// <summary>
    /// ELAM information.
    /// </summary>
    public sealed class ElamInformation
    {
        /// <summary>
        /// The hash of the certificate.
        /// </summary>
        public string CertificateHash { get; }
        /// <summary>
        /// The hash algorithm.
        /// </summary>
        public HashAlgorithm Algorithm { get; }
        /// <summary>
        /// List of optional EKUs.
        /// </summary>
        public IReadOnlyCollection<string> EnhancedKeyUsage { get; }

        internal ElamInformation(string hash, HashAlgorithm algorithm, IEnumerable<string> ekus)
        {
            CertificateHash = hash;
            Algorithm = algorithm;
            EnhancedKeyUsage = ekus.ToList().AsReadOnly();
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The ELAM information as a string.</returns>
        public override string ToString()
        {
            return $"{Algorithm} - {CertificateHash}";
        }
    }
}
