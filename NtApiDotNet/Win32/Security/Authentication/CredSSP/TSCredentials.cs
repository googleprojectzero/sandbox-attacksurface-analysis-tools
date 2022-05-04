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

using NtApiDotNet.Utilities.ASN1.Builder;

namespace NtApiDotNet.Win32.Security.Authentication.CredSSP
{
    /// <summary>
    /// Base class to represent TSSSP credentials.
    /// </summary>
    public abstract class TSCredentials
    {
        /// <summary>
        /// Specify the type of credentials.
        /// </summary>
        public TSCredentialsType CredType { get; }

        /// <summary>
        /// Convert the credentials to an array.
        /// </summary>
        /// <returns>The credential array.</returns>
        public byte[] ToArray()
        {
            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, (int)CredType);
                seq.WriteContextSpecific(1, GetCredentials());
            }
            return builder.ToArray();
        }

        private protected TSCredentials(TSCredentialsType type)
        {
            CredType = type;
        }

        private protected abstract byte[] GetCredentials();
    }
}
