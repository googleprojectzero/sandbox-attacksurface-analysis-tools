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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// A PAC authorization builder where the contents aren't known.
    /// </summary>
    public sealed class KerberosAuthorizationDataPACEntryRawBuilder : KerberosAuthorizationDataPACEntryBuilder
    {
        /// <summary>
        /// The raw data.
        /// </summary>
        public byte[] Data { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="entry">The unknown element.</param>
        public KerberosAuthorizationDataPACEntryRawBuilder(KerberosAuthorizationDataPACEntry entry) 
            : base(entry.PACType)
        {
            Data = entry.Data;
        }

        /// <summary>
        /// Create the PAC entry.
        /// </summary>
        /// <returns>The PAC entry.</returns>
        public override KerberosAuthorizationDataPACEntry Create()
        {
            return new KerberosAuthorizationDataPACEntry(PACType, Data);
        }
    }
}
