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
    /// Class to represent a raw authorization data value.
    /// </summary>
    public sealed class KerberosAuthorizationDataRawBuilder : KerberosAuthorizationDataBuilder
    {
        private readonly byte[] _data;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data_type">The type of the authorization data.</param>
        /// <param name="data">The raw data for authorization data.</param>
        public KerberosAuthorizationDataRawBuilder(KerberosAuthorizationDataType data_type, byte[] data) : base(data_type)
        {
            _data = data;
        }

        /// <summary>
        /// Convert back to an authorization data object.
        /// </summary>
        /// <returns>The authorization data.</returns>
        public override KerberosAuthorizationData Create()
        {
            return new KerberosAuthorizationDataRaw(DataType, _data);
        }
    }
}
