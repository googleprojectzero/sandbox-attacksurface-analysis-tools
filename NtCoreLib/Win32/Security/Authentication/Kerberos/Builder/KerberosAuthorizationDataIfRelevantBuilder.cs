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
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// Class to build an IF-RELEVANT authorization data.
    /// </summary>
    public sealed class KerberosAuthorizationDataIfRelevantBuilder : KerberosAuthorizationDataBuilder
    {
        /// <summary>
        /// The list of embedded authorization data elements.
        /// </summary>
        public List<KerberosAuthorizationDataBuilder> Entries { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosAuthorizationDataIfRelevantBuilder() 
            : base(KerberosAuthorizationDataType.AD_IF_RELEVANT)
        {
            Entries = new List<KerberosAuthorizationDataBuilder>();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="entries">List of authorization entry builders.</param>
        public KerberosAuthorizationDataIfRelevantBuilder(IEnumerable<KerberosAuthorizationDataBuilder> entries) : this()
        {
            Entries.AddRange(entries);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="entries">List of authorization entries.</param>
        public KerberosAuthorizationDataIfRelevantBuilder(IEnumerable<KerberosAuthorizationData> entries) 
            : this(entries.Select(e => e.ToBuilder()))
        {
        }

        /// <summary>
        /// Create the Kerberos IF-RELEVANT data.
        /// </summary>
        /// <returns>The kerberos IF-RELEVANT data.</returns>
        public override KerberosAuthorizationData Create()
        {
            DERBuilder builder = new DERBuilder();
            builder.WriteSequence(Entries.Select(b => b.Create()));
            if (!KerberosAuthorizationDataIfRelevant.Parse(builder.ToArray(), out KerberosAuthorizationDataIfRelevant auth_data))
                throw new InvalidDataException("IF-RELEVANT data is invalid.");
            return auth_data;
        }
    }
}
