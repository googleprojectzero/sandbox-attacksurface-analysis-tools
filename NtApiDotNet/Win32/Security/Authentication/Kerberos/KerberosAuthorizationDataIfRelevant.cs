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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.ASN1.Builder;
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent the AD-IF-RELEVANT authorization data.
    /// </summary>
    public sealed class KerberosAuthorizationDataIfRelevant : KerberosAuthorizationData
    {
        /// <summary>
        /// The list of embedded authorization data elements.
        /// </summary>
        public IReadOnlyList<KerberosAuthorizationData> Entries { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="entries">The list of additional authorization data entries.</param>
        public KerberosAuthorizationDataIfRelevant(IEnumerable<KerberosAuthorizationData> entries) 
            : base(KerberosAuthorizationDataType.AD_IF_RELEVANT)
        {
            Entries = entries.ToList().AsReadOnly();
        }

        /// <summary>
        /// Create a builder for this AD data.
        /// </summary>
        /// <returns>The builder.</returns>
        public override KerberosAuthorizationDataBuilder ToBuilder()
        {
            return new KerberosAuthorizationDataIfRelevantBuilder(Entries);
        }

        internal static bool Parse(byte[] data, out KerberosAuthorizationDataIfRelevant entry)
        {
            DERValue[] values = DERParser.ParseData(data, 0);
            if (values.Length != 1 || !values[0].CheckSequence() || !values[0].HasChildren())
            {
                entry = null;
                return false;
            }
            entry = new KerberosAuthorizationDataIfRelevant(values[0].Children.Select(c => Parse(c)));
            return true;
        }

        private protected override byte[] GetData()
        {
            DERBuilder builder = new DERBuilder();
            builder.WriteSequence(Entries);
            return builder.ToArray();
        }

        private protected override void FormatData(StringBuilder builder)
        {
            foreach (var entry in Entries)
            {
                entry.Format(builder);
            }
        }
    }
}
