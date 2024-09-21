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

using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a PAC_REQUESTOR entry.
    /// </summary>
    public sealed class KerberosAuthorizationDataPACRequestor : KerberosAuthorizationDataPACEntry
    {
        /// <summary>
        /// The SID of the requestor.
        /// </summary>
        public Sid Requestor { get; }

        private KerberosAuthorizationDataPACRequestor(byte[] data, Sid requestor) 
            : base(KerberosAuthorizationDataPACEntryType.Requestor, data)
        {
            Requestor = requestor;
        }

        internal static bool Parse(byte[] data, out KerberosAuthorizationDataPACEntry entry)
        {
            entry = null;

            var sid = Sid.Parse(data, false);
            if (!sid.IsSuccess)
                return false;
            entry = new KerberosAuthorizationDataPACRequestor(data, sid.Result);
            return true;
        }

        private protected override void FormatData(StringBuilder builder)
        {
            builder.AppendLine($"Requestor Name   : {Requestor.Name}");
            builder.AppendLine($"Requestor SID    : {Requestor}");
        }
    }
}
