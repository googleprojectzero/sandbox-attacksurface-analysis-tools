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

using System.Security.Cryptography;

namespace NtApiDotNet.Utilities.ASN1
{
    /// <summary>
    /// Class containing known OID values.
    /// </summary>
    public static class OIDValues
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        public const string KERBEROS_NAME = "1.2.840.113554.1.2.2.1";
        public const string KERBEROS_PRINCIPAL = "1.2.840.113554.1.2.2.2";
        public const string KERBEROS_USER_TO_USER = "1.2.840.113554.1.2.2.3";
        public const string KERBEROS = "1.2.840.113554.1.2.2";
        public const string MS_KERBEROS = "1.2.840.48018.1.2.2";
        public const string NTLM_SSP = "1.3.6.1.4.1.311.2.2.10";
        public const string MS_NEGOX = "1.3.6.1.4.1.311.2.2.30";
        public const string SPNEGO = "1.3.6.1.5.5.2";
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member

        /// <summary>
        /// Convert an OID to a human readable name.
        /// </summary>
        /// <param name="oid">The OID to convert.</param>
        /// <returns>The human readable name if known.</returns>
        public static string ToString(string oid)
        {
            switch (oid)
            {
                case KERBEROS:
                case KERBEROS_NAME:
                    return "Kerberos";
                case KERBEROS_USER_TO_USER:
                    return "Kerberos User to User";
                case MS_KERBEROS:
                    return "Microsoft Kerberos";
                case NTLM_SSP:
                    return "NTLM";
                case MS_NEGOX:
                    return "Microsoft Negotiate Extended";
                case SPNEGO:
                    return "SPNEGO";
                default:
                    return new Oid(oid).FriendlyName ?? $"UNKNOWN OID {oid}";
            }
        }
    }
}
