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
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.PkInit
{
    internal static class KerberosPkInitUtils
    {
        private static SignedCms ParseSignedData(byte[] data, bool try_fallback)
        {
            try
            {
                SignedCms ret = new SignedCms();
                ret.Decode(data);
                return ret;
            }
            catch (CryptographicException)
            {
                if (!try_fallback)
                    throw;
            }

            // At least for PKU2U it seems the CMS is missing a header that breaks the .NET parser.
            // The Windows code passes the undocumented CMSG_LENGTH_ONLY_FLAG flag when parsing the
            // CMS which works without the header. Add the header ourselves.
            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                seq.WriteObjectId("1.2.840.113549.1.7.2");
                using (var ctx = seq.CreateContextSpecific(0))
                {
                    ctx.WriteRawBytes(data);
                }
            }

            return ParseSignedData(builder.ToArray(), false);
        }

        public static SignedCms ParseSignedData(byte[] data)
        {
            return ParseSignedData(data, true);
        }
    }
}
