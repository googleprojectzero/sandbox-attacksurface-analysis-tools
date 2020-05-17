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

using NtApiDotNet.Utilities.ASN1;
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// The supported transited encoding types.
    /// </summary>
    public enum KerberosTransitedEncodingType
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// X.500 Compress.
        /// </summary>
        X500Compress = 1,
    }

    /// <summary>
    /// Class to represent a Kerberos Transiting Encoding.
    /// </summary>
    public sealed class KerberosTransitedEncoding
    {
        /// <summary>
        /// Transited encoding type.
        /// </summary>
        public KerberosTransitedEncodingType TransitedType { get; }

        /// <summary>
        /// Transited encoding data.
        /// </summary>
        public byte[] Data { get; }

        private KerberosTransitedEncoding(KerberosTransitedEncodingType type, byte[] data)
        {
            TransitedType = type;
            Data = data;
        }

        internal static KerberosTransitedEncoding Parse(DERValue value)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();
            KerberosTransitedEncodingType type = 0;
            byte[] data = null;
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        type = (KerberosTransitedEncodingType)next.ReadChildInteger();
                        break;
                    case 1:
                        data = next.ReadChildOctetString();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }

            if (data == null)
                throw new InvalidDataException();
            return new KerberosTransitedEncoding(type, data);
        }
    }
}
