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
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a Kerberos Checksum.
    /// </summary>
    public class KerberosChecksum
    {
        /// <summary>
        /// Type of kerberos checksum.
        /// </summary>
        public KerberosChecksumType ChecksumType { get;}
        /// <summary>
        /// The checksum value.
        /// </summary>
        public byte[] Checksum { get; }

        internal virtual void Format(StringBuilder builder)
        {
            builder.AppendLine($"Checksum        : {ChecksumType} - {NtObjectUtils.ToHexString(Checksum)}");
        }

        private protected KerberosChecksum(KerberosChecksumType type, byte[] data)
        {
            ChecksumType = type;
            Checksum = data;
        }

        internal static KerberosChecksum Parse(DERValue value)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();
            KerberosChecksumType type = 0;
            byte[] data = null;
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        type = (KerberosChecksumType)next.ReadChildInteger();
                        break;
                    case 1:
                        data = next.ReadChildOctetString();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }

            if (type == 0 || data == null)
                throw new InvalidDataException();
            if (type == KerberosChecksumType.GSSAPI && KerberosChecksumGSSApi.Parse(data, out KerberosChecksum chksum))
            {
                return chksum;
            }
            return new KerberosChecksum(type, data);
        }
    }
}
