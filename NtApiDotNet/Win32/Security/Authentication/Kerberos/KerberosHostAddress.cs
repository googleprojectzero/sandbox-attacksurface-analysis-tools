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
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
#pragma warning disable 1591
    /// <summary>
    /// Type of Kerberos Host Address.
    /// </summary>
    public enum KerberosHostAddressType
    {
        IPv4 = 2,
        Directional = 3,
        ChaosNet = 5,
        XNS = 6,
        ISO = 7,
        DECNETPhaseIV = 12,
        AppleTalkDDP = 16,
        NetBios = 20,
        IPv6 = 24,
    }
#pragma warning restore 1591

    /// <summary>
    /// Class representing a Kerberos Host Address.
    /// </summary>
    public class KerberosHostAddress
    {
        /// <summary>
        /// Type of host address.
        /// </summary>
        public KerberosHostAddressType AddressType { get; }
        /// <summary>
        /// Address bytes.
        /// </summary>
        public byte[] Address { get; }

        /// <summary>
        /// ToString Method.
        /// </summary>
        /// <returns>The formatted string.</returns>
        public override string ToString()
        {
            switch (AddressType)
            {
                case KerberosHostAddressType.IPv4:
                    if (Address.Length == 4)
                    {
                        return $"IPv4: {new IPAddress(Address)}";
                    }
                    break;
                case KerberosHostAddressType.IPv6:
                    if (Address.Length == 16)
                    {
                        return $"IPv6: {new IPAddress(Address)}";
                    }
                    break;
            }
            return $"{AddressType} - {NtObjectUtils.ToHexString(Address)}";
        }

        private KerberosHostAddress(KerberosHostAddressType type, byte[] address)
        {
            AddressType = type;
            Address = address;
        }

        internal static KerberosHostAddress Parse(DERValue value)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();
            KerberosHostAddressType type = 0;
            byte[] data = null;
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        type = (KerberosHostAddressType)next.ReadChildInteger();
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
            return new KerberosHostAddress(type, data);
        }

        internal static IReadOnlyList<KerberosHostAddress> ParseSequence(DERValue value)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();
            List<KerberosHostAddress> ret = new List<KerberosHostAddress>();

            foreach (var next in value.Children)
            {
                ret.Add(Parse(next));
            }
            return ret.AsReadOnly();
        }
    }
}
