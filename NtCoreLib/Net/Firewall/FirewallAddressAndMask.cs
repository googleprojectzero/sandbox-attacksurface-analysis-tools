//  Copyright 2021 Google LLC. All Rights Reserved.
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

using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Represents a firewall address and mask.
    /// </summary>
    public struct FirewallAddressAndMask
    {
        /// <summary>
        /// The IP address.
        /// </summary>
        public IPAddress Address { get;}

        /// <summary>
        /// The mask.
        /// </summary>
        public IPAddress Mask { get; }

        /// <summary>
        /// Mask prefix length.
        /// </summary>
        public int PrefixLength { get; }

        private static int CalculatePrefix(IPAddress mask)
        {
            byte[] ba = mask.GetAddressBytes();
            int i;
            for (i = 0; i < ba.Length; ++i)
            {
                if (ba[i] != 0xFF)
                {
                    break;
                }
            }

            int prefix = i * 8;
            if (i == ba.Length)
            {
                return prefix;
            }

            for (int j = 7; j >= 0; --j, ++prefix)
            {
                if ((ba[i] & (1 << j)) == 0)
                {
                    break;
                }
            }
            return prefix;
        }

        private static IPAddress CalculateMask(IPAddress address, int prefix)
        {
            byte[] ba = new byte[address.GetAddressBytes().Length];
            for (int i = 0; i < ba.Length; ++i)
            {
                if (prefix >= 8)
                {
                    ba[i] = 0xFF;
                }
                else if (prefix <= 0)
                {
                    break;
                }
                else
                {
                    ba[i] = (byte)(0xFF << (8 - prefix));
                }
                prefix -= 8;
            }
            return new IPAddress(ba);
        }

        private static IPAddress GetAddress(uint addr)
        {
            byte[] ba = BitConverter.GetBytes(addr);
            Array.Reverse(ba);
            return new IPAddress(ba);
        }

        internal FirewallAddressAndMask(IPAddress address, IPAddress mask)
        {
            Address = address;
            Mask = mask;
            PrefixLength = CalculatePrefix(mask);
        }

        internal FirewallAddressAndMask(FWP_V4_ADDR_AND_MASK value) 
            : this(GetAddress(value.addr), GetAddress(value.mask))
        {
        }

        internal FirewallAddressAndMask(FWP_V6_ADDR_AND_MASK value) 
            : this(new IPAddress(value.addr), value.prefixLength)
        {
        }

        internal FirewallAddressAndMask(IPAddress address, int prefix)
        {
            Address = address;
            Mask = CalculateMask(address, prefix);
            PrefixLength = prefix;
        }

        internal SafeBuffer ToBuffer(DisposableList list)
        {
            switch (Address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    return list.AddStructureRef(new FWP_V4_ADDR_AND_MASK()
                    {
                        addr = BitConverter.ToUInt32(Address.GetAddressBytes().Reverse().ToArray(), 0),
                        mask = BitConverter.ToUInt32(Mask.GetAddressBytes().Reverse().ToArray(), 0),
                    });
                case AddressFamily.InterNetworkV6:
                    return list.AddStructureRef(new FWP_V6_ADDR_AND_MASK()
                    {
                        addr = Address.GetAddressBytes(),
                        prefixLength = (byte)PrefixLength
                    });
                default:
                    throw new ArgumentException("Invalid address family.");
            }
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The value and mask as a string.</returns>
        public override string ToString()
        {
            return $"{Address} - Prefix: {PrefixLength}";
        }
    }
}
