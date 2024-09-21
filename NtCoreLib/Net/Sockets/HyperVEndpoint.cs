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

using System;
using System.Net;
using System.Net.Sockets;

namespace NtApiDotNet.Net.Sockets
{
    /// <summary>
    /// Endpoint implementation for a HyperV socket.
    /// </summary>
    [Serializable]
    public class HyperVEndPoint : EndPoint
    {
        /// <summary>
        /// Address family.
        /// </summary>
        public readonly static AddressFamily AF_HYPERV = (AddressFamily)34;
        /// <summary>
        /// Protocol type for HyperV sockets.
        /// </summary>
        public readonly static ProtocolType HV_PROTOCOL_RAW = (ProtocolType)1;

        private static void CopyGuid(Guid guid, SocketAddress address, int offset)
        {
            byte[] bytes = guid.ToByteArray();
            for (int i = 0; i < bytes.Length; ++i)
            {
                address[i + offset] = bytes[i];
            }
        }

        private static Guid ReadGuid(SocketAddress address, int offset)
        {
            byte[] bytes = new byte[16];
            for (int i = 0; i < bytes.Length; ++i)
            {
                bytes[i] = address[i + offset];
            }
            return new Guid(bytes);
        }

        /// <summary>
        /// Default constructor.
        /// </summary>
        public HyperVEndPoint()
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public HyperVEndPoint(Guid service_id, Guid vm_id)
        {
            ServiceId = service_id;
            VmId = vm_id;
        }

        /// <summary>
        /// Get or set the service ID.
        /// </summary>
        public Guid ServiceId { get; set; }

        /// <summary>
        /// Get or set the VM ID.
        /// </summary>
        public Guid VmId { get; set; }

        /// <summary>
        /// Address family.
        /// </summary>
        public override AddressFamily AddressFamily => AF_HYPERV;

        /// <summary>
        /// Serialize the socket address.
        /// </summary>
        /// <returns>The serialized address.</returns>
        public override SocketAddress Serialize()
        {
            // At least on Windows you need to allocate the entire address otherwise bad things happen.
            var addr = new SocketAddress(AddressFamily, 36);
            CopyGuid(VmId, addr, 4);
            CopyGuid(ServiceId, addr, 20);
            return addr;
        }

        /// <summary>
        /// Create a endpoint from a socket address.
        /// </summary>
        /// <param name="address">The socket address.</param>
        /// <returns>The created endpoint.</returns>
        public override EndPoint Create(SocketAddress address)
        {
            if (address.Family != AF_HYPERV)
                throw new ArgumentException("Family in socket address isn't AF_HYPERV");
            return new HyperVEndPoint(ReadGuid(address, 20), ReadGuid(address, 4));
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The endpoint as a string.</returns>
        public override string ToString()
        {
            return $"{ServiceId} - {VmId}";
        }

        /// <summary>
        /// Overridden equals method.
        /// </summary>
        /// <param name="obj">The object to compare.</param>
        /// <returns>True if the objects are equal.</returns>
        public override bool Equals(object obj)
        {
            if (!(obj is HyperVEndPoint))
            {
                return false;
            }

            HyperVEndPoint ep = (HyperVEndPoint)obj;
            return ep.ServiceId == ServiceId && ep.VmId == VmId;
        }

        /// <summary>
        /// Get endpoint hash code.
        /// </summary>
        /// <returns>The hashcode.</returns>
        public override int GetHashCode()
        {
            return ServiceId.GetHashCode() ^ VmId.GetHashCode();
        }
    }
}
