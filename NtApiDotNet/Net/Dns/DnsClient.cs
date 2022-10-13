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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace NtApiDotNet.Net.Dns
{
    /// <summary>
    /// Basic cross-platform DNS client.
    /// </summary>
    /// <remarks>This is mainly to support a few raw queries that are not available in the .NET Dns class. Use that in preference
    /// to this one.</remarks>
    public sealed class DnsClient
    {
        #region Private Members
        private ushort _id;

        private IDnsTransport GetTransport(bool tcp)
        {
            if (tcp)
                return new DnsTransportTcp(ServerAddress, Timeout);
            return new DnsTransportUdp(ServerAddress, Timeout);
        }

        private DnsPacket Query(bool tcp, string qname, DnsQueryType qtype, DnsQueryClass qclass)
        {
            using (var transport = GetTransport(tcp))
            {
                DnsPacket query = new DnsPacket
                {
                    Id = ++_id,
                    RecursionDesired = true,
                    Opcode = DnsQueryOpcode.QUERY,
                    Questions = new[] { new DnsQuestion() { QClass = qclass, QName = qname, QType = qtype } }
                };

                byte[] data = query.ToArray();
                transport.Send(data);
                data = transport.Receive();
                var result = DnsPacket.FromArray(data);
                if (result.Id != query.Id)
                    throw new ProtocolViolationException("Mismatched IDs for DNS query.");
                if (result.ResponseCode != DnsResponseCode.NoError)
                    throw new ProtocolViolationException($"Error in query response {result.ResponseCode}.");
                return result;
            }
        }

        private DnsPacket Query(string qname, DnsQueryType qtype, DnsQueryClass qclass = DnsQueryClass.IN)
        {
            if (!ForceTcp)
            {
                var result = Query(false, qname, qtype, qclass);
                if (!result.Truncation)
                    return result;
            }

            return Query(true, qname, qtype, qclass);
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Set to force TCP for the transport. If false then the class will try UDP first, and fallback
        /// to TCP if the reply is truncated.
        /// </summary>
        public bool ForceTcp { get; set; }

        /// <summary>
        /// The DNS server address.
        /// </summary>
        public IPAddress ServerAddress { get; }

        /// <summary>
        /// The timeout in milli-seconds to wait for a query. Values &lt;= 0 result in an infinite timeout.
        /// </summary>
        public int Timeout { get; set; }
        #endregion

        #region Constructors
        /// <summary>
        /// Specify the DNS servers
        /// </summary>
        /// <param name="server_address">The address of the DNS server.</param>
        public DnsClient(IPAddress server_address)
        {
            ServerAddress = server_address ?? throw new ArgumentNullException(nameof(server_address));
            Timeout = 5000;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Query the IP addresses for a host.
        /// </summary>
        /// <param name="name">The host name.</param>
        /// <returns>The list of host addresses.</returns>
        public IReadOnlyCollection<DnsAddressRecord> QueryIPv4Address(string name)
        {
            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            var result = Query(name, DnsQueryType.A);
            return result.Answers.OfType<DnsResourceRecordA>().Select(
                a => new DnsAddressRecord(a.Name, a.Address, a.TimeToLive)).ToList().AsReadOnly();
        }

        /// <summary>
        /// Query the IP addresses for a host.
        /// </summary>
        /// <param name="name">The host name.</param>
        /// <returns>The list of host addresses.</returns>
        public IReadOnlyCollection<DnsAddressRecord> QueryIPv6Address(string name)
        {
            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            var result = Query(name, DnsQueryType.AAAA);
            return result.Answers.OfType<DnsResourceRecordAAAA>().Select(
                a => new DnsAddressRecord(a.Name, a.Address, a.TimeToLive)).ToList().AsReadOnly();
        }

        /// <summary>
        /// Query the SRV records for a hsot.
        /// </summary>
        /// <param name="name">The host name for example _kerberos._tcp.dc._msdcs.domain.local.</param>
        /// <returns>The list of service records.</returns>
        public IReadOnlyCollection<DnsServiceRecord> QueryServices(string name)
        {
            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            var result = Query(name, DnsQueryType.SRV);
            return result.Answers.OfType<DnsResourceRecordSRV>().Select(
                a => new DnsServiceRecord(a)).ToList().AsReadOnly();
        }
        #endregion
    }
}
