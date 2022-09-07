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

namespace NtApiDotNet.Net.Dns
{
    /// <summary>
    /// A single DNS service record.
    /// </summary>
    public sealed class DnsServiceRecord
    {
        /// <summary>
        /// The service priority.
        /// </summary>
        public int Priority { get; }

        /// <summary>
        /// The service weight.
        /// </summary>
        public int Weight { get; }

        /// <summary>
        /// The service port.
        /// </summary>
        public int Port { get; }

        /// <summary>
        /// The service host name.
        /// </summary>
        public string Target { get; }

        internal DnsServiceRecord(DnsResourceRecordSRV srv)
        {
            Priority = srv.Priority;
            Weight = srv.Weight;
            Port = srv.Port;
            Target = srv.Target;
        }
    }
}
