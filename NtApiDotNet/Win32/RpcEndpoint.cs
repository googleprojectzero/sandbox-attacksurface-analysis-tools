//  Copyright 2018 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32.Rpc;
using System;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Class to represent an RPC endpoint.
    /// </summary>
    public class RpcEndpoint
    {
        /// <summary>
        /// The interface ID of the endpoint.
        /// </summary>
        public Guid InterfaceId { get; }
        /// <summary>
        /// The interface version.
        /// </summary>
        public Version InterfaceVersion { get; }
        /// <summary>
        /// The object UUID.
        /// </summary>
        public Guid ObjectUuid { get; }
        /// <summary>
        /// Optional annotation.
        /// </summary>
        public string Annotation { get; }
        /// <summary>
        /// RPC binding string.
        /// </summary>
        public string BindingString { get; }
        /// <summary>
        /// Endpoint protocol sequence.
        /// </summary>
        public string ProtocolSequence { get; }
        /// <summary>
        /// Endpoint network address.
        /// </summary>
        public string NetworkAddress { get; }
        /// <summary>
        /// Endpoint name.
        /// </summary>
        public string Endpoint { get; }
        /// <summary>
        /// Endpoint network options.
        /// </summary>
        public string NetworkOptions { get; }
        /// <summary>
        /// The endpoint path.
        /// </summary>
        public string EndpointPath { get; }
        /// <summary>
        /// Indicates this endpoint is registered with the endpoint mapper.
        /// </summary>
        public bool Registered { get; }

        private RpcEndpoint(Guid interface_id, Version interface_version, string annotation, string binding, bool registered)
        {
            InterfaceId = interface_id;
            InterfaceVersion = interface_version;
            CrackedBindingString cracked = new CrackedBindingString(binding);
            Guid.TryParse(cracked.ObjUuid, out Guid guid);
            ObjectUuid = guid;

            Annotation = annotation ?? string.Empty;
            BindingString = binding.ToString();
            ProtocolSequence = cracked.Protseq;
            NetworkAddress = cracked.NetworkAddr;
            Endpoint = cracked.Endpoint;
            NetworkOptions = cracked.NetworkOptions;
            if (ProtocolSequence.Equals("ncalrpc", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(Endpoint))
            {
                if (Endpoint.Contains(@"\"))
                {
                    EndpointPath = Endpoint;
                }
                else
                {
                    EndpointPath = $@"\RPC Control\{Endpoint}";
                }
            }
            else if (ProtocolSequence.Equals("ncacn_np", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(Endpoint))
            {
                EndpointPath = $@"\??{Endpoint}";
            }
            else
            {
                EndpointPath = string.Empty;
            }
            Registered = registered;
        }

        internal RpcEndpoint(Guid interface_id, Version interface_version, string string_binding, bool registered)
            : this(interface_id, interface_version, null, string_binding, registered)
        {
        }

        internal RpcEndpoint(RPC_IF_ID if_id, UUID uuid, SafeRpcStringHandle annotation, SafeRpcBindingHandle binding, bool registered)
            : this(if_id.Uuid, new Version(if_id.VersMajor, if_id.VersMinor), annotation?.ToString(), binding.ToString(), registered)
        {
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>String form of the object.</returns>
        public override string ToString()
        {
            return $"[{InterfaceId}, {InterfaceVersion}] {BindingString}";
        }
    }
}
