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

using NtApiDotNet.Ndr;
using NtApiDotNet.Win32.Rpc.EndpointMapper;
using System;

namespace NtApiDotNet.Win32.Rpc
{
    /// <summary>
    /// Class to present an RPC interface ID.
    /// </summary>
    public sealed class RpcInterfaceId
    {
        /// <summary>
        /// The interface UUID.
        /// </summary>
        public Guid Uuid { get; }

        /// <summary>
        /// The interface version.
        /// </summary>
        public Version Version { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="uuid">The interface UUID.</param>
        public RpcInterfaceId(Guid uuid) : this(uuid, new Version())
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="uuid">The interface UUID.</param>
        /// <param name="version">The interface version.</param>
        public RpcInterfaceId(Guid uuid, Version version)
        {
            Uuid = uuid;
            Version = version ?? throw new ArgumentNullException(nameof(version));
        }

        /// <summary>
        /// The interface ID for the DCE NDR transfer syntax.
        /// </summary>
        public static RpcInterfaceId DCETransferSyntax => new RpcInterfaceId(NdrNativeUtils.DCE_TransferSyntax, new Version(2, 0));

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The interface ID as a string.</returns>
        public override string ToString()
        {
            return $"{Uuid} {Version}";
        }

        internal RPC_IF_ID_EPT ToRpcIfId()
        {
            return new RPC_IF_ID_EPT()
            {
                Uuid = Uuid,
                VersMajor = (short)Version.Major,
                VersMinor = (short)Version.Minor
            };
        }
    }
}
