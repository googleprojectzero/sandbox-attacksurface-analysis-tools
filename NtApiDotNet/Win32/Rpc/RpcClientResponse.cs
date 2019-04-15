//  Copyright 2019 Google Inc. All Rights Reserved.
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
using NtApiDotNet.Ndr.Marshal;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Rpc
{
    /// <summary>
    /// Response data from an RPC client call.
    /// </summary>
    public sealed class RpcClientResponse
    {
        /// <summary>
        /// The marshaled NDR data from the response.
        /// </summary>
        public byte[] NdrBuffer { get; }
        /// <summary>
        /// Any object handles returned in the response. (only for ALPC).
        /// </summary>
        public IEnumerable<NtObject> Handles { get; }
        /// <summary>
        /// Indicates the NDR data representation for the response.
        /// </summary>
        public NdrDataRepresentation DataRepresentation { get; }

        internal RpcClientResponse(byte[] ndr_buffer, IEnumerable<NtObject> handles)
        {
            NdrBuffer = ndr_buffer;
            Handles = new List<NtObject>(handles.Select(o => o.DuplicateObject()));
            DataRepresentation = new NdrDataRepresentation();
        }
    }
}
