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

using NtApiDotNet.Win32;
using System.Collections.Generic;
using System.Linq;

namespace NtObjectManager.Cmdlets.Rpc
{
    /// <summary>
    /// <para type="description">Result of a RPC server comparison.</para>
    /// </summary>
    public class CompareRpcServerResult
    {
        /// <summary>
        /// Collection of added servers in comparison.
        /// </summary>
        public ICollection<RpcServer> AddedServer { get; }
        /// <summary>
        /// Collection of modified servers in comparison.
        /// </summary>
        public ICollection<ModifiedRpcServerResult> ModifiedServer { get; }
        /// <summary>
        /// Count of added servers.
        /// </summary>
        public int AddedServerCount => AddedServer.Count;
        /// <summary>
        /// Count of modified servers.
        /// </summary>
        public int ModifiedServerCount => ModifiedServer.Count;

        internal CompareRpcServerResult(IEnumerable<RpcServer> added_server, IEnumerable<ModifiedRpcServerResult> modified_server)
        {
            AddedServer = added_server.ToList().AsReadOnly();
            ModifiedServer = modified_server.ToList().AsReadOnly();
        }
    }
}
