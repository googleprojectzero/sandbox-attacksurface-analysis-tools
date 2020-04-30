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
using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Rpc
{
    /// <summary>
    /// <para type="synopsis">Compare two lists of RPC server objects for differences.</para>
    /// <para type="description">This cmdlet compares two lists of RPC server objects for differences.
    /// It highlights servers which didn't exist before as well as
    /// servers which have been modified in some way.</para>
    /// </summary>
    /// <example>
    ///   <code>Compare-RpcServer -Server $new -CompareServer $old</code>
    ///   <para>Compare a list of old servers in $old with ones in $new.</para>
    /// </example>
    [Cmdlet(VerbsData.Compare, "RpcServer")]
    [OutputType(typeof(CompareRpcServerResult))]
    public class CompareRpcServerCmdlet : PSCmdlet
    {
        private static Dictionary<Tuple<Guid, Version>, RpcServer> CreateDictionary(IEnumerable<RpcServer> servers)
        {
            Dictionary<Tuple<Guid, Version>, RpcServer> ret = new Dictionary<Tuple<Guid, Version>, RpcServer>();
            foreach (var server in servers)
            {
                var key = Tuple.Create(server.InterfaceId, server.InterfaceVersion);
                ret[key] = server;
            }
            return ret;
        }

        private static ModifiedRpcServerResult CompareModifiedServer(RpcServer server, RpcServer compare_server)
        {
            if (server.ProcedureCount > compare_server.ProcedureCount)
            {
                return new ModifiedRpcServerResult(server, compare_server, server.Procedures.Skip(compare_server.ProcedureCount));
            }

            return new ModifiedRpcServerResult(server, compare_server, new NdrProcedureDefinition[0]);
        }

        private CompareRpcServerResult CompareServers()
        {
            var servers = CreateDictionary(Server);
            var compare_servers = CreateDictionary(CompareServer);

            if (compare_servers.Count == 0)
            {
                return new CompareRpcServerResult(servers.Values, new ModifiedRpcServerResult[0]);
            }

            if (servers.Count == 0)
            {
                return new CompareRpcServerResult(new RpcServer[0], new ModifiedRpcServerResult[0]);
            }

            var added_servers = servers.Where(p => !compare_servers.ContainsKey(p.Key)).Select(p => p.Value);
            var modified_server = servers.Where(p => compare_servers.ContainsKey(p.Key))
                            .Select(p => CompareModifiedServer(p.Value, compare_servers[p.Key])).Where(s => s.AddedProcedureCount > 0);
            return new CompareRpcServerResult(added_servers, modified_server);
        }

        /// <summary>
        /// <para type="description">Specify a list of RPC servers for comparison.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public RpcServer[] Server { get; set; }

        /// <summary>
        /// <para type="description">Specify a list of RPC servers to compare against Server.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true)]
        public RpcServer[] CompareServer { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            WriteObject(CompareServers());
        }
    }
}
