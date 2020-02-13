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

namespace NtObjectManager
{
    /// <summary>
    /// Result of a modified RPC server.
    /// </summary>
    public class ModifiedRpcServerResult
    {
        /// <summary>
        /// The server which was modified.
        /// </summary>
        public RpcServer Server { get; }
        /// <summary>
        /// The original compare server.
        /// </summary>
        public RpcServer CompareServer { get; }
        /// <summary>
        /// A collection of added procedures.
        /// </summary>
        public ICollection<NdrProcedureDefinition> AddedProcedure { get; }
        /// <summary>
        /// The count of added procedures.
        /// </summary>
        public int AddedProcedureCount => AddedProcedure.Count;

        internal ModifiedRpcServerResult(RpcServer server, RpcServer compare_server, 
            IEnumerable<NdrProcedureDefinition> added_procedure)
        {
            Server = server;
            CompareServer = compare_server;
            AddedProcedure = added_procedure.ToList().AsReadOnly();
        }
    }

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

    /// <summary>
    /// <para type="synopsis">Compare two lists of RPC server objects for differences.</para>
    /// <para type="description">This cmdlet compares two lists of RPC server objects for differences.
    /// It highlights servers which didn't exist before, servers removed from the list as well as 
    /// servers which have been modified in some way.</para>
    /// </summary>
    /// <example>
    ///   <code>Compare-RpcServer -Server $old -CompareServer $new</code>
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

    /// <summary>
    /// <para type="synopsis">Selects RPC server objects based on some specific criteria.</para>
    /// <para type="description">This cmdlet selects out RPC servers from a list based on a few specific criteria such as partial name match or specific parameter types.</para>
    /// </summary>
    /// <example>
    ///   <code>$rpc | Select-RpcServer -Name "Start"</code>
    ///   <para>Select all servers which have a procedure containing the text Start.</para>
    /// </example>
    /// <example>
    ///   <code>$rpc | Select-RpcServer -SystemHandle</code>
    ///   <para>Select all servers which have a procedure which take a system handle parameter.</para>
    /// </example>
    /// <example>
    ///   <code>$rpc | Select-RpcServer -SystemHandle -SystemHandleType File</code>
    ///   <para>Select all servers which have a procedure which take a system handle parameter of type File.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Select, "RpcServer")]
    [OutputType(typeof(RpcServer))]
    public class SelectRpcServerCmdlet : PSCmdlet
    {
        private static bool MatchName(RpcServer server, string name)
        {
            name = name.ToLower();
            foreach (var f in server.Procedures)
            {
                if (f.Name.ToLower().Contains(name))
                {
                    return true;
                }
            }
            return false;
        }

        private static bool MatchSystemHandle(RpcServer server, NdrSystemHandleResource? type)
        {
            foreach (var f in server.Procedures)
            {
                foreach (var p in f.Params)
                {
                    if (p.Type is NdrSystemHandleTypeReference system_handle)
                    {
                        if (!type.HasValue || system_handle.Resource == type.Value)
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private static bool MatchInterfaceId(RpcServer server, Guid interface_id, Version interface_version)
        {
            if (server.InterfaceId != interface_id)
            {
                return false;
            }

            if (interface_version == null)
            {
                return true;
            }

            return server.InterfaceVersion == interface_version;
        }

        private bool MatchServer(RpcServer server)
        {
            switch (ParameterSetName)
            {
                case "MatchName":
                    return MatchName(server, Name);
                case "MatchSystemHandle":
                    return MatchSystemHandle(server, SystemHandleType);
                case "MatchInterfaceId":
                    return MatchInterfaceId(server, InterfaceId, InterfaceVersion);
            }
            return false;
        }

        /// <summary>
        /// <para type="description">Specify a list of RPC servers for selecting.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ValueFromPipeline = true)]
        public RpcServer[] Server { get; set; }

        /// <summary>
        /// <para type="description">Specify name to partially match against a function name.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "MatchName")]
        public string Name { get; set; }

        /// <summary>
        /// <para type="description">Specify one function must take a system handle parameter.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "MatchSystemHandle")]
        public SwitchParameter SystemHandle { get; set; }

        /// <summary>
        /// <para type="description">Specify an optional type of system handle to match.</para>
        /// </summary>
        [Parameter(ParameterSetName = "MatchSystemHandle")]
        public NdrSystemHandleResource? SystemHandleType { get; set; }

        /// <summary>
        /// <para type="description">Specify the Interface ID to match.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "MatchInterfaceId")]
        [Alias("UUID")]
        public Guid InterfaceId { get; set; }

        /// <summary>
        /// <para type="description">Specify an optional interface version to match.</para>
        /// </summary>
        [Parameter(ParameterSetName = "MatchInterfaceId")]
        public Version InterfaceVersion { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            foreach (var s in Server.Where(MatchServer))
            {
                WriteObject(s);
            }
        }
    }
}
