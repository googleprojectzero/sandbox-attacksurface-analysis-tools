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

using NtApiDotNet.Win32.Rpc.Transport;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Class representing an RPC ALPC server.
    /// </summary>
    public class RpcAlpcServer
    {
        /// <summary>
        /// The PID of the process which contains the ALPC server.
        /// </summary>
        public int ProcessId { get; }
        /// <summary>
        /// The name of the process which contains the ALPC server.
        /// </summary>
        public string ProcessName { get; }
        /// <summary>
        /// List of known endpoints potentially accessible via this RPC server.
        /// </summary>
        public IReadOnlyCollection<RpcEndpoint> Endpoints { get; }
        /// <summary>
        /// The number of endpoints.
        /// </summary>
        public int EndpointCount { get; }
        /// <summary>
        /// The name of the ALPC server.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The security descriptor of the ALPC server.
        /// </summary>
        public SecurityDescriptor SecurityDescriptor { get; }

        private RpcAlpcServer(int process_id, string name, SecurityDescriptor sd, string process_name, IEnumerable<RpcEndpoint> endpoints)
        {
            ProcessId = process_id;
            ProcessName = process_name;
            Name = name;
            SecurityDescriptor = sd;
            Endpoints = new List<RpcEndpoint>(endpoints).AsReadOnly();
            EndpointCount = Endpoints.Count;
        }

        private RpcAlpcServer(NtHandle handle, string process_name, IEnumerable<RpcEndpoint> endpoints) 
            : this(handle.ProcessId, handle.Name, handle.SecurityDescriptor, process_name, endpoints)
        {
        }

        /// <summary>
        /// Get RPC ALPC servers for a specific process.
        /// </summary>
        /// <param name="process_id">The ID of the process.</param>
        /// <returns>The list of RPC ALPC servers.</returns>
        /// <remarks>If the process is suspended or frozen this call can hang.</remarks>
        public static IEnumerable<RpcAlpcServer> GetAlpcServers(int process_id)
        {
            using (var proc = NtProcess.Open(process_id, ProcessAccessRights.QueryInformation | ProcessAccessRights.DupHandle))
            {
                List<RpcAlpcServer> ret = new List<RpcAlpcServer>();
                GetAlpcServersInternal(proc.Duplicate(), NtObjectUtils.IsWindows7OrLess ? NtSystemInfo.GetHandles(process_id, true) :
                    proc.GetHandles(true), ret);
                if (ret.Count == 0)
                    Win32Error.RPC_S_SERVER_UNAVAILABLE.ToNtException();
                return ret.AsReadOnly();
            }
        }

        /// <summary>
        /// Get a list of all RPC ALPC servers.
        /// </summary>
        /// <remarks>This works by discovering any server ALPC ports owned by the process and querying for interfaces.
        /// This will ignore any frozen processes (primarily UWP) as they can't respond to the endpoint enumeration.</remarks>
        /// <returns>The list of RPC ALPC servers.</returns>
        public static IEnumerable<RpcAlpcServer> GetAlpcServers()
        {
            List<RpcAlpcServer> ret = new List<RpcAlpcServer>();

            foreach (var group in NtSystemInfo.GetHandles().GroupBy(h => h.ProcessId))
            {
                using (var proc = NtProcess.Open(group.Key,
                    ProcessAccessRights.QueryLimitedInformation | ProcessAccessRights.DupHandle, false))
                {
                    if (!proc.IsSuccess)
                        continue;
                    if (proc.Result.Frozen)
                        continue;
                    GetAlpcServersInternal(proc.Result, group, ret);
                }
            }
            return ret.AsReadOnly();
        }

        /// <summary>
        /// Get the RPC ALPC server for an ALPC port object path.
        /// </summary>
        /// <param name="path">The object manager path to the ALPC port.</param>
        /// <returns>The ALPC RPC server.</returns>
        /// <remarks>Needs an API which is only available from Windows 10 19H1.</remarks>
        [SupportedVersion(SupportedVersion.Windows10_19H1)]
        public static RpcAlpcServer GetAlpcServer(string path)
        {
            using (var transport = new RpcAlpcClientTransport(path, null))
            {
                var server = transport.ServerProcess;
                return new RpcAlpcServer(server.ProcessId, path, null, server.Name,
                    RpcEndpointMapper.QueryEndpointsForAlpcPort(path));
            }
        }

        private static void GetAlpcServersInternal(NtProcess process, IEnumerable<NtHandle> handles, List<RpcAlpcServer> servers)
        {
            NtType alpc_type = NtType.GetTypeByType<NtAlpc>();
            string process_name = process.Name;
            foreach (var handle in handles.Where(h => h.NtType == alpc_type
                && h.Name.IndexOf(@"\RPC Control\", StringComparison.OrdinalIgnoreCase) >= 0))
            {
                var eps = RpcEndpointMapper.QueryEndpointsForAlpcPort(handle.Name, false);
                if (eps.IsSuccess)
                {
                    servers.Add(new RpcAlpcServer(handle, process_name, eps.Result));
                }
            }
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>Formatted string.</returns>
        public override string ToString()
        {
            return $"{ProcessName} - Endpoints: {EndpointCount}"; 
        }
    }
}
