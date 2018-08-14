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
        public IEnumerable<RpcEndpoint> Endpoints { get; }
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

        private RpcAlpcServer(NtHandle handle, List<RpcEndpoint> endpoints)
        {
            ProcessId = handle.ProcessId;
            using (var proc = NtProcess.Open(handle.ProcessId, ProcessAccessRights.QueryLimitedInformation, false))
            {
                if (proc.IsSuccess)
                {
                    ProcessName = proc.Result.Name;
                }
                else
                {
                    ProcessName = string.Empty;
                }
            }
            Name = handle.Name;
            SecurityDescriptor = handle.SecurityDescriptor;
            Endpoints = endpoints.AsReadOnly();
            EndpointCount = endpoints.Count;
        }

        /// <summary>
        /// Get RPC ALPC servers for a specific process.
        /// </summary>
        /// <param name="process_id">The ID of the process.</param>
        /// <returns>The list of RPC ALPC servers.</returns>
        public static IEnumerable<RpcAlpcServer> GetAlpcServers(int process_id)
        {
            return GetAlpcServersInternal(NtSystemInfo.GetHandles(process_id, true)).ToCached();
        }

        /// <summary>
        /// Get a list of all RPC ALPC servers.
        /// </summary>
        /// <remarks>This works by discovering any server ALPC ports owned by the process and querying for interfaces.</remarks>
        /// <returns>The list of RPC ALPC servers.</returns>
        public static IEnumerable<RpcAlpcServer> GetAlpcServers()
        {
            return GetAlpcServersInternal(NtSystemInfo.GetHandles()).ToCached();
        }

        private static IEnumerable<RpcAlpcServer> GetAlpcServersInternal(IEnumerable<NtHandle> handles)
        {
            NtType alpc_type = NtType.GetTypeByType<NtAlpc>();
            
            foreach (var handle in handles.Where(h => h.NtType == alpc_type
                && h.Name.StartsWith(@"\RPC Control\", StringComparison.OrdinalIgnoreCase)))
            {
                List<RpcEndpoint> endpoints = new List<RpcEndpoint>();
                try
                {
                    endpoints.AddRange(RpcEndpointMapper.QueryEndpointsForAlpcPort(handle.Name));
                }
                catch (SafeWin32Exception)
                {
                }

                if (endpoints.Count > 0)
                {
                    yield return new RpcAlpcServer(handle, endpoints);
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
