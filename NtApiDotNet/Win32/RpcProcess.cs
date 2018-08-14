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
    /// Class representing an RPC process.
    /// </summary>
    public class RpcProcess
    {
        /// <summary>
        /// The PID of the process.
        /// </summary>
        public int ProcessId { get; }
        /// <summary>
        /// The name of the process.
        /// </summary>
        public string ProcessName { get; }
        /// <summary>
        /// List of known endpoints.
        /// </summary>
        public IEnumerable<RpcEndpoint> Endpoints { get; }
        /// <summary>
        /// The number of endpoints.
        /// </summary>
        public int EndpointCount { get; }

        private RpcProcess(int process_id, List<RpcEndpoint> endpoints)
        {
            ProcessId = process_id;
            using (var proc = NtProcess.Open(process_id, ProcessAccessRights.QueryLimitedInformation, false))
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
            Endpoints = endpoints.AsReadOnly();
            EndpointCount = endpoints.Count;
        }

        /// <summary>
        /// Get RPC details for a single process.
        /// </summary>
        /// <param name="process_id">The ID of the process.</param>
        /// <returns>The parsed process. The process might not have any endpoints available.</returns>
        public static RpcProcess GetProcess(int process_id)
        {
            return GetProcessInternal(process_id, NtSystemInfo.GetHandles(process_id, true));
        }

        private static RpcProcess GetProcessInternal(int process_id, IEnumerable<NtHandle> handles)
        {
            NtType alpc_type = NtType.GetTypeByType<NtAlpc>();
            List<RpcEndpoint> endpoints = new List<RpcEndpoint>();
            foreach (var handle in handles.Where(h => h.NtType == alpc_type
                && h.Name.StartsWith(@"\RPC Control\", StringComparison.OrdinalIgnoreCase)))
            {
                try
                {
                    endpoints.AddRange(RpcEndpointMapper.QueryEndpointsForAlpcPort(handle.Name));
                }
                catch (SafeWin32Exception)
                {
                }
            }
            return new RpcProcess(process_id, endpoints);
        }

        private static IEnumerable<RpcProcess> GetProcessesInternal()
        {
            foreach (var group in NtSystemInfo.GetHandles().GroupBy(h => h.ProcessId))
            {
                var process = GetProcessInternal(group.Key, group);
                if (process.EndpointCount > 0)
                {
                    yield return process;
                }
            }
        }

        /// <summary>
        /// Get a list of RPC processes.
        /// </summary>
        /// <remarks>This works by discovering any server ALPC ports owned by the process and querying for interfaces.</remarks>
        /// <returns>The list of RPC processes.</returns>
        public static IEnumerable<RpcProcess> GetProcesses()
        {
            return GetProcessesInternal().ToCached();
        }
    }
}
