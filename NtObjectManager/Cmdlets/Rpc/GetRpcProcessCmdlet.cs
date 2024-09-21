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

using NtCoreLib;
using NtCoreLib.Ndr.Rpc;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Rpc.EndpointMapper;
using NtCoreLib.Win32.Rpc.Server;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Rpc;

/// <summary>
/// <para type="synopsis">Gets RPC processes with their endpoints and server objects.</para>
/// <para type="description">This cmdlet sorts through all information to find processes hosting RPC services and extracts out the endpoints.</para>
/// </summary>
/// <example>
///   <code>Get-RpcProcess</code>
///   <para>Get all RPC processes.</para>
/// </example>
/// <example>
///   <code>Get-RpcProcess -ProcessId 1234</code>
///   <para>Get the RPC process for a specific PID.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "RpcProcess", DefaultParameterSetName = "All")]
[OutputType(typeof(RpcProcess))]
public sealed class GetRpcProcessCmdlet : PSCmdlet
{
    #region Private Members
    private sealed class TempRpcProcess
    {
        private static Dictionary<string, List<RpcServer>> _cached_servers = new(StringComparer.InvariantCultureIgnoreCase);

        public int ProcessId { get; }
        public string ImagePath { get; }
        public List<RpcEndpoint> Endpoints { get; }
        public Dictionary<RpcSyntaxIdentifier, RpcServer> Servers { get; }
        public Dictionary<RpcStringBinding, SecurityDescriptor> BindingSecurity { get; }

        private List<RpcServer> ParseModule(ProcessModule module, string dbghelp_path, 
            string symbol_path, RpcServerParserFlags flags)
        {
            try
            {
                return RpcServer.ParsePeFile(module.FileName, dbghelp_path, 
                    symbol_path, flags).ToList();
            }
            catch
            {
            }
            return new();
        }

        public void ProcessServers(Func<string, bool> write_progress, string dbghelp_path,
            string symbol_path, RpcServerParserFlags flags)
        {
            HashSet<RpcSyntaxIdentifier> interface_ids = new(Endpoints.Select(ep => ep.InterfaceId));
            try
            {
                using Process process = Process.GetProcessById(ProcessId);
                foreach (ProcessModule module in process.Modules)
                {
                    if (!_cached_servers.ContainsKey(module.FileName))
                    {
                        if (!write_progress($"Parsing {module.FileName}"))
                            return;
                        _cached_servers[module.FileName] = ParseModule(module, dbghelp_path, symbol_path, flags);
                    }

                    foreach (var server in _cached_servers[module.FileName])
                    {
                        var interface_id = new RpcSyntaxIdentifier(server.InterfaceId, server.InterfaceVersion);
                        if (interface_ids.Contains(interface_id))
                        {
                            Servers[interface_id] = server;
                        }
                    }
                }
            }
            catch
            {
            }
        }

        public TempRpcProcess(int process_id, string image_path)
        {
            ProcessId = process_id;
            ImagePath = image_path;
            Endpoints = new();
            Servers = new();
            BindingSecurity = new();
        }
    }

    private bool WriteProgress(string description)
    {
        if (Stopping)
            return false;
        WriteProgress(new ProgressRecord(0, "Getting RPC Processes", description));
        return true;
    }

    private void EnableDebugPrivilege()
    {
        if (!NtToken.EnableDebugPrivilege())
        {
            WriteWarning("Couldn't enable SeDebugPrivilege. Results maybe inaccurate.");
        }
    }

    private void AddEndpoint(Dictionary<int, TempRpcProcess> processes, RpcEndpoint endpoint)
    {
        try
        {
            var server_process = endpoint.GetServerProcess();
            if (!processes.ContainsKey(server_process.ProcessId))
            {
                processes.Add(server_process.ProcessId, 
                    new TempRpcProcess(server_process.ProcessId, server_process.ImagePath));
            }
            processes[server_process.ProcessId].Endpoints.Add(endpoint);
        }
        catch(NtException)
        {
        }
    }

    private void GetAllProcesses()
    {
        Dictionary<int, TempRpcProcess> processes = new();
        if (!WriteProgress("Processing Endpoint Mapper."))
            return;
        var eps = RpcEndpointMapper.QueryAllEndpoints();
        foreach (var ep in eps)
        {
            AddEndpoint(processes, ep);
        }

        if (!WriteProgress("Processing ALPC servers."))
            return;
        foreach (var alpc in RpcAlpcServer.GetAlpcServers(IgnoreComServers))
        {
            if (!processes.ContainsKey(alpc.ProcessId))
            {
                processes[alpc.ProcessId] = new TempRpcProcess(alpc.ProcessId, alpc.ProcessName);
            }
            processes[alpc.ProcessId].Endpoints.AddRange(alpc.Endpoints);
            if (alpc.SecurityDescriptor != null)
            {
                processes[alpc.ProcessId].BindingSecurity.Add(alpc.Endpoints.First().Binding, 
                    alpc.SecurityDescriptor);
            }
        }

        if (!WriteProgress("Processing exposed interfaces."))
            return;

        foreach (TempRpcProcess process in processes.Values)
        {
            if (Stopping)
                return;
            foreach (var endpoint in process.Endpoints)
            {
                var result = RpcEndpointMapper.QueryEndpointsForBinding(endpoint.Binding, false);
                if (result.IsSuccess)
                {
                    process.Endpoints.AddRange(result.Result);
                    break;
                }
            }
        }

        foreach (TempRpcProcess process in processes.Values)
        {
            if (!IgnoreServers)
            {
                process.ProcessServers(WriteProgress, DbgHelpPath,
                    SymbolPath, IgnoreSymbols ? RpcServerParserFlags.IgnoreSymbols : 0);
            }
            if (Stopping)
                return;
            WriteObject(new RpcProcess(process.ProcessId,
                process.ImagePath, process.Servers.Values, process.Endpoints,
                process.BindingSecurity));
        }
    }

    private void GetProcess()
    {
        using var process = NtProcess.Open(ProcessId, ProcessAccessRights.AllAccess);
        TempRpcProcess temp_process = new(ProcessId, process.Win32ImagePath);
        if (!WriteProgress("Processing Endpoint Mapper."))
            return;
        var eps = RpcEndpointMapper.QueryAllEndpoints();
        foreach (var ep in eps)
        {
            try
            {
                var server = ep.GetServerProcess();
                if (server.ProcessId == ProcessId)
                {
                    temp_process.Endpoints.Add(ep);
                }
            }
            catch
            {
            }
        }

        if (!WriteProgress("Processing ALPC servers."))
            return;
        foreach (var alpc in RpcAlpcServer.GetAlpcServers(ProcessId, IgnoreComServers))
        {
            temp_process.Endpoints.AddRange(alpc.Endpoints);
            if (alpc.SecurityDescriptor != null)
            {
                temp_process.BindingSecurity.Add(alpc.Endpoints.First().Binding, alpc.SecurityDescriptor);
            }
        }

        if (!WriteProgress("Processing exposed interfaces."))
            return;

        if (Stopping)
            return;
        foreach (var endpoint in temp_process.Endpoints)
        {
            var result = RpcEndpointMapper.QueryEndpointsForBinding(endpoint.Binding, false);
            if (result.IsSuccess)
            {
                temp_process.Endpoints.AddRange(result.Result);
                break;
            }
        }

        if (!IgnoreServers)
        {
            temp_process.ProcessServers(WriteProgress, DbgHelpPath,
                SymbolPath, IgnoreSymbols ? RpcServerParserFlags.IgnoreSymbols : 0);
        }
        if (Stopping)
            return;
        WriteObject(new RpcProcess(temp_process.ProcessId,
            temp_process.ImagePath, temp_process.Servers.Values, temp_process.Endpoints,
            temp_process.BindingSecurity));
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// <para type="description">Specify to extract a single process.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromProcessId")]
    [Alias("pid")]
    public int ProcessId { get; set; }

    /// <summary>
    /// <para type="description">Specify the path to debug help.</para>
    /// </summary>
    [Parameter]
    public string DbgHelpPath { get; set; }

    /// <summary>
    /// <para type="description">Specify the symbol path.</para>
    /// </summary>
    [Parameter]
    public string SymbolPath { get; set; }

    /// <summary>
    /// <para type="description">Specify to ignore symbols.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter IgnoreSymbols { get; set; }

    /// <summary>
    /// <para type="description">Specify to not parse the servers.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter IgnoreServers { get; set; }

    /// <summary>
    /// <para type="description">Specify to ignore COM servers where possible.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter IgnoreComServers { get; set; }
    #endregion

    /// <inheritdoc/>
    protected override void ProcessRecord()
    {
        EnableDebugPrivilege();
        switch (ParameterSetName)
        {
            case "All":
                GetAllProcesses();
                break;
            case "FromProcessId":
                GetProcess();
                break;
        }
    }
}