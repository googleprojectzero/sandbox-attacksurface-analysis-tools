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

using NtCoreLib.Ndr.Dce;
using NtCoreLib.Ndr.Rpc;
using NtCoreLib.Win32.Rpc.Server;
using System;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Rpc;

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
        if (server.Server.DceSyntaxInfo == null)
            return false;

        foreach (var base_type in server.Server.DceSyntaxInfo.Types)
        {
            if (base_type is NdrSystemHandleTypeReference system_handle)
            {
                if (!type.HasValue || system_handle.Resource == type.Value)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool MatchNonStrictContextHandle(RpcServer server)
    {
        if (server.Server.DceSyntaxInfo == null)
            return false;

        foreach (var base_type in server.Server.DceSyntaxInfo.Types)
        {
            if (base_type is NdrContextHandleTypeReference context_handle)
            {
                if (context_handle.IsStrict)
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static bool MatchInterfaceId(RpcServer server, Guid interface_id, RpcVersion? interface_version)
    {
        if (server.InterfaceId != interface_id)
        {
            return false;
        }

        if (!interface_version.HasValue)
        {
            return true;
        }

        return server.InterfaceVersion == interface_version;
    }

    private bool MatchServer(RpcServer server)
    {
        return ParameterSetName switch
        {
            "MatchName" => MatchName(server, Name),
            "MatchSystemHandle" => MatchSystemHandle(server, SystemHandleType),
            "MatchInterfaceId" => MatchInterfaceId(server, InterfaceId, InterfaceVersion),
            "MatchNonStrictContextHandle" => MatchNonStrictContextHandle(server),
            _ => false,
        };
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
    public RpcVersion? InterfaceVersion { get; set; }

    /// <summary>
    /// <para type="description">Specify we want to find interfaces with non-strict context handles.</para>
    /// </summary>
    [Parameter(ParameterSetName = "MatchNonStrictContextHandle")]
    public SwitchParameter NonStrictContextHandle { get; set; }

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
