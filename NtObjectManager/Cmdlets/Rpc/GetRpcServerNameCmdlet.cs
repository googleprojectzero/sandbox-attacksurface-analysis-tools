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

using NtCoreLib.Win32.Rpc.Server;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Rpc;

/// <summary>
/// <para type="synopsis">Get the names from a RPC server as XML.</para>
/// <para type="description">This cmdlet extracts the names from a RPC server instance and
/// generates an XML file for easy editing. You can then update the names with Set-RpcServerName.</para>
/// </summary>
/// <example>
///   <code>Get-RpcServerName -Server $server</code>
///   <para>Get names for an RPC server object.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "RpcServerName")]
[OutputType(typeof(string))]
public sealed class GetRpcServerNameCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the server object to get the names from.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public RpcServer Server { get; set; }
    /// <summary>
    /// Process record override.
    /// </summary>
    protected override void ProcessRecord()
    {
        RpcServerNameData name_data = new(Server);
        WriteObject(name_data.ToXml());
    }
}
