//  Copyright 2022 Google LLC. All Rights Reserved.
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

using NtCoreLib.Win32.Security.Authentication.Kerberos.Client;
using NtCoreLib.Win32.Security.Authentication.Kerberos.Server;
using NtObjectManager.Utils.Kerberos;
using System.DirectoryServices.ActiveDirectory;
using System.Management.Automation;
using System.Net;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="synopsis">Create a new KDC proxy with PowerShell handlers.</para>
/// <para type="description">This cmdlet creates a KDC proxy instance with PowerShell scripts to filter requests and replies.</para>
/// </summary>
/// <example>
///   <code>$proxy = New-KerberosKdcProxy -HandleRequest { $_.Format() | Out-Host } -HandleReply { $_.Format() | Out-Host }&#x0A;$proxy.Start()</code>
///   <para>Create a new KDC proxy and display the request and reply tokens.</para>
/// </example>
[Cmdlet(VerbsCommon.New, "KerberosKdcProxy")]
public class NewKerberosKDCProxyCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify a script block to handle the request.</para>
    /// </summary>
    [Parameter]
    public ScriptBlock HandleRequest { get; set; }

    /// <summary>
    /// <para type="description">Specify a script block to handle a reply.</para>
    /// </summary>
    [Parameter]
    public ScriptBlock HandleReply { get; set; }

    /// <summary>
    /// <para type="description">Specify a script block to handle an error in the proxy.</para>
    /// </summary>
    [Parameter]
    public ScriptBlock HandleError { get; set; }

    /// <summary>
    /// <para type="description">Specify the server listener.</para>
    /// </summary>
    [Parameter]
    public IKerberosKDCServerListener Listener { get; set; }

    /// <summary>
    /// <para type="description">Specify the server hostname. If not specified then will use the current PDC for the domain.</para>
    /// </summary>
    public string Hostname { get; set; }

    /// <summary>
    /// <para type="description">Specify the server TCP port.</para>
    /// </summary>
    [Parameter]
    public int Port { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public NewKerberosKDCProxyCmdlet()
    {
        Port = 88;
    }

    /// <summary>
    /// Process the command.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (string.IsNullOrWhiteSpace(Hostname))
            Hostname = Domain.GetCurrentDomain().PdcRoleOwner.Name;

        WriteObject(new PSKerberosKDCProxy(Listener ?? new KerberosKDCServerListenerTCP(IPAddress.Loopback, 88),
            new KerberosKDCClientTransportTCP(Hostname, Port), HandleRequest, HandleReply, HandleError));
    }
}
