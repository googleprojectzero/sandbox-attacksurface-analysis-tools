//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtCoreLib.Win32.Security.Authorization;
using NtObjectManager.Utils;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="synopsis">Create a new AuthZ Resource Manager..</para>
/// <para type="description">This cmdlet creates a new AuthZ Resource Manager.</para>
/// </summary>
/// <example>
///   <code>New-AuthZResourceManager</code>
///   <para>Create a default AuthZ Resource Manager.</para>
/// </example>
/// <example>
///   <code>New-AuthZResourceManager -Name "TestRM"</code>
///   <para>Create a AuthZ Resource Manager with a name.</para>
/// </example>
/// <example>
///   <code>New-AuthZResourceManager -Flags InitializeUnderImpersonation, NoAudit</code>
///   <para>Create a AuthZ Resource Manager flags.</para>
/// </example>
/// <example>
///   <code>New-AuthZResourceManager { $_.Type -EQ "DeniedCallback" }</code>
///   <para>Create a AuthZ Resource Manager with a Callback ACE script block.</para>
/// </example>
[Cmdlet(VerbsCommon.New, "AuthZResourceManager", DefaultParameterSetName = "LocalRM")]
[OutputType(typeof(AuthZResourceManager))]
public class NewAuthZResourceManagerCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Flags for initialization. Defaults to NoAudit.</para>
    /// </summary>
    [Parameter(ParameterSetName = "LocalRM")]
    public AuthZResourceManagerInitializeFlags Flags { get; set; }

    /// <summary>
    /// <para type="description">Optional name for the Resource Manager.</para>
    /// </summary>
    [Parameter(ParameterSetName = "LocalRM")]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">Optional script block for callback ACE handling.</para>
    /// </summary>
    [Parameter(Position = 0, ParameterSetName = "LocalRM")]
    public ScriptBlock CallbackAceScriptBlock { get; set; }

    /// <summary>
    /// <para type="description">Network address for the server.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "RemoteRM")]
    public string Server { get; set; }

    /// <summary>
    /// <para type="description">The SPN for the server.</para>
    /// </summary>
    [Parameter(ParameterSetName = "RemoteRM")]
    public string ServerSpn { get; set; }

    /// <summary>
    /// <para type="description">The service type for the remote server.</para>
    /// </summary>
    [Parameter(ParameterSetName = "RemoteRM")]
    public AuthZResourceManagerRemoteServiceType ServiceType { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public NewAuthZResourceManagerCmdlet()
    {
        Flags = AuthZResourceManagerInitializeFlags.NoAudit;
        ServiceType = AuthZResourceManagerRemoteServiceType.Default;
    }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (ParameterSetName == "LocalRM")
        {
            AuthZHandleCallbackAce callback = null;
            if (CallbackAceScriptBlock != null)
            {
                callback = a => PSUtils.InvokeWithArg(CallbackAceScriptBlock, false, a);
            }
            WriteObject(AuthZResourceManager.Create(Name, Flags, callback));
        }
        else
        {
            WriteObject(AuthZResourceManager.Create(Server, ServerSpn, ServiceType));
        }
    }
}
