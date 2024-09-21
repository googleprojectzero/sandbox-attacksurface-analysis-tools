//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtCoreLib.Security.Token;
using NtCoreLib.Win32.Service;
using NtObjectManager.Utils;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="synopsis">Change the configuration of a service.</para>
/// <para type="description">This cmdlet changes the configuration of a service either locally
/// or remotely.</para>
/// </summary>
/// <example>
///   <code>Set-Win32ServiceConfig -Name "DEMO" -Path "c:\target\path.exe"</code>
///   <para>Set the binary path for the service DEMO.</para>
/// </example>
[Cmdlet(VerbsCommon.Set, "Win32ServiceConfig")]
public sealed class SetWin32ServiceConfigCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the name of the service.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0)]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">Specify the name of target computer.</para>
    /// </summary>
    [Parameter]
    public string MachineName { get; set; }

    /// <summary>
    /// <para type="description">Specify the display name of the service.</para>
    /// </summary>
    [Parameter(ParameterSetName = "ChangeConfig")]
    public string DisplayName { get; set; }

    /// <summary>
    /// <para type="description">Specify the type of the service.</para>
    /// </summary>
    [Parameter(ParameterSetName = "ChangeConfig")]
    public ServiceType? Type { get; set; }

    /// <summary>
    /// <para type="description">Specify the start type of the service.</para>
    /// </summary>
    [Parameter(ParameterSetName = "ChangeConfig")]
    public ServiceStartType? Start { get; set; }

    /// <summary>
    /// <para type="description">Specify error control of the service.</para>
    /// </summary>
    [Parameter(ParameterSetName = "ChangeConfig")]
    public ServiceErrorControl? ErrorControl { get; set; }

    /// <summary>
    /// <para type="description">Specify the binary path to the service.</para>
    /// </summary>
    [Parameter(ParameterSetName = "ChangeConfig")]
    public string Path { get; set; }

    /// <summary>
    /// <para type="description">Specify the load order tag id.</para>
    /// </summary>
    [Parameter(ParameterSetName = "ChangeConfig")]
    public int? TagId { get; set; }

    /// <summary>
    /// <para type="description">Specify the load order group.</para>
    /// </summary>
    [Parameter(ParameterSetName = "ChangeConfig")]
    public string LoadOrderGroup { get; set; }

    /// <summary>
    /// <para type="description">Specify list of dependencies.</para>
    /// </summary>
    [Parameter(ParameterSetName = "ChangeConfig")]
    public string[] Dependencies { get; set; }

    /// <summary>
    /// <para type="description">Specify the user name for the service.</para>
    /// </summary>
    [Parameter(ParameterSetName = "ChangeConfig")]
    public string UserName { get; set; }

    /// <summary>
    /// <para type="description">Specify password for the service user.</para>
    /// </summary>
    [Parameter(ParameterSetName = "ChangeConfig")]
    public PasswordHolder Password { get; set; }

    /// <summary>
    /// <para type="description">Specify the service protected type.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "ChangeProtected")]
    public ServiceLaunchProtectedType LaunchProtected { get; set; }

    /// <summary>
    /// <para type="description">Specify the service restricted SID type.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "ChangeSid")]
    public ServiceSidType SidType { get; set; }

    /// <summary>
    /// <para type="description">Specify the service required privilege.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "ChangeRequiredPrivilege")]
    [AllowEmptyCollection]
    public TokenPrivilegeValue[] RequiredPrivilege { get; set; }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        switch (ParameterSetName)
        {
            case "ChangeConfig":
                ServiceUtils.ChangeServiceConfig(MachineName, Name,
                    DisplayName, Type, Start, ErrorControl,
                    Path, TagId, LoadOrderGroup, Dependencies, UserName, Password?.Password);
                break;
            case "ChangeProtected":
                ServiceUtils.SetServiceLaunchProtected(MachineName, Name, LaunchProtected);
                break;
            case "ChangeSid":
                ServiceUtils.SetServiceSidType(MachineName, Name, SidType);
                break;
            case "ChangeRequiredPrivilege":
                ServiceUtils.SetServiceRequiredPrivileges(MachineName, Name, RequiredPrivilege.Select(p => p.ToString()).ToArray());
                break;
        }
    }
}
