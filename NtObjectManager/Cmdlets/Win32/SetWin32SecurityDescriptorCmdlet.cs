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

using NtCoreLib;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32;
using NtCoreLib.Win32.Security;
using NtCoreLib.Win32.Security.Authorization;
using NtObjectManager.Utils;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="synopsis">Sets a security descriptor using the Win32 APIs.</para>
/// <para type="description">This cmdlet sets the security descriptor on an object using the Win32 SetSecurityInfo APIs.
/// </para>
/// </summary>
/// <example>
///   <code>Set-Win32SecurityDescriptor "c:\test" $sd Dacl</code>
///   <para>Set the DACL of the file path c:\test.</para>
/// </example>
/// <example>
///   <code>Set-Win32SecurityDescriptor -Object $obj -Type Kernel $sd Dacl</code>
///   <para>Set the DACL of a kernel object.</para>
/// </example>
/// <example>
///   <code>Set-Win32SecurityDescriptor -Handle -Type Kernel $handle $sd Dacl</code>
///   <para>Set the DACL of a kernel object handle.</para>
/// </example>
/// <example>
///   <code>Set-Win32SecurityDescriptor "c:\test" $sd Dacl -ShowProgress</code>
///   <para>Set the DACL of the file path c:\test and show progress</para>
/// </example>
/// <example>
///   <code>Set-Win32SecurityDescriptor "c:\test"  $sd Dacl -ShowProgress</code>
///   <para>Set the DACL of the file path c:\test and show progress</para>
/// </example>

[Cmdlet(VerbsCommon.Set, "Win32SecurityDescriptor", DefaultParameterSetName = "FromName")]
[OutputType(typeof(Win32SetSecurityDescriptorResult))]
public sealed class SetWin32SecurityDescriptorCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">The name of the object.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromName")]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">Handle to an object.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromObject")]
    public NtObject Object { get; set; }

    /// <summary>
    /// <para type="description">Handle to an object.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromHandle")]
    public SafeHandle Handle { get; set; }

    /// <summary>
    /// <para type="description">The type of object represented by Name/Object/Handle. Default is File.</para>
    /// </summary>
    [Parameter]
    public SeObjectType Type { get; set; }

    /// <summary>
    /// <para type="description">The security descriptor to set.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true)]
    public SecurityDescriptor SecurityDescriptor { get; set; }

    /// <summary>
    /// <para type="description">Specify the security information to set.</para>
    /// </summary>
    [Parameter(Position = 2, Mandatory = true)]
    public SecurityInformation SecurityInformation { get; set; }

    /// <summary>
    /// <para type="description">Specify to show the progress when setting security.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromName")]
    public SwitchParameter ShowProgress { get; set; }

    /// <summary>
    /// <para type="description">Specify to pass through results of the security setting operation.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromName")]
    public SwitchParameter PassThru { get; set; }

    /// <summary>
    /// <para type="description">Specify to the tree operation to perform.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromName")]
    public TreeSecInfo Action { get; set; }

    /// <summary>
    /// <para type="description">Specify to only show progress/pass through when an error occurs.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromName")]
    public SwitchParameter ErrorOnly { get; set; }

    private ProgressInvokeSetting ProgressFunction(
        string object_name, Win32Error status, ProgressInvokeSetting invoke_setting, bool security_set)
    {
        if (Stopping)
        {
            return ProgressInvokeSetting.CancelOperation;
        }

        if (ErrorOnly && status == Win32Error.SUCCESS)
        {
            return invoke_setting;
        }

        if (ShowProgress)
        {
            ProgressRecord progress = new(0, "Changing Security", object_name);
            WriteProgress(progress);
        }

        if (PassThru)
        {
            WriteObject(new Win32SetSecurityDescriptorResult(object_name, status, security_set));
        }

        return invoke_setting;
    }

    private void SetNamedSecurityInfo()
    {
        bool do_callback = ShowProgress || PassThru;

        if (Type == SeObjectType.Service)
        {
            SecurityInformation &= SecurityInformation.Owner |
                SecurityInformation.Group | SecurityInformation.Dacl | 
                SecurityInformation.Label | SecurityInformation.Sacl;
        }

        string path = Name;
        if (Type == SeObjectType.File)
        {
            path = PSUtils.ResolveWin32Path(SessionState, path, false);
        }

        if (do_callback || Action != TreeSecInfo.Set)
        {
            TreeProgressFunction fn = ProgressFunction;
            NtStatus status = Win32Security.SetSecurityInfo(path, Type, SecurityInformation, SecurityDescriptor, Action, do_callback ? fn : null, 
                ShowProgress ? ProgressInvokeSetting.PrePostError : ProgressInvokeSetting.EveryObject, !PassThru);
            if (!PassThru)
            {
                status.ToNtException();
            }
        }
        else
        {
            Win32Security.SetSecurityInfo(path, Type, SecurityInformation, SecurityDescriptor);
        }
    }

    /// <summary>
    /// Process Record.
    /// </summary>
    protected override void ProcessRecord()
    {
        switch (ParameterSetName)
        {
            case "FromName":
                SetNamedSecurityInfo();
                break;
            case "FromObject":
                Win32Security.SetSecurityInfo(Object, Type, SecurityInformation, SecurityDescriptor);
                break;
            case "FromHandle":
                Win32Security.SetSecurityInfo(Handle, Type, SecurityInformation, SecurityDescriptor);
                break;
        }
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    public SetWin32SecurityDescriptorCmdlet()
    {
        Action = TreeSecInfo.Set;
        Type = SeObjectType.File;
    }
}
