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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="synopsis">Resets a security descriptor using the Win32 APIs.</para>
/// <para type="description">This cmdlet resets the security descriptor on an object using the Win32 SetSecurityInfo APIs.
/// </para>
/// </summary>
/// <example>
///   <code>Reset-Win32SecurityDescriptor "c:\test" Dacl</code>
///   <para>Reset the DACL of the file path c:\test.</para>
/// </example>
/// <example>
///   <code>Reset-Win32SecurityDescriptor "c:\test" Dacl -KeepExplicit</code>
///   <para>Reset the DACL of the file path c:\test keeping explicit ACEs.</para>
/// </example>
/// <example>
///   <code>Reset-Win32SecurityDescriptor "c:\test" Dacl -ShowProgress</code>
///   <para>Reset the DACL of the file path c:\test and show progress</para>
/// </example>
/// <example>
///   <code>Reset-Win32SecurityDescriptor "c:\test" Dacl -SecurityDescriptor $sd</code>
///   <para>Reset the DACL of the file path c:\test with an explicit SD.</para>
/// </example>
[Cmdlet(VerbsCommon.Reset, "Win32SecurityDescriptor")]
[OutputType(typeof(Win32SetSecurityDescriptorResult))]
public sealed class ResetWin32SecurityDescriptorCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">The name of the object.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">Specify the security information to set.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true)]
    public SecurityInformation SecurityInformation { get; set; }

    /// <summary>
    /// <para type="description">The security descriptor to set. Optional.</para>
    /// </summary>
    [Parameter]
    public SecurityDescriptor SecurityDescriptor { get; set; }

    /// <summary>
    /// <para type="description">The type of object represented by Name. Default to File.</para>
    /// </summary>
    [Parameter]
    public SeObjectType Type { get; set; }

    /// <summary>
    /// <para type="description">Specify to show the progress when setting security.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter ShowProgress { get; set; }

    /// <summary>
    /// <para type="description">Specify to keep explicit ACEs.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter KeepExplicit { get; set; }

    /// <summary>
    /// <para type="description">Specify to pass through results of the security setting operation.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter PassThru { get; set; }

    /// <summary>
    /// <para type="description">Specify to only show progress/pass through when an error occurs.</para>
    /// </summary>
    [Parameter]
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
            ProgressRecord progress = new(0, "Resetting Security", object_name);
            WriteProgress(progress);
        }

        if (PassThru)
        {
            WriteObject(new Win32SetSecurityDescriptorResult(object_name, status, security_set));
        }

        return invoke_setting;
    }

    /// <summary>
    /// Process Record.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (SecurityDescriptor == null)
        {
            SecurityDescriptor = new SecurityDescriptor();
            if (SecurityInformation.HasFlag(SecurityInformation.Dacl))
                SecurityDescriptor.Dacl = new Acl();
            if (SecurityInformation.HasFlag(SecurityInformation.Sacl))
                SecurityDescriptor.Sacl = new Acl();
        }

        bool do_callback = ShowProgress || PassThru;
        TreeProgressFunction fn = ProgressFunction;
        NtStatus status = Win32Security.ResetSecurityInfo(Name, Type, SecurityInformation, SecurityDescriptor, do_callback ? fn : null,
            ShowProgress ? ProgressInvokeSetting.PrePostError : ProgressInvokeSetting.EveryObject, KeepExplicit, !PassThru);
        if (!PassThru)
        {
            status.ToNtException();
        }
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    public ResetWin32SecurityDescriptorCmdlet()
    {
        Type = SeObjectType.File;
    }
}
