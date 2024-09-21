//  Copyright 2021 Google LLC. All Rights Reserved.
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
using NtCoreLib.Win32.Printing;
using NtCoreLib.Win32.Security;
using NtCoreLib.Win32.Security.Authorization;
using NtObjectManager.Cmdlets.Object;
using NtObjectManager.Utils;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="synopsis">Gets the granted access using a Win32 security query.</para>
/// <para type="description">This cmdlet allows you to determine the granted access to a particular
/// resource using the Win32 APIs.</para>
/// </summary>
/// <example>
///   <code>Get-Win32GrantedAccess -Type File -Name "c:\windows"</code>
///   <para>Get the maximum access for a file object.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "Win32GrantedAccess")]
public class GetWin32GrantedAccessCmdlet : GetGrantedAccessCmdletBase
{
    /// <summary>
    /// <para type="description">The name of the object.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">The type of object represented by Name/Object/Handle. Default is File.</para>
    /// </summary>
    [Parameter]
    public SeObjectType Type { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public GetWin32GrantedAccessCmdlet()
    {
        Type = SeObjectType.File;
    }

    /// <summary>
    /// Abstract method to get the NT type for the access check.
    /// </summary>
    /// <returns>The NT type.</returns>
    protected override NtType GetNtType()
    {
        if (Type == SeObjectType.Printer)
            return PrintSpoolerUtils.GetTypeForPath(Name);
        return Win32Security.GetNativeType(Type);
    }

    /// <summary>
    /// Abstract method to get the security descriptor for access checking.
    /// </summary>
    /// <returns>The security descriptor.</returns>
    protected override SecurityDescriptor GetSecurityDescriptor()
    {
        SecurityInformation security_info = SecurityInformation.AllBasic;
        if (Type == SeObjectType.Service)
        {
            security_info = SecurityInformation.Owner |
                SecurityInformation.Group | SecurityInformation.Dacl |
                SecurityInformation.Label | SecurityInformation.Sacl;
        }
        return Win32Security.GetSecurityInfo(GetPath(), Type, security_info);
    }

    private string GetPath()
    {
        return Type == SeObjectType.File ? PSUtils.ResolveWin32Path(SessionState, Name, false) : Name;
    }
}
