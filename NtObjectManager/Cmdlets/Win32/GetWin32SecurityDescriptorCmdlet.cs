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
using NtCoreLib.Win32.Security;
using NtCoreLib.Win32.Security.Authorization;
using NtObjectManager.Utils;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="synopsis">Gets a security descriptor using the Win32 APIs.</para>
/// <para type="description">This cmdlet gets the security descriptor on an object using the Win32 GetSecurityInfo APIs.
/// </para>
/// </summary>
/// <example>
///   <code>Get-Win32SecurityDescriptor "c:\test"</code>
///   <para>Get the security descriptor for file path c:\test.</para>
/// </example>
/// <example>
///   <code>Get-Win32SecurityDescriptor -Object $obj -Type Kernel Dacl</code>
///   <para>Get the DACL of a kernel object.</para>
/// </example>
/// <example>
///   <code>Get-Win32SecurityDescriptor -Handle -Type Kernel $handle Dacl</code>
///   <para>Get the DACL of a kernel object handle.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "Win32SecurityDescriptor", DefaultParameterSetName = "FromName")]
[OutputType(typeof(SecurityDescriptor))]
public sealed class GetWin32SecurityDescriptorCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">The name of the object.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromName")]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">Specify the security information to set.</para>
    /// </summary>
    [Parameter(Position = 1)]
    public SecurityInformation SecurityInformation { get; set; }

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
    /// Process Record.
    /// </summary>
    protected override void ProcessRecord()
    {
        SecurityDescriptor sd = null;
        switch (ParameterSetName)
        {
            case "FromName":
                string path = Name;
                if (Type == SeObjectType.File)
                {
                    path = PSUtils.ResolveWin32Path(SessionState, Name, false);
                }

                if (Type == SeObjectType.Service)
                {
                    SecurityInformation &= SecurityInformation.Owner |
                        SecurityInformation.Group | SecurityInformation.Dacl | 
                        SecurityInformation.Label | SecurityInformation.Sacl;
                }

                sd = Win32Security.GetSecurityInfo(path, Type, SecurityInformation);
                break;
            case "FromObject":
                sd = Win32Security.GetSecurityInfo(Object.Handle, Type, SecurityInformation);
                break;
            case "FromHandle":
                sd = Win32Security.GetSecurityInfo(Handle, Type, SecurityInformation);
                break;
        }
        if (sd != null)
        {
            WriteObject(sd);
        }
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    public GetWin32SecurityDescriptorCmdlet()
    {
        Type = SeObjectType.File;
        SecurityInformation = SecurityInformation.AllBasic;
    }
}
