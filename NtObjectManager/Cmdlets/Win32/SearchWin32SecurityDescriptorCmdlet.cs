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

using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Security;
using NtCoreLib.Win32.Security.Authorization;
using System;
using System.IO;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="synopsis">Search for inherited ACLs for the security descriptor.</para>
/// <para type="description">This cmdlet searches for the ancestors of an inherited security resource.
/// </para>
/// </summary>
/// <example>
///   <code>Search-Win32SecurityDescriptor "c:\test"</code>
///   <para>Search for the inheritance ancestors of c:\test.</para>
/// </example>
[Cmdlet(VerbsCommon.Search, "Win32SecurityDescriptor")]
[OutputType(typeof(SecurityDescriptorInheritanceSource))]
public sealed class SearchWin32SecurityDescriptorCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">The name of the object.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">The security descriptor to check for inheritance.</para>
    /// </summary>
    [Parameter]
    public SecurityDescriptor SecurityDescriptor { get; set; }

    /// <summary>
    /// <para type="description">Specify the GenericMapping for the check.</para>
    /// </summary>
    [Parameter]
    public GenericMapping? GenericMapping { get; set; }

    /// <summary>
    /// <para type="description">Specify to check the SACL. Default is the DACL.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Sacl { get; set; }

    /// <summary>
    /// <para type="description">The type of object represented by Name. Default is File.</para>
    /// </summary>
    [Parameter]
    public SeObjectType Type { get; set; }

    /// <summary>
    /// <para type="description">Specify list of object types.</para>
    /// </summary>
    [Parameter]
    public Guid[] ObjectType { get; set; }

    /// <summary>
    /// <para type="description">Specify to query the full security descriptor for the ancestors.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter QuerySecurity { get; set; }

    private GenericMapping GetGenericMapping()
    {
        if (GenericMapping.HasValue)
        {
            return GenericMapping.Value;
        }

        return Win32Security.GetNativeType(Type)?.GenericMapping 
            ?? throw new ArgumentException("Must specify a Generic Mapping for the type");
    }

    /// <summary>
    /// Process Record.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (SecurityDescriptor == null)
        {
            SecurityDescriptor = Win32Security.GetSecurityInfo(Name, Type, 
                Sacl ? SecurityInformation.All : SecurityInformation.AllNoSacl);
        }

        WriteObject(Win32Security.GetInheritanceSource(Name, Type, IsContainer(), ObjectType,
            SecurityDescriptor, Sacl, GetGenericMapping(), QuerySecurity), true);
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    public SearchWin32SecurityDescriptorCmdlet()
    {
        Type = SeObjectType.File;
    }

    private bool IsContainer()
    {
        if (Type == SeObjectType.File)
        {
            return Directory.Exists(Name);
        }
        return true;
    }
}
