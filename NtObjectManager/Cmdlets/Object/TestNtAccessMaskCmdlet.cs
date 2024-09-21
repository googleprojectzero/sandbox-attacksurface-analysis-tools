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

using NtCoreLib;
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Tests an access mask for empty or specific bits set.</para>
/// <para type="description">This cmdlet tests if an access mask is empty or if one or all bits are set from a 
/// comparison access mask.</para>
/// </summary>
/// <example>
///   <code>Test-NtAccessMask $access WriteDac</code>
///   <para>Checks if an access mask has WriteDac access.</para>
/// </example>
/// <example>
///   <code>Test-NtAccessMask $access WriteDac, ReadControl -All</code>
///   <para>Checks if an access mask has WriteDac and ReadControl access.</para>
/// </example>
/// <example>
///   <code>Test-NtAccessMask $access WriteDac, ReadControl</code>
///   <para>Checks if an access mask has WriteDac or ReadControl access.</para>
/// </example>
/// <example>
///   <code>Test-NtAccessMask $access -Empty</code>
///   <para>Checks if an access mask is empty.</para>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "NtAccessMask", DefaultParameterSetName = "AccessCompare")]
public class TestNtAccessMaskCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">The access mask to test.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public AccessMask AccessMask { get; set; }

    /// <summary>
    /// <para type="description">The access mask to compare to.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true, ParameterSetName = "AccessCompare")]
    public GenericAccessRights AccessCompare { get; set; }

    /// <summary>
    /// <para type="description">The raw access mask to compare to.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true, ParameterSetName = "RawAccessCompare")]
    public AccessMask RawAccessCompare { get; set; }

    /// <summary>
    /// <para type="description">Check all access is in the mask.</para>
    /// </summary>
    [Parameter(ParameterSetName = "AccessCompare")]
    [Parameter(ParameterSetName = "RawAccessCompare")]
    public SwitchParameter All { get; set; }

    /// <summary>
    /// <para type="description">Test if access mask is empty.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "AccessEmpty")]
    public SwitchParameter Empty { get; set; }

    /// <summary>
    /// <para type="description">Specify the GenericMapping to check if Access Mask would be Write Restricted.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "WriteRestricted")]
    public GenericMapping WriteRestricted { get; set; }

    private AccessMask GetAccessMask()
    {
        if (ParameterSetName == "RawAccessCompare")
        {
            return RawAccessCompare;
        }
        return AccessCompare;
    }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (Empty)
        {
            WriteObject(AccessMask.IsEmpty);
        }
        else if (ParameterSetName == "WriteRestricted")
        {
            GenericMapping std_map = NtSecurity.StandardAccessMapping;
            WriteObject((std_map.GenericWrite & ~(std_map.GenericRead | std_map.GenericExecute)
                | WriteRestricted.GenericWrite & ~(WriteRestricted.GenericRead | WriteRestricted.GenericExecute)).IsEmpty);
        }
        else if (All)
        {
            WriteObject(AccessMask.IsAllAccessGranted(GetAccessMask()));
        }
        else
        {
            WriteObject(AccessMask.IsAccessGranted(GetAccessMask()));
        }
    }
}
