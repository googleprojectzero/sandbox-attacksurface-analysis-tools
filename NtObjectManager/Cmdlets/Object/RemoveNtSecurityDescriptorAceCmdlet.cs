//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Removes ACEs from a security descriptor.</para>
/// <para type="description">This cmdlet removes ACEs from a security descriptor.
/// </para>
/// </summary>
/// <example>
///   <code>Remove-NtSecurityDescriptorAce $sd -Sid "WD"</code>
///   <para>Remove all ACEs from DACL and SACL with the World SID.</para>
/// </example>
/// <example>
///   <code>Remove-NtSecurityDescriptorAce $sd -Type Denied</code>
///   <para>Remove all Denied ACEs from DACL.</para>
/// </example>
/// <example>
///   <code>Remove-NtSecurityDescriptorAce $sd -Flags Inherited -AclType Dacl</code>
///   <para>Remove all inherited ACEs from the DACL only.</para>
/// </example>
/// <example>
///   <code>Remove-NtSecurityDescriptorAce $sd -Flags ObjectInherit,ContainerInherit -AllFlags</code>
///   <para>Remove all ACEs with Flags set to ObjectInherit and ContainerInherit from the DACL and SACL.</para>
/// </example>
/// <example>
///   <code>Remove-NtSecurityDescriptorAce $sd -Access 0x20019</code>
///   <para>Remove all ACEs with the Access Mask set to 0x20019 from the DACL and SACL.</para>
/// </example>
/// <example>
///   <code>Remove-NtSecurityDescriptorAce $sd -Filter { $_.IsConditionalAce }</code>
///   <para>Remove all condition ACEs from the DACL and SACL.</para>
/// </example>
/// <example>
///   <code>Remove-NtSecurityDescriptorAce $sd -Ace @($a1, $a2)</code>
///   <para>Remove all ACEs which match a list from the DACL and SACL.</para>
/// </example>
/// <example>
///   <code>@($a1, $a2) | Remove-NtSecurityDescriptorAce $sd</code>
///   <para>Remove all ACEs which match a list from the DACL and SACL.</para>
/// </example>
/// <example>
///   <code>Remove-NtSecurityDescriptorAce $sd -Sid "WD" -WhatIf</code>
///   <para>Test what ACEs would be removed from DACL and SACL with the World SID.</para>
/// </example>
/// <example>
///   <code>Remove-NtSecurityDescriptorAce $sd -Sid "WD" -Confirm</code>
///   <para>Remove all ACEs from DACL and SACL with the World SID with confirmation.</para>
/// </example>
[Cmdlet(VerbsCommon.Remove, "NtSecurityDescriptorAce", DefaultParameterSetName = "FromSid", SupportsShouldProcess = true)]
[OutputType(typeof(Ace))]
public sealed class RemoveNtSecurityDescriptorAceCmdlet : SelectNtSecurityDescriptorAceCmdlet
{
    #region Public Properties
    /// <summary>
    /// <para type="description">Specify list of ACEs to remove.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromAce", Position = 1, ValueFromPipeline = true)]
    public Ace[] Ace { get; set; }

    /// <summary>
    /// <para type="description">Return the ACEs removed by the operation.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter PassThru { get; set; }

    #endregion

    #region Protected Members
    /// <summary>
    /// Process Record.
    /// </summary>
    protected override void ProcessRecord()
    {
        IEnumerable<Ace> aces = new Ace[0];
        if (ParameterSetName == "FromAce")
        {
            aces = FilterFromAce();
        }
        else
        {
            aces = SelectAces(RemoveAces);
        }

        if (PassThru)
        {
            WriteObject(aces, true);
        }
    }
    #endregion

    #region Private Members

    private void RemoveAces(Acl acl, Predicate<Ace> predicate)
    {
        if (First)
        {
            foreach (var ace in acl)
            {
                if (predicate(ace))
                {
                    return;
                }
            }
        }
        else
        {
            acl.RemoveAll(predicate);
        }
    }

    private IEnumerable<Ace> FilterFromAce()
    {
        HashSet<Ace> aces = new(Ace);
        return FilterWithFilter(a => aces.Contains(a), RemoveAces);
    }

    #endregion
}
