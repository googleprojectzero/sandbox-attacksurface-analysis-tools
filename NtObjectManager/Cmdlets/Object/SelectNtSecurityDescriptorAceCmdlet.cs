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

using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using NtObjectManager.Utils;
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="description">ACL type for ACE selection.</para>
/// </summary>
[Flags]
public enum SecurityDescriptorAclType
{
    /// <summary>
    /// Only select from the DACL.
    /// </summary>
    Dacl = 1,
    /// <summary>
    /// Only select from the SACL.
    /// </summary>
    Sacl = 2,
    /// <summary>
    /// Select from both ACL and SACL.
    /// </summary>
    Both = Dacl | Sacl,
}

/// <summary>
/// <para type="synopsis">Selects ACEs from a Security Descriptor.</para>
/// <para type="description">This cmdlet selects ACEs from a security descriptor.
/// </para>
/// </summary>
/// <example>
///   <code>Select-NtSecurityDescriptorAce $sd -Sid "WD"</code>
///   <para>Select all ACEs from DACL and SACL with the World SID.</para>
/// </example>
/// <example>
///   <code>Select-NtSecurityDescriptorAce $sd -Type Denied</code>
///   <para>Select all Denied ACEs from DACL.</para>
/// </example>
/// <example>
///   <code>Select-NtSecurityDescriptorAce $sd -Flags Inherited -AclType Dacl</code>
///   <para>Select all inherited ACEs from the DACL only.</para>
/// </example>
/// <example>
///   <code>Select-NtSecurityDescriptorAce $sd -Flags ObjectInherit,ContainerInherit -AllFlags</code>
///   <para>Select all ACEs with Flags set to ObjectInherit and ContainerInherit from the DACL and SACL.</para>
/// </example>
/// <example>
///   <code>Select-NtSecurityDescriptorAce $sd -Access 0x20019</code>
///   <para>Select all ACEs with the Access Mask set to 0x20019 from the DACL and SACL.</para>
/// </example>
/// <example>
///   <code>Select-NtSecurityDescriptorAce $sd -Filter { $_.IsConditionalAce }</code>
///   <para>Select all condition ACEs from the DACL and SACL.</para>
/// </example>
[Cmdlet(VerbsCommon.Select, "NtSecurityDescriptorAce", DefaultParameterSetName = "FromSid")]
[OutputType(typeof(Ace))]
public class SelectNtSecurityDescriptorAceCmdlet : PSCmdlet
{
    #region Constructors
    /// <summary>
    /// Constuctor.
    /// </summary>
    public SelectNtSecurityDescriptorAceCmdlet()
    {
        AclType = SecurityDescriptorAclType.Both;
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// <para type="description">Specify the security descriptor.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ValueFromPipeline = true)]
    [SecurityDescriptorTransform]
    public SecurityDescriptor SecurityDescriptor { get; set; }

    /// <summary>
    /// <para type="description">Specify to select ACE with SID.</para>
    /// </summary>
    [Parameter(Position = 1, ParameterSetName = "FromSid")]
    public Sid Sid { get; set; }

    /// <summary>
    /// <para type="description">Specify to select ACE with a Known SID. Overrides the Sid parameter.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromKnownSid")]
    public KnownSidValue KnownSid { get; set; }

    /// <summary>
    /// <para type="description">Specify to select ACE with a user name. Overrides the Sid and KnownSid parameter.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromName")]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">Specify the type of ACE.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromSid")]
    [Parameter(ParameterSetName = "FromKnownSid")]
    [Parameter(ParameterSetName = "FromName")]
    public AceType? Type { get; set; }

    /// <summary>
    /// <para type="description">Specify the ACE flags.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromSid")]
    [Parameter(ParameterSetName = "FromKnownSid")]
    [Parameter(ParameterSetName = "FromName")]
    public AceFlags? Flags { get; set; }

    /// <summary>
    /// <para type="description">Specify the ACE flags must all match. The default is to select on a partial match.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromSid")]
    [Parameter(ParameterSetName = "FromKnownSid")]
    [Parameter(ParameterSetName = "FromName")]
    public SwitchParameter AllFlags { get; set; }

    /// <summary>
    /// <para type="description">Specify the access.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromSid")]
    [Parameter(ParameterSetName = "FromKnownSid")]
    [Parameter(ParameterSetName = "FromName")]
    public AccessMask? Access { get; set; }

    /// <summary>
    /// <para type="description">Specify a filter to select.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromFilter", Position = 1)]
    public ScriptBlock Filter { get; set; }

    /// <summary>
    /// <para type="description">Specify what ACLs to select the ACEs from.</para>
    /// </summary>
    [Parameter]
    public SecurityDescriptorAclType AclType { get; set; }

    /// <summary>
    /// <para type="description">Only select the first ACE which matches the criteria.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter First { get; set; }

    /// <summary>
    /// <para type="description">Specify to return the result as a new security descriptor.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter AsSecurityDescriptor { get; set; }

    #endregion

    #region Protected Members

    private protected IEnumerable<Ace> SelectAces(Action<Acl, Predicate<Ace>> run_on_acl)
    {
        switch (ParameterSetName)
        {
            case "FromSid":
            case "FromKnownSid":
            case "FromName":
                return FilterFromSid(run_on_acl);
            case "FromFilter":
                return FilterFromFilter(run_on_acl);
        }
        return new Ace[0];
    }

    /// <summary>
    /// Process Record.
    /// </summary>
    protected override void ProcessRecord()
    {
        Action<Acl, Predicate<Ace>> selector;
        if (First)
        {
            selector = (a, p) => a.Find(p);
        }
        else
        {
            selector = (a, p) => a.FindAll(p);
        }

        if (AsSecurityDescriptor)
        {
            var acl_type = AclType;
            SecurityDescriptor sd = SecurityDescriptor.Clone();
            sd.Dacl = null;
            sd.Sacl = null;
            if (acl_type.HasFlag(SecurityDescriptorAclType.Dacl))
            {
                AclType = SecurityDescriptorAclType.Dacl;
                sd.Dacl = new Acl(SelectAces(selector));
            }
            if (acl_type.HasFlag(SecurityDescriptorAclType.Sacl))
            {
                AclType = SecurityDescriptorAclType.Sacl;
                sd.Sacl = new Acl(SelectAces(selector));
            }
            AclType = acl_type;
            WriteObject(sd);
        }
        else
        {
            WriteObject(SelectAces(selector), true);
        }
    }
    #endregion

    #region Private Members

    private Sid GetSid()
    {
        switch (ParameterSetName)
        {
            case "FromSid":
                return Sid;
            case "FromKnownSid":
                return KnownSids.GetKnownSid(KnownSid);
            case "FromName":
                return NtSecurity.LookupAccountName(Name);
            default:
                throw new InvalidOperationException("Unknown parameter set");
        }
    }

    private bool ProcessAce(List<Ace> list, Ace ace, bool dacl, Func<Ace, bool> filter)
    {
        if (!filter(ace))
        {
            return false;
        }

        if (!ShouldProcess($"Type:{ace.Type} Sid:{ace.Sid} Mask:{ace.Mask:X08} in {(dacl ? "DACL" : "SACL")}"))
        {
            return false;
        }

        list.Add(ace);

        return true;
    }

    private static bool HasAcl(Acl acl)
    {
        return acl != null && !acl.NullAcl;
    }

    private void FilterWithFilter(List<Ace> list, Acl acl, bool dacl, Func<Ace, bool> filter, Action<Acl, Predicate<Ace>> run_on_acl)
    {
        if (!HasAcl(acl))
        {
            return;
        }

        run_on_acl?.Invoke(acl, a => ProcessAce(list, a, dacl, filter));
    }

    private protected IEnumerable<Ace> FilterWithFilter(Func<Ace, bool> filter, Action<Acl, Predicate<Ace>> run_on_acl)
    {
        List<Ace> list = new();
        if (AclType.HasFlag(SecurityDescriptorAclType.Dacl))
        {
            FilterWithFilter(list, SecurityDescriptor.Dacl, true, filter, run_on_acl);
        }
        if (AclType.HasFlag(SecurityDescriptorAclType.Sacl))
        {
            FilterWithFilter(list, SecurityDescriptor.Sacl, false, filter, run_on_acl);
        }
        return list;
    }

    private IEnumerable<Ace> FilterFromFilter(Action<Acl, Predicate<Ace>> run_on_acl)
    {
        return FilterWithFilter(a => Filter.InvokeWithArg(false, a), run_on_acl);
    }

    private bool CheckSid(Sid sid, Ace ace)
    {
        if (sid != null && ace.Sid != sid)
        {
            return false;
        }
        if (Type.HasValue && ace.Type != Type)
        {
            return false;
        }
        if (Access.HasValue && ace.Mask != Access)
        {
            return false;
        }
        if (Flags.HasValue)
        {
            if (AllFlags)
            {
                if (ace.Flags != Flags)
                {
                    return false;
                }
            }
            else
            {
                if ((ace.Flags & Flags) != Flags)
                {
                    return false;
                }
            }
        }
        return true;
    }

    private IEnumerable<Ace> FilterFromSid(Action<Acl, Predicate<Ace>> run_on_acl)
    {
        var sid = GetSid();
        if (sid == null && !Type.HasValue && !Access.HasValue && !Flags.HasValue)
        {
            WriteWarning("No filter parameters specified. Not selecting any ACEs.");
            return new Ace[0];
        }

        return FilterWithFilter(ace => CheckSid(sid, ace), run_on_acl);
    }

    #endregion
}
