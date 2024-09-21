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

using NtCoreLib;
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.Token;
using NtObjectManager.Utils;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Adds an ACE to a security descriptor.</para>
/// <para type="description">This cmdlet adds an ACE to the specified security descriptor. It will
/// automatically select the DACL or SACL depending on the ACE type requested. It also supports
/// specifying a Condition for callback ACEs and Object GUIDs for Object ACEs. The Access property
/// changes behavior depending on the NtType property of the Security Descriptor.
/// </para>
/// </summary>
/// <example>
///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll</code>
///   <para>Add Allowed ACE to DACL with Generic All access for the Everyone group.</para>
/// </example>
/// <example>
///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll -MapGeneric</code>
///   <para>Add Allowed ACE to DACL with Generic All access for the Everyone group and map the generic rights.</para>
/// </example>
/// <example>
///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll -Type Audit</code>
///   <para>Add Audit ACE to SACL with Generic All access for the Everyone group.</para>
/// </example>
/// <example>
///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll -Flags ObjectInherit, InheritOnly</code>
///   <para>Add Allowed ACE to DACL with Generic All access for the Everyone group with Object Inherity and InheritOnly flags.</para>
/// </example>
/// <example>
///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll -Type Denied</code>
///   <para>Add Denied ACE to DACL with Generic All access for the Everyone group.</para>
/// </example>
/// <example>
///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll -Type AllowedCallback -Condition 'APPID://PATH Contains "*"'</code>
///   <para>Add Allowed ACE to DACL with a condition.</para>
/// </example>
/// <example>
///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll -Type AllowedObject -ObjectType "{AD39A509-02C7-4E9A-912A-A51168C10A4C}"</code>
///   <para>Add Allowed Object ACE to DACL with an object type.</para>
/// </example>
/// <example>
///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -ServerSid "BA" -Access GenericAll -Type AllowedCompound</code>
///   <para>Add Allowed Compound ACE to DACL with with Administrators SID as the Server SID.</para>
/// </example>
[Cmdlet(VerbsCommon.Add, "NtSecurityDescriptorAce", DefaultParameterSetName = "FromSid")]
[OutputType(typeof(Ace))]
public sealed class AddNtSecurityDescriptorAceCmdlet : PSCmdlet, IDynamicParameters
{
    private RuntimeDefinedParameterDictionary _dict;

    /// <summary>
    /// <para type="description">Specify to create the security descriptor with a NULL DACL.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    [SecurityDescriptorTransform]
    public SecurityDescriptor SecurityDescriptor { get; set; }

    /// <summary>
    /// <para type="description">Specify to add ACE with SID.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromSid")]
    [SidTransform]
    public Sid Sid { get; set; }

    /// <summary>
    /// <para type="description">Specify to add ACE from a user/group name.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromName")]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">Specify to add ACE a known SID.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromKnownSid")]
    public KnownSidValue KnownSid { get; set; }

    /// <summary>
    /// <para type="description">Specify the type of ACE.</para>
    /// </summary>
    [Parameter]
    public AceType Type { get; set; }

    /// <summary>
    /// <para type="description">Specify the ACE flags.</para>
    /// </summary>
    [Parameter]
    public AceFlags Flags { get; set; }

    /// <summary>
    /// <para type="description">Return the ACE added from the operation.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter PassThru { get; set; }

    /// <summary>
    /// <para type="description">Specify a raw access mask.</para>
    /// </summary>
    [Parameter]
    public AccessMask? RawAccess { get; set; }

    /// <summary>
    /// <para type="description">Map generic access based on the NtType of the SD.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter MapGeneric { get; set; }

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

    /// <summary>
    /// Process Record.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (!_dict.GetValue("Access", out Enum access))
        {
            if (!RawAccess.HasValue && RequiresAccess(Type))
            {
                throw new ArgumentException("Invalid access value.");
            }
            else
            {
                access = GenericAccessRights.None;
            }
        }

        _dict.GetValue("Condition", out string condition);
        _dict.GetValue("ObjectType", out Guid? object_type);
        _dict.GetValue("InheritedObjectType", out Guid? inherited_object_type);
        _dict.GetValue("ServerSid", out Sid server_sid);
        _dict.GetValue("SecurityAttribute", out ClaimSecurityAttribute security_attribute);

        Acl acl;

        if (NtSecurity.IsSystemAceType(Type))
        {
            if (SecurityDescriptor.Sacl == null)
            {
                SecurityDescriptor.Sacl = new Acl();
            }
            acl = SecurityDescriptor.Sacl;
        }
        else
        {
            if (SecurityDescriptor.Dacl == null)
            {
                SecurityDescriptor.Dacl = new Acl();
            }
            acl = SecurityDescriptor.Dacl;
        }

        AccessMask mask = access;
        if (RawAccess.HasValue)
        {
            mask |= RawAccess.Value;
        }

        if (MapGeneric)
        {
            NtType type = SecurityDescriptor.NtType;
            if (type == null)
            {
                WriteWarning("No NtType specified in security descriptor. Defaulting to File.");
                type = NtType.GetTypeByType<NtFile>();
            }
            mask = type.MapGenericRights(mask);
        }

        Ace ace = new(Type, Flags, mask, GetSid());
        if ((NtSecurity.IsCallbackAceType(Type) || Type == AceType.AccessFilter) && !string.IsNullOrWhiteSpace(condition))
        {
            ace.Condition = condition;
        }
        if (NtSecurity.IsObjectAceType(Type))
        {
            ace.ObjectType = object_type;
            ace.InheritedObjectType = inherited_object_type;
        }
        if (Type == AceType.AllowedCompound)
        {
            ace.ServerSid = server_sid;
        }
        if (Type == AceType.ResourceAttribute)
        {
            ace.ResourceAttribute = security_attribute;
        }

        acl.Add(ace);
        if (PassThru)
        {
            WriteObject(ace);
        }
    }

    object IDynamicParameters.GetDynamicParameters()
    {
        bool access_mandatory = !RawAccess.HasValue;
        _dict = new RuntimeDefinedParameterDictionary();
        if (NtSecurity.IsCallbackAceType(Type) || Type == AceType.AccessFilter)
        {
            _dict.AddDynamicParameter("Condition", typeof(string), false);
        }

        if (NtSecurity.IsObjectAceType(Type))
        {
            _dict.AddDynamicParameter("ObjectType", typeof(Guid?), false);
            _dict.AddDynamicParameter("InheritedObjectType", typeof(Guid?), false);
        }

        if (Type == AceType.AllowedCompound)
        {
            _dict.AddDynamicParameter("ServerSid", typeof(Sid), true);
        }

        if (Type == AceType.ResourceAttribute)
        {
            _dict.AddDynamicParameter("SecurityAttribute", typeof(ClaimSecurityAttribute), true);
        }

        Type access_type = SecurityDescriptor?.AccessRightsType ?? typeof(GenericAccessRights);
        if (Type == AceType.MandatoryLabel)
        {
            access_type = typeof(MandatoryLabelPolicy);
        }
        _dict.AddDynamicParameter("Access", access_type, !RawAccess.HasValue && RequiresAccess(Type), 2);

        return _dict;
    }

    private static bool RequiresAccess(AceType type)
    {
        switch (type)
        {
            case AceType.ScopedPolicyId:
            case AceType.ResourceAttribute:
                return false;
        }
        return true;
    }
}
