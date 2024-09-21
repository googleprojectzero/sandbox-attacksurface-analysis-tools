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
using NtCoreLib.Security.Authorization;
using NtCoreLib.Utilities.Security.Authorization;
using NtCoreLib.Win32.Security.Authorization;
using NtObjectManager.Utils;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="synopsis">Gets the granted access to a security descriptor or object.</para>
/// <para type="description">This cmdlet allows you to determine the granted access to a particular
/// resource through a security descriptor using the AuthZ APIs.</para>
/// </summary>
/// <example>
///   <code>Get-AuthZGrantedAccess $ctx $sd</code>
///   <para>Get the maximum access for a security descriptor.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "AuthZGrantedAccess")]
[OutputType(typeof(AuthZAccessCheckResult))]
public class GetAuthZGrantedAccessCmdlet : PSCmdlet, IDynamicParameters
{
    private RuntimeDefinedParameterDictionary _dict;

    /// <summary>
    /// <para type="description">Specify the AuthZ Client Context.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0)]
    public AuthZContext Context { get; set; }

    /// <summary>
    /// <para type="description">Specify a security descriptor.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1)]
    [SecurityDescriptorTransform]
    public SecurityDescriptor SecurityDescriptor { get; set; }

    /// <summary>
    /// <para type="description">Specify list of additional SDs to merge in.</para>
    /// </summary>
    [Parameter]
    public SecurityDescriptor[] AdditionalSecurityDescriptor { get; set; }

    /// <summary>
    /// <para type="description">Specify an access mask to check against. Overrides GenericAccess.</para>
    /// </summary>
    [Parameter]
    public AccessMask? RawAccess { get; set; }

    /// <summary>
    /// <para type="description">Specify a principal SID to user when checking security descriptors with SELF SID.</para>
    /// </summary>
    [Parameter]
    public Sid Principal { get; set; }

    /// <summary>
    /// <para type="description">Specify object types for access check.</para>
    /// </summary>
    [Parameter]
    public ObjectTypeTree ObjectType { get; set; }

    /// <summary>
    /// <para type="description">Specify the NT type for the access check.</para>
    /// </summary>
    [Parameter, ArgumentCompleter(typeof(NtTypeArgumentCompleter))]
    public NtType Type { get; set; }

    private AccessMask GetDesiredAccess()
    {
        NtType type = GetNtType();
        if (RawAccess.HasValue)
        {
            return type.MapGenericRights(RawAccess.Value);
        }

        if (!_dict.GetValue("Access", out Enum access))
        {
            return GenericAccessRights.MaximumAllowed;
        }

        return type.MapGenericRights(access);
    }

    private NtType GetNtType()
    {
        NtType type;
        if (Type != null)
        {
            type = Type;
        }
        else
        {
            type = SecurityDescriptor?.NtType;
        }

        return type;
    }

    /// <summary>
    /// Process Record.
    /// </summary>
    protected override void ProcessRecord()
    {
        WriteObject(Context.AccessCheck(SecurityDescriptor, AdditionalSecurityDescriptor, 
            GetDesiredAccess(), Principal, ObjectType?.ToArray(), GetNtType()), true);
    }

    object IDynamicParameters.GetDynamicParameters()
    {
        _dict = new RuntimeDefinedParameterDictionary();
        Type access_type = GetNtType()?.AccessRightsType ?? typeof(GenericAccessRights);
        _dict.AddDynamicParameter("Access", access_type, false);
        return _dict;
    }
}
