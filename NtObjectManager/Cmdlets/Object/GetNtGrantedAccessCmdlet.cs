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
using NtCoreLib.Security.Authorization;
using NtObjectManager.Utils;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Gets the granted access to a security descriptor or object.</para>
/// <para type="description">This cmdlet allows you to determine the granted access to a particular
/// resource through a security descriptor or a reference to an object.</para>
/// </summary>
/// <example>
///   <code>Get-NtGrantedAccess $sd -Type $(Get-NtType File)</code>
///   <para>Get the maximum access for a security descriptor for a file object.</para>
/// </example>
/// <example>
///   <code>Get-NtGrantedAccess -Sddl "O:BAG:BAD:(A;;GA;;;WD)" -Type $(Get-NtType Process)</code>
///   <para>Get the maximum access for a security descriptor for a process object based on an SDDL string.</para>
/// </example>
/// <example>
///   <code>Get-NtGrantedAccess -Object $obj</code>
///   <para>Get the maximum access for a security descriptor for an object.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "NtGrantedAccess", DefaultParameterSetName = "sd")]
public class GetNtGrantedAccessCmdlet : GetGrantedAccessCmdletBase
{
    /// <summary>
    /// <para type="description">Specify a security descriptor.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "sd")]
    [SecurityDescriptorTransform]
    public SecurityDescriptor SecurityDescriptor { get; set; }

    /// <summary>
    /// <para type="description">Specify a security descriptor in SDDL format.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "sddl")]
    public string Sddl { get; set; }

    /// <summary>
    /// <para type="description">Specify the NT type for the access check.</para>
    /// </summary>
    [Parameter(ParameterSetName = "sd"), 
        Parameter(Mandatory = true, ParameterSetName = "sddl"), 
        ArgumentCompleter(typeof(NtTypeArgumentCompleter))]
    public NtType Type { get; set; }

    /// <summary>
    /// <para type="description">Specify an object to get security descriptor from.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "obj")]
    public INtObjectSecurity Object { get; set; }

    /// <summary>
    /// <para type="description">Specify if the type is a container..</para>
    /// </summary>
    [Parameter]
    public override SwitchParameter Container { get => Object?.IsContainer ?? base.Container; set => base.Container = value; }

    /// <summary>
    /// Abstract method to get the security descriptor for access checking.
    /// </summary>
    /// <returns>The security descriptor.</returns>
    protected override SecurityDescriptor GetSecurityDescriptor()
    {
        if (SecurityDescriptor != null)
        {
            return SecurityDescriptor;
        }
        else if (Sddl != null)
        {
            return new SecurityDescriptor(Sddl);
        }
        else
        {
            return Object?.GetSecurityDescriptor(SecurityInformation.AllNoSacl);
        }
    }

    /// <summary>
    /// Abstract method to get the NT type for the access check.
    /// </summary>
    /// <returns>The NT type.</returns>
    protected override NtType GetNtType()
    {
        NtType type;
        if (Type != null)
        {
            type = Type;
        }
        else
        {
            type = GetSecurityDescriptor()?.NtType;
        }
        
        return type;
    }
}
