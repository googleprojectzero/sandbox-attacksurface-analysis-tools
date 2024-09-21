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
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Set the Default DACL for a Token.</para>
/// <para type="description">This cmdlet sets the Default DACL for a Token.</para>
/// </summary>
/// <example>
///   <code>Set-NtTokenDefaultDacl -DefaultDacl $dacl</code>
///   <para>Set current effective token's Default DACL.</para>
/// </example>
/// <example>
///   <code>Set-NtTokenDefaultDacl -SecurityDescriptor $sd</code>
///   <para>Set current effective token's Default DACL from a Security Descriptor.</para>
/// </example>
/// <example>
///   <code>Set-NtTokenDefaultDacl -DefaultDacl $dacl -Token $token</code>
///   <para>Set Default DACL for a Token.</para>
/// </example>
[Cmdlet(VerbsCommon.Set, "NtTokenDefaultDacl", DefaultParameterSetName = "FromAcl")]
public class SetNtTokenDefaultDacl : PSCmdlet
{
    private NtToken GetToken()
    {
        if (Token != null)
            return Token.Duplicate();
        return NtToken.OpenEffectiveToken(NtThread.Current, true, false, TokenAccessRights.AdjustDefault);
    }

    /// <summary>
    /// <para type="description">Specify the default DACL.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromAcl", Position = 1, Mandatory = true)]
    [AllowEmptyCollection]
    public Acl DefaultDacl { get; set; }

    /// <summary>
    /// <para type="description">Specify the default DACL as a Security Descriptor.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromSD", Position = 1, Mandatory = true)]
    public SecurityDescriptor SecurityDescriptor { get; set; }

    /// <summary>
    /// <para type="description">Specify the token to set the default DACL.</para>
    /// </summary>
    [Parameter(Position = 1)]
    public NtToken Token { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {

        Acl default_dacl = null;

        switch (ParameterSetName)
        {
            case "FromAcl":
                default_dacl = DefaultDacl;
                break;
            case "FromSD":
                default_dacl = SecurityDescriptor.Dacl;
                break;
        }

        if (default_dacl == null)
        {
            throw new ArgumentNullException(nameof(DefaultDacl));
        }

        using var token = GetToken();
        token.SetDefaultDacl(default_dacl);
    }
}
