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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Get the Default DACL from a Token.</para>
/// <para type="description">This cmdlet gets the Default DACL from a Token.</para>
/// </summary>
/// <example>
///   <code>$dacl = Get-NtTokenDefaultDacl</code>
///   <para>Get current effective token's Default DACL.</para>
/// </example>
/// <example>
///   <code>$dacl = Get-NtTokenDefaultDacl -Token $token</code>
///   <para>Get Default DACL from a Token.</para>
/// </example>
/// <example>
///   <code>$sd = Get-NtTokenDefaultDacl -AsSecurityDescriptor</code>
///   <para>Get current process' primary token's Default DACL as a Security Descriptor.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "NtTokenDefaultDacl", DefaultParameterSetName = "FromCurrent")]
[OutputType(typeof(SecurityDescriptor), typeof(Acl))]
public class GetNtTokenDefaultDacl : PSCmdlet
{
    private NtToken GetToken()
    {
        if (Token != null)
            return Token.Duplicate();
        return NtToken.OpenEffectiveToken(NtThread.Current, true, false, TokenAccessRights.Query);
    }

    /// <summary>
    /// <para type="description">Specify the token to query for the default DACL.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromToken", Position = 0, Mandatory = true)]
    public NtToken Token { get; set; }

    /// <summary>
    /// <para type="description">Specify to return the ACL in a Security Descriptor.</para>
    /// </summary>
    [Parameter]
    [Alias("sd")]
    public SwitchParameter AsSecurityDescriptor { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        using var token = GetToken();
        Acl default_dacl = token.DefaultDacl;
        if (AsSecurityDescriptor)
        {
            WriteObject(new SecurityDescriptor() { Dacl = default_dacl });
        }
        else
        {
            WriteObject(default_dacl, false);
        }
    }
}
