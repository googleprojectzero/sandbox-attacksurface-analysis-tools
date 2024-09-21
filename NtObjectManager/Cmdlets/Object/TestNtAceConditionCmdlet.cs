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
using NtCoreLib.Security.Token;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Checks a ACE conditional express evaluated to a true.</para>
/// <para type="description">This cmdlet evaluates an ACE conditional express to see if a specified token would match.</para>
/// </summary>
/// <example>
///   <code>Test-NtAceCondition -Token $token</code>
///   <para>Checks if the token can be impersonated at impersonation level.</para>
/// </example>
/// <example>
///   <code>Test-NtAceCondition -Condition "WIN://ABC == 100"</code>
///   <para>Checks the expression "WIN://ABC == 100" matches the effective token.</para>
/// </example>
/// <example>
///   <code>Test-NtAceCondition -Condition "WIN://ABC == 100" -Token $token</code>
///   <para>Checks the expression "WIN://ABC == 100" matches a specified token.</para>
/// </example>
/// <example>
///   <code>Test-NtAceCondition -ConditionData $ba</code>
///   <para>Checks the expression as a byte array matches the effective token.</para>
/// </example>
/// <example>
///   <code>Test-NtAceCondition -Ace $ace</code>
///   <para>Checks the expression from a conditional ACE matches the effective token.</para>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "NtAceCondition")]
public class TestNtAceConditionCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the token to test.</para>
    /// </summary>
    [Parameter]
    public NtToken Token { get; set; }

    /// <summary>
    /// <para type="description">Specify the conditional expression as an SDDL string.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromSddl")]
    public string Condition { get; set; }

    /// <summary>
    /// <para type="description">Specify the conditional expression as a byte array.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromData")]
    public byte[] ConditionData { get; set; }

    /// <summary>
    /// <para type="description">Specify a conditional ACE. Note that only the conditional expression is used, not the Sid or Mask.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromAce")]
    public Ace Ace { get; set; }

    /// <summary>
    /// <para type="description">Specify a list of resource attributes.</para>
    /// </summary>
    [Parameter]
    public ClaimSecurityAttribute[] ResourceAttribute { get; set; }

    private NtToken GetToken()
    {
        if (Token?.IsPseudoToken ?? false)
            return Token;
        return Token?.Duplicate() ?? NtToken.OpenEffectiveToken();
    }

    /// <summary>
    /// Process Record.
    /// </summary>
    protected override void ProcessRecord()
    {
        using var token = GetToken();
        var attributes = ResourceAttribute ?? new ClaimSecurityAttribute[0];
        switch (ParameterSetName)
        {
            case "FromSddl":
                WriteObject(NtSecurity.EvaluateConditionAce(token, Condition, attributes));
                break;
            case "FromData":
                WriteObject(NtSecurity.EvaluateConditionAce(token, ConditionData, attributes));
                break;
            case "FromAce":
                if (!Ace.IsConditionalAce)
                    throw new ArgumentException("Must specify a conditional ACE.");
                WriteObject(NtSecurity.EvaluateConditionAce(token, Ace.ApplicationData, attributes));
                break;
        }
    }
}
