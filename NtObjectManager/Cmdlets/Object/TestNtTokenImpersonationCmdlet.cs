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
using NtCoreLib.Security.Token;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Checks if an NT Token can be impersonated.</para>
/// <para type="description">This cmdlet impersonates an NT Token and checks if the impersonation level matches.</para>
/// </summary>
/// <example>
///   <code>Test-NtTokenImpersonation -Token $token</code>
///   <para>Checks if the token can be impersonated at impersonation level.</para>
/// </example>
/// <example>
///   <code>Test-NtTokenImpersonation -Token $token -ImpersonationLevel Identification</code>
///   <para>Checks if the token can be impersonated at identification level.</para>
/// </example>
/// <example>
///   <code>Test-NtTokenImpersonation -Token $token -PassThru</code>
///   <para>Impersonates the token and passes through the impersonated token.</para>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "NtTokenImpersonation")]
public sealed class TestNtTokenImpersonationCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the token to test.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public NtToken Token { get; set; }

    /// <summary>
    /// <para type="description">Specify an optional thread to test on.</para>
    /// </summary>
    [Parameter(Position = 1)]
    public NtThread Thread { get; set; }

    /// <summary>
    /// <para type="description">Pass through the impersonated Token rather than returning a boolean.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter PassThru { get; set; }

    /// <summary>
    /// <para type="description">Specify the level of impersonation to check.</para>
    /// </summary>
    [Parameter]
    public SecurityImpersonationLevel ImpersonationLevel { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public TestNtTokenImpersonationCmdlet()
    {
        ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
    }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        using var token = Token.DuplicateToken(ImpersonationLevel);
        var thread = Thread ?? NtThread.Current;
        using var imp = thread.Impersonate(token);
        using var new_token = NtToken.OpenThreadToken(thread);
        if (PassThru)
        {
            WriteObject(new_token.Duplicate());
        }
        else
        {
            WriteObject(ImpersonationLevel == new_token.ImpersonationLevel);
        }
    }
}
