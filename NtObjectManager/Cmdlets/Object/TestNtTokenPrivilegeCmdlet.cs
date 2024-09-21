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
/// <para type="synopsis">Checks for enabled privileges in a token.</para>
/// <para type="description">This cmdlet does a privilege check for a token. The default it to pass a boolean indicating the privilege enable state.
/// You can specify PassResult to get the full result information.</para>
/// </summary>
/// <example>
///   <code>Test-NtTokenPrivilege SeTcbPrivilege</code>
///   <para>Checks if the current effective token has SeTcbPrivilege enabled.</para>
/// </example>
/// <example>
///   <code>Test-NtTokenPrivilege SeTcbPrivilege,SeDebugPrivilege</code>
///   <para>Checks if the current effective token has either SeTcbPrivilege or SeDebugPrivilege enabled.</para>
/// </example>
/// <example>
///   <code>Test-NtTokenPrivilege SeTcbPrivilege,SeDebugPrivilege -All</code>
///   <para>Checks if the current effective token has SeTcbPrivilege and SeDebugPrivilege enabled.</para>
/// </example>
/// <example>
///   <code>Test-NtTokenPrivilege SeTcbPrivilege,SeDebugPrivilege -PassResult</code>
///   <para>Checks if the current effective token has SeTcbPrivilege and SeDebugPrivilege enabled and pass on a result rather than just a boolean.</para>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "NtTokenPrivilege")]
[OutputType(typeof(bool), typeof(PrivilegeCheckResult))]
public sealed class TestNtTokenPrivilegeCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the token to test. If not specified uses the current effective token.</para>
    /// </summary>
    [Parameter]
    public NtToken Token { get; set; }

    /// <summary>
    /// <para type="description">Specify an optional thread to test on.</para>
    /// </summary>
    [Parameter(Position = 0, ParameterSetName = "FromPrivilegeValue")]
    public TokenPrivilegeValue[] PrivilegeValue { get; set; }

    /// <summary>
    /// <para type="description">Specify that all the privileges are required.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter All { get; set; }

    /// <summary>
    /// <para type="description">Specify to pass through the full check result, otherwise just return a boolean which indicates
    /// whether the check succeeded.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter PassResult { get; set; }

    private NtToken GetToken()
    {
        if (Token != null)
        {
            if (Token.IsPseudoToken)
                return Token;
            return Token.Duplicate(TokenAccessRights.Query);
        }
        return NtToken.OpenEffectiveToken();
    }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        using var token = GetToken();
        var result = token.PrivilegeCheck(PrivilegeValue, All);
        if (PassResult)
            WriteObject(result);
        else
            WriteObject(result.AllPrivilegesHeld);
    }
}
