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
using System.Management.Automation;
using System.Linq;
using NtCoreLib.Security.Token;
using NtCoreLib.Utilities.Token;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Removes security attributes on an NT token.</para>
/// <para type="description">This cmdlet removes security attributes on an NT token. It needs SeTcbPrivilege to succeed.</para>
/// </summary>
/// <example>
///   <code>Remove-NtTokenSecurityAttribute -Token $token -Name "TEST://ME"</code>
///   <para>Removes the security attribute TEST://ME.</para>
/// </example>
[Cmdlet(VerbsCommon.Remove, "NtTokenSecurityAttribute")]
public sealed class RemoveNtTokenSecurityAttributeCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the token to set the attributes on.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public NtToken Token { get; set; }

    /// <summary>
    /// <para type="description">Specify the name of the attributes to remove.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromName")]
    public string[] Name { get; set; }

    /// <summary>
    /// <para type="description">Specify existing attribute values.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromAttribute")]
    public ClaimSecurityAttribute[] Attribute { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (Attribute != null)
        {
            Name = Attribute.Select(a => a.Name).ToArray();
        }
        
        var builders = Name.Select(n => ClaimSecurityAttributeBuilder.Create(n, 0, new long[0]));
        var ops = Enumerable.Repeat(TokenSecurityAttributeOperation.Delete, Name.Length);
        Token.SetSecurityAttributes(builders, ops);
    }
}
