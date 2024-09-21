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
using NtCoreLib.Security.Token;
using NtCoreLib.Utilities.Token;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Creates a new security attribute.</para>
/// <para type="description">This cmdlet creates a new security attribute object.</para>
/// </summary>
/// <example>
///   <code>New-NtSecurityAttribute -Name "TEST://ME" -StringValue "ABC"</code>
///   <para>Creates the security attribute TEST://ME with the string value "ABC".</para>
/// </example>
/// <example>
///   <code>New-NtSecurityAttribute -Name "TEST://ME2" -LongValue 1,10,30,100</code>
///   <para>Creates the security attribute TEST://ME2 with the long values 1, 10, 30 and 100.</para>
/// </example>
[Cmdlet(VerbsCommon.New, "NtSecurityAttribute")]
[OutputType(typeof(ClaimSecurityAttribute))]
public sealed class NewNtSecurityAttributeCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the name of the attribute to add or update.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromString")]
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromULong")]
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromLong")]
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromBool")]
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromSid")]
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromFqbn")]
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromOctet")]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">Specify the attribute flags.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromString")]
    [Parameter(ParameterSetName = "FromULong")]
    [Parameter(ParameterSetName = "FromLong")]
    [Parameter(ParameterSetName = "FromBool")]
    [Parameter(ParameterSetName = "FromSid")]
    [Parameter(ParameterSetName = "FromFqbn")]
    [Parameter(ParameterSetName = "FromOctet")]
    public ClaimSecurityFlags Flags { get; set; }

    /// <summary>
    /// <para type="description">Specify the string values.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromString")]
    public string[] StringValue { get; set; }

    /// <summary>
    /// <para type="description">Specify the ulong values.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromULong")]
    public ulong[] ULongValue { get; set; }

    /// <summary>
    /// <para type="description">Specify the long values.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromLong")]
    public long[] LongValue { get; set; }

    /// <summary>
    /// <para type="description">Specify the bool values.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromBool")]
    public bool[] BoolValue { get; set; }

    /// <summary>
    /// <para type="description">Specify the SID values.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromSid")]
    public Sid[] SidValue { get; set; }

    /// <summary>
    /// <para type="description">Specify the fully qualified binary name values.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromFqbn")]
    public ClaimSecurityAttributeFqbn[] FqbnValue { get; set; }

    /// <summary>
    /// <para type="description">Specify the octet values.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromOctet")]
    public byte[][] OctetValue { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        WriteObject(CreateBuilder().ToAttribute());
    }

    private ClaimSecurityAttributeBuilder CreateBuilder()
    {
        if (StringValue != null)
        {
            return ClaimSecurityAttributeBuilder.Create(Name, Flags, StringValue);
        }
        else if (ULongValue != null)
        {
            return ClaimSecurityAttributeBuilder.Create(Name, Flags, ULongValue);
        }
        else if (LongValue != null)
        {
            return ClaimSecurityAttributeBuilder.Create(Name, Flags, LongValue);
        }
        else if (BoolValue != null)
        {
            return ClaimSecurityAttributeBuilder.Create(Name, Flags, BoolValue);
        }
        else if (SidValue != null)
        {
            return ClaimSecurityAttributeBuilder.Create(Name, Flags, SidValue);
        }
        else if (FqbnValue != null)
        {
            return ClaimSecurityAttributeBuilder.Create(Name, Flags, FqbnValue);
        }
        else if (OctetValue != null)
        {
            return ClaimSecurityAttributeBuilder.Create(Name, Flags, OctetValue);
        }

        throw new ArgumentException("Invalid security attribute type");
    }
}
