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
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Sets a registry key value.</para>
/// <para type="description">This cmdlet sets a registry key value on a specific key.</para>
/// </summary>
/// <example>
///   <code>Set-NtKeyValue -Key $key -String "Hello"</code>
///   <para>Sets the default value to the string "Hello".</para>
/// </example>
/// <example>
///   <code>Set-NtKeyValue -Key $key -Name ABC -MultiString "Hello","World!"</code>
///   <para>Sets the value ABC to the multi-string "Hello" and "World!".</para>
/// </example>
/// <example>
///   <code>Set-NtKeyValue -Key $key -Name ABC -ValueType Binary -Bytes @(1, 2, 3, 4)</code>
///   <para>Sets the value ABC to the binary data value.</para>
/// </example>
[Cmdlet(VerbsCommon.Set, "NtKeyValue")]
public class SetNtKeyValueCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">The key to set the value on.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0)]
    public NtKey Key { get; set; }

    /// <summary>
    /// <para type="description">The name of the value to set. If not specified it will set the default value.</para>
    /// </summary>
    [Parameter(Position = 1)]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">Specify the value as a string.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromString")]
    public string String { get; set; }

    /// <summary>
    /// <para type="description">Specify the value as an expanded string.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromExpandString")]
    public string ExpandString { get; set; }

    /// <summary>
    /// <para type="description">Specify the value as a string.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromMultiString")]
    public string[] MultiString { get; set; }

    /// <summary>
    /// <para type="description">Specify the value type when using bytes.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromBytes")]
    [Parameter(ParameterSetName = "FromString")]
    public RegistryValueType ValueType { get; set; }

    /// <summary>
    /// <para type="description">Specify the value as an array of bytes.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromBytes")]
    public byte[] Bytes { get; set; }

    /// <summary>
    /// <para type="description">Specify the value as a dword.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromDword")]
    public uint Dword { get; set; }

    /// <summary>
    /// <para type="description">Specify whether to set the dword as big endian or little endian.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromDword")]
    public SwitchParameter BigEndian { get; set; }

    /// <summary>
    /// <para type="description">Specify the value as a qword.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromQword")]
    public ulong Qword { get; set; }

    /// <summary>
    /// <para type="description">Specify the value from an existing NtKeyValue. The name is ignored.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromValue")]
    public NtKeyValue Value { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        switch (ParameterSetName)
        {
            case "FromString":
                if (ValueType == RegistryValueType.None)
                {
                    Key.SetValue(Name, String);
                }
                else
                {
                    Key.SetValue(Name, ValueType, String);
                }
                break;
            case "FromExpandString":
                Key.SetValue(Name, RegistryValueType.ExpandString, ExpandString);
                break;
            case "FromMultiString":
                Key.SetValue(Name, MultiString);
                break;
            case "FromBytes":
                if (ValueType == RegistryValueType.None)
                {
                    ValueType = RegistryValueType.Binary;
                }
                Key.SetValue(Name, ValueType, Bytes);
                break;
            case "FromDword":
                Key.SetValue(Name, BigEndian, Dword);
                break;
            case "FromQword":
                Key.SetValue(Name, Qword);
                break;
            case "FromValue":
                Key.SetValue(Name, Value.Type, Value.Data);
                break;
            default:
                throw new ArgumentException("Invalid type specified");
        }
    }
}
