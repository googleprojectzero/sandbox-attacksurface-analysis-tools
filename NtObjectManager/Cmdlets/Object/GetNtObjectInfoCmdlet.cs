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
using NtCoreLib.Native.SafeBuffers;
using NtObjectManager.Utils;
using System;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Call QueryInformation on the object type.</para>
/// <para type="description">This cmdlet queries information from an object handle. You specify the information class by name or number.
/// </para>
/// </summary>
/// <example>
///   <code>Get-NtObjectInformation -Object $obj -InformationClass BasicInfo</code>
///   <para>Query the basic info class for the object.</para>
/// </example>
/// <example>
///   <code>Get-NtObjectInformation -Object $obj -InformationClass 1</code>
///   <para>Query the info class 1 for the object.</para>
/// </example>
/// <example>
///   <code>Get-NtObjectInformation -Object $obj -InformationClass BasicInfo -InitBuffer @(1, 2, 3, 4)</code>
///   <para>Query the basic info class providing an initial buffer as bytes.</para>
/// </example>
/// <example>
///   <code>Get-NtObjectInformation -Object $obj -InformationClass BasicInfo -Length 16</code>
///   <para>Query the basic info class providing an initial 16 byte buffer.</para>
/// </example>
/// <example>
///   <code>Get-NtObjectInformation -Object $obj -InformationClass BasicInfo -AsBuffer</code>
///   <para>Query the basic info class and return a safe buffer.</para>
/// </example>
/// /// <example>
///   <code>Get-NtObjectInformation -Object $obj -InformationClass BasicInfo -AsType $type</code>
///   <para>Query the basic info class and a typed value. $type needs to be a blitable .NET type.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "NtObjectInformation", DefaultParameterSetName = "QueryBytes")]
[OutputType(typeof(byte[]))]
[OutputType(typeof(SafeBufferGeneric))]
public sealed class GetNtObjectInfoCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the object to query information from.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0)]
    public NtObject Object { get; set; }

    /// <summary>
    /// <para type="description">Specify the information class to query. Can be a string or an integer.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1)]
    [ArgumentCompleter(typeof(QueryInfoClassCompleter))]
    public string InformationClass { get; set; }

    /// <summary>
    /// <para type="description">Return the result as a buffer rather than a byte array.</para>
    /// </summary>
    [Parameter(ParameterSetName = "QueryBuffer")]
    public SwitchParameter AsBuffer { get; set; }

    /// <summary>
    /// <para type="description">Return the result as a type rather than a byte array. Also uses type size for initial sizing.</para>
    /// </summary>
    [Parameter(ParameterSetName = "QueryType")]
    public Type AsType { get; set; }

    /// <summary>
    /// <para type="description">Return the result as a type rather than a byte array. Also uses type size for initial sizing.</para>
    /// </summary>
    [Parameter(ParameterSetName = "QueryObject")]
    public SwitchParameter AsObject { get; set; }

    /// <summary>
    /// <para type="description">Specify initial value as a byte array.</para>
    /// </summary>
    [Parameter(ParameterSetName = "QueryBuffer")]
    [Parameter(ParameterSetName = "QueryType")]
    [Parameter(ParameterSetName = "QueryBytes")]
    public byte[] InitBuffer { get; set; }

    /// <summary>
    /// <para type="description">Specify initial value as an empty buffer of a specified length.</para>
    /// </summary>
    [Parameter]
    public int Length { get; set; }

    private byte[] GetInitialBuffer()
    {
        if (InitBuffer != null)
        {
            return InitBuffer;
        }
        else if (AsType != null)
        {
            return new byte[Marshal.SizeOf(AsType)];
        }
        return new byte[Length];
    }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        INtObjectQueryInformation query_info = (INtObjectQueryInformation)Object;
        int info_class;
        if (Object.NtType.QueryInformationClass.ContainsKey(InformationClass))
        {
            info_class = Object.NtType.QueryInformationClass[InformationClass];
        }
        else if (!int.TryParse(InformationClass, out info_class))
        {
            throw new ArgumentException($"Invalid info class {InformationClass}");
        }

        if (AsObject)
        {
            WriteObject(query_info.QueryObject(info_class, true).Result);
        }
        else
        {
            using var buffer = query_info.QueryBuffer(info_class, GetInitialBuffer(), true).Result;
            if (AsBuffer)
            {
                WriteObject(buffer.Detach());
            }
            else if (AsType != null)
            {
                WriteObject(Marshal.PtrToStructure(buffer.DangerousGetHandle(), AsType));
            }
            else
            {
                WriteObject(buffer.ToArray());
            }
        }
    }
}
