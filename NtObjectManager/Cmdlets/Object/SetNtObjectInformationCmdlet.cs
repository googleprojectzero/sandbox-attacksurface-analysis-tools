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
/// <para type="synopsis">Call SetInformation on the object type.</para>
/// <para type="description">This cmdlet sets information to an object handle. You specify the information class by name or number.
/// </para>
/// </summary>
/// <example>
///   <code>Set-NtObjectInformation -Object $obj -InformationClass BasicInfo -Bytes @(1, 2, 3, 4)</code>
///   <para>Set the basic info class for the object.</para>
/// </example>
/// <example>
///   <code>Set-NtObjectInformation -Object $obj -InformationClass 1 -Bytes @(1, 2, 3, 4)</code>
///   <para>Query the info class 1 for the object.</para>
/// </example>
[Cmdlet(VerbsCommon.Set, "NtObjectInformation", DefaultParameterSetName = "SetBytes")]
public sealed class SetNtObjectInformationCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the object to set information to.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0)]
    public NtObject Object { get; set; }

    /// <summary>
    /// <para type="description">Specify the information class to set. Can be a string or an integer.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1)]
    [ArgumentCompleter(typeof(QueryInfoClassCompleter))]
    public string InformationClass { get; set; }

    /// <summary>
    /// <para type="description">Sets the buffer rather than a byte array.</para>
    /// </summary>
    [Parameter(ParameterSetName = "SetBytes")]
    public byte[] Bytes { get; set; }

    /// <summary>
    /// <para type="description">Sets the buffer rather than a byte array.</para>
    /// </summary>
    [Parameter(ParameterSetName = "SetBuffer")]
    public SafeBuffer Buffer { get; set; }

    /// <summary>
    /// <para type="description">Sets the information as a blittable value type.</para>
    /// </summary>
    [Parameter(ParameterSetName = "Type")]
    public object Value { get; set; }

    private SafeBuffer GetInitialBuffer()
    {
        if (Buffer != null)
        {
            return new SafeHGlobalBuffer(Buffer.DangerousGetHandle(), (int)Buffer.ByteLength, false);
        }
        else if (Bytes != null)
        {
            return new SafeHGlobalBuffer(Bytes);
        }
        else
        {
            using var buffer = new SafeHGlobalBuffer(Marshal.SizeOf(Value));
            Marshal.StructureToPtr(Value, buffer.DangerousGetHandle(), false);
            return buffer.Detach();
        }
    }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        INtObjectSetInformation set_info = (INtObjectSetInformation)Object;
        int info_class;
        if (Object.NtType.SetInformationClass.ContainsKey(InformationClass))
        {
            info_class = Object.NtType.SetInformationClass[InformationClass];
        }
        else if (!int.TryParse(InformationClass, out info_class))
        {
            throw new ArgumentException($"Invalid info class {InformationClass}");
        }

        using var buffer = GetInitialBuffer();
        set_info.SetBuffer(info_class, buffer, true);
    }
}
