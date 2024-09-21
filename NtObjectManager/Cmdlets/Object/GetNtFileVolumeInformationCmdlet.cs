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
using NtCoreLib.Native.SafeBuffers;
using System;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Call QueryVolume on a file.</para>
/// <para type="description">This cmdlet queries volume information from an file handle.
/// </para>
/// </summary>
/// <example>
///   <code>Get-NtFileVolumeInformation -File $file -InformationClass FileFsVolumeInformation</code>
///   <para>Query the info class for the object.</para>
/// </example>
/// <example>
///   <code>Get-NtFileVolumeInformation -Object $obj -InformationClass FileFsVolumeInformation -InitBuffer @(1, 2, 3, 4)</code>
///   <para>Query the info class providing an initial buffer as bytes.</para>
/// </example>
/// <example>
///   <code>Get-NtFileVolumeInformation -Object $obj -InformationClass FileFsVolumeInformation -Length 16</code>
///   <para>Query the info class providing an initial 16 byte buffer.</para>
/// </example>
/// <example>
///   <code>Get-NtFileVolumeInformation -Object $obj -InformationClass FileFsVolumeInformation -AsBuffer</code>
///   <para>Query the info class and return a safe buffer.</para>
/// </example>
/// /// <example>
///   <code>Get-NtFileVolumeInformation -Object $obj -InformationClass FileFsVolumeInformation -AsType $type</code>
///   <para>Query the info class and a typed value. $type needs to be a blitable .NET type.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "NtFileVolumeInformation", DefaultParameterSetName = "QueryBytes")]
[OutputType(typeof(byte[]))]
[OutputType(typeof(SafeBufferGeneric))]
public sealed class GetNtFileVolumeInformationCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the file to query information from.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0)]
    public NtFile File { get; set; }

    /// <summary>
    /// <para type="description">Specify the information class to query.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1)]
    public FsInformationClass InformationClass { get; set; }

    /// <summary>
    /// <para type="description">Return the result as a buffer rather than a byte array.</para>
    /// </summary>
    [Parameter(ParameterSetName = "QueryBuffer")]
    public SwitchParameter AsBuffer { get; set; }

    /// <summary>
    /// <para type="description">Return the result as a type rather than a byte array. Also uses type size for initial sizing.</para>
    /// </summary>
    [Parameter(ParameterSetName = "Type")]
    public Type AsType { get; set; }

    /// <summary>
    /// <para type="description">Specify initial value as a byte array.</para>
    /// </summary>
    [Parameter]
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
        using var buffer = File.QueryVolumeBuffer(InformationClass, GetInitialBuffer());
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
