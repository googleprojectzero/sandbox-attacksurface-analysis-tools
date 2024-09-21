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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="description">Choose the function to send the IO control code to.</para>
/// </summary>
public enum SendNtFileControlFunc
{
    /// <summary>
    /// Default, use FsControl for FSCTLs and DeviceIoControl for anything else.
    /// </summary>
    Default = 0,
    /// <summary>
    /// Only send to FsControl.
    /// </summary>
    FsControl,
    /// <summary>
    /// Only send to DeviceIoControl.
    /// </summary>
    DeviceIoControl
}

/// <summary>
/// <para type="synopsis">Sends a control code to a file.</para>
/// <para type="description">This cmdlet sends a control code to a file.</para>
/// </summary>
/// <example>
///   <code>Send-NtFileControl -File $file -ControlCode 1234 -Input @(1, 2, 3, 4) -OutputLength 100</code>
///   <para>Send the control code 1234 with input and a maximum output length of 100 bytes.</para>
/// </example>
/// <example>
///   <code>Send-NtFileControl -File $file -ControlCode 4567 -OutputLength 100</code>
///   <para>Send the control code 4567 with no input and a maximum output length of 100 bytes.</para>
/// </example>
/// <example>
///   <code>Send-NtFileControl -File $file -ControlCode 4567 -Input @(1, 2, 3, 4)</code>
///   <para>Send the control code 4567 with input and no output.</para>
/// </example>
/// <example>
///   <code>Send-NtFileControl -File $file -ControlCode 4567 -Input @(1, 2, 3, 4) -Function FsControl</code>
///   <para>Send the control code 4567 with input and no output. Always sends to FsControl regardless of the control code.</para>
/// </example>
[Cmdlet(VerbsCommunications.Send, "NtFileControl")]
[OutputType(typeof(byte[]))]
public class SendNtFileControlCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">The file object to send the control code to.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public NtFile File { get; set; }

    /// <summary>
    /// <para type="description">The control code to send.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true)]
    public NtIoControlCode ControlCode { get; set; }

    /// <summary>
    /// <para type="description">The input bytes to send.</para>
    /// </summary>
    [Parameter]
    public byte[] Input { get; set; }

    /// <summary>
    /// <para type="description">The number of bytes maximum to get from the output.</para>
    /// </summary>
    [Parameter]
    public int OutputLength { get; set; }

    /// <summary>
    /// <para type="description">Specify the IO control function to send to.</para>
    /// </summary>
    [Parameter]
    public SendNtFileControlFunc Function { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        byte[] result;

        if (Function == SendNtFileControlFunc.FsControl)
        {
            result = File.FsControl(ControlCode, Input, OutputLength);
        }
        else if (Function == SendNtFileControlFunc.DeviceIoControl)
        {
            result = File.DeviceIoControl(ControlCode, Input, OutputLength);
        }
        else if (ControlCode.DeviceType == FileDeviceType.FILE_SYSTEM)
        {
            result = File.FsControl(ControlCode, Input, OutputLength);
        }
        else
        {
            result = File.DeviceIoControl(ControlCode, Input, OutputLength);
        }

        if (result != null)
        {
            WriteObject(result, false);
        }
    }
}
