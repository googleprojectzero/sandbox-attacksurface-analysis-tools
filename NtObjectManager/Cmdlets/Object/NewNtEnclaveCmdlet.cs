//  Copyright 2023 Google LLC. All Rights Reserved.
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
using NtCoreLib.Win32.Security.Authenticode;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Create a new enclave.</para>
/// <para type="description">This cmdlet creates a new enclave.</para>
/// </summary>
/// <example>
///   <code>$ev = New-NtEnclave -ImageFile "secure.dll"</code>
///   <para>Create a VBS enclave in the current process.</para>
/// </example>
[Cmdlet(VerbsCommon.New, "NtEnclave")]
[OutputType(typeof(NtEnclave))]
public class NewNtEnclaveCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify to process to create the enclave in.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromVBS")]
    public NtProcess Process { get; set; }

    /// <summary>
    /// <para type="description">Specify the VBS enclave flags.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromVBS")]
    public LdrEnclaveVBSFlags VBSFlags { get; set; }

    /// <summary>
    /// <para type="description">Specify the VBS enclave owner ID.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromVBS")]
    public byte[] OwnerId { get; set; }

    /// <summary>
    /// <para type="description">Specify the primary image file to load in the enclave.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromVBS")]
    public string ImageFile { get; set; }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        var config = AuthenticodeUtils.GetEnclaveConfiguration(ImageFile);

        if (Process == null)
        {
            Process = NtProcess.Current;
        }

        var enclave = Process.CreateEnclaveVBS(config.EnclaveSize, VBSFlags, OwnerId);
        try
        {
            enclave.LoadModule(ImageFile, IntPtr.Zero);
            enclave.Initialize(config.NumberOfThreads);
            WriteObject(enclave);
        }
        catch
        {
            enclave?.Dispose();
            throw;
        }
    }
}
