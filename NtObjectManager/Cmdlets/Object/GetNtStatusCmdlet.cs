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
using NtCoreLib.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// The result of an NTSTATUS code lookup.
/// </summary>
public sealed class NtStatusResult
{
    /// <summary>
    /// The numeric value of the status code.
    /// </summary>
    public uint Status { get; }
    /// <summary>
    /// The numeric value of the status code as a signed integer.
    /// </summary>
    public int StatusSigned => (int)Status;
    /// <summary>
    /// The name of the status code if known.
    /// </summary>
    public string StatusName { get; }
    /// <summary>
    /// Corresponding message text.
    /// </summary>
    public string Message { get; }
    /// <summary>
    /// Win32 error code.
    /// </summary>
    public Win32Error Win32Error { get; }
    /// <summary>
    /// Win32 error as an integer.
    /// </summary>
    public int Win32ErrorCode => (int)Win32Error;
    /// <summary>
    /// The status code.
    /// </summary>
    public int Code { get; }
    /// <summary>
    /// True if a customer code.
    /// </summary>
    public bool CustomerCode { get; }
    /// <summary>
    /// True if reserved.
    /// </summary>
    public bool Reserved { get; }
    /// <summary>
    /// The status facility.
    /// </summary>
    public NtStatusFacility Facility { get; }
    /// <summary>
    /// The status severity.
    /// </summary>
    public NtStatusSeverity Severity { get; }

    internal NtStatusResult(NtStatus status)
    {
        Status = (uint)status;

        Message = NtObjectUtils.GetNtStatusMessage(status);
        Win32Error = NtObjectUtils.MapNtStatusToDosError(status);
        StatusName = status.ToString();
        Code = status.GetStatusCode();
        CustomerCode = status.IsCustomerCode();
        Reserved = status.IsReserved();
        Facility = status.GetFacility();
        Severity = status.GetSeverity();
    }

    internal NtStatusResult(int status)
        : this(NtObjectUtils.ConvertIntToNtStatus(status))
    {
    }
}

/// <summary>
/// <para type="synopsis">Get known information about an NTSTATUS code.</para>
/// <para type="description">This cmdlet looks up an NTSTATUS code and if possible prints the
/// enumeration name, the message description and the corresponding win32 error.
/// </para>
/// </summary>
/// <example>
///   <code>Get-NtStatus</code>
///   <para>Gets all known NTSTATUS codes defined in this library.</para>
/// </example>
/// <example>
///   <code>Get-NtStatus -Status 0xC0000022</code>
///   <para>Gets information about a specific status code.</para>
/// </example>
/// <example>
///   <code>Get-NtStatus -Name "STATUS_ACCESS_DENIED"</code>
///   <para>Gets information about a specific status code.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "NtStatus", DefaultParameterSetName = "All")]
public sealed class GetNtStatusCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify a NTSTATUS code to retrieve.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromStatus")]
    public int Status { get; set; }

    /// <summary>
    /// <para type="description">Specify the name of a Status Code to retrieve.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromName")]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">Pass the NtStatus enumeration rather than the status information.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter PassStatus { get; set; }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (ParameterSetName == "FromStatus")
        {
            if (PassStatus)
            {
                WriteObject(NtObjectUtils.ConvertIntToNtStatus(Status));
            }
            else
            {
                WriteObject(new NtStatusResult(Status));
            }
        }
        else if (ParameterSetName == "FromName")
        {
            var result = GetAllStatus().Where(s => s.ToString().Equals(Name, StringComparison.OrdinalIgnoreCase));
            if (!result.Any())
                throw new ArgumentException($"Can't find status with name {Name}");
            var status = result.First();
            if (PassStatus)
            {
                WriteObject(status);
            }
            else
            {
                WriteObject(new NtStatusResult(status));
            }
        }
        else
        {
            var status = GetAllStatus();
            if (PassStatus)
            {
                WriteObject(status, true);
            }
            else
            {
                WriteObject(GetAllStatus().Select(s => new NtStatusResult(s)), true);
            }
        }
    }

    private static IEnumerable<NtStatus> GetAllStatus()
    {
        return Enum.GetValues(typeof(NtStatus)).Cast<NtStatus>().Distinct();
    }
}
