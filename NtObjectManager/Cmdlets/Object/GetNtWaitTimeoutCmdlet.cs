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
/// <para type="synopsis">Get a wait timeout which represents a specific time.</para>
/// <para type="description">This cmdlet gets an NtWaitTimeout which can be passed to other calls. The timeout
/// value is a combination of all the allowed time parameters, e.g. if you specify 1 second and 1000 milliseconds it will
/// actually wait 2 seconds in total. Specifying -Infinite will get cause a wait to stop indefinitely.</para>
/// </summary>
/// <example>
///   <code>$to = Get-NtWaitTimeout -Seconds 10</code>
///   <para>Get a wait timeout represent 10 seconds.</para>
/// </example>
/// <example>
///   <code>$to = Get-NtWaitTimeout Infinite</code>
///   <para>Get a wait timeout representing infinity.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "NtWaitTimeout")]
[OutputType(typeof(NtStatus))]
public class GetNtWaitTimeoutCmdlet : Cmdlet
{
    /// <summary>
    /// <para type="description">Specify a wait time in seconds.</para>
    /// </summary>
    [Parameter(ParameterSetName = "time")]
    [Alias("s", "Seconds")]
    public int Second { get; set; }

    /// <summary>
    /// <para type="description">Specify a wait time in milliseconds.</para>
    /// </summary>
    [Parameter(ParameterSetName = "time")]
    [Alias("ms", "MilliSeconds")]
    public long MilliSecond { get; set; }

    /// <summary>
    /// <para type="description">Specify a wait time in minutes.</para>
    /// </summary>
    [Parameter(ParameterSetName = "time")]
    [Alias("m", "Minutes")]
    public int Minute { get; set; }

    /// <summary>
    /// <para type="description">Specify a wait time in hours.</para>
    /// </summary>
    [Parameter(ParameterSetName = "time")]
    [Alias("h", "Hours")]
    public int Hour { get; set; }

    /// <summary>
    /// <para type="description">Specify an infinite wait time.</para>
    /// </summary>
    [Parameter(ParameterSetName = "infinite")]
    public SwitchParameter Infinite { get; set; }

    /// <summary>
    /// Get the NtWaitTimeout object.
    /// </summary>
    /// <returns>The NtWaitTime object.</returns>
    protected NtWaitTimeout GetTimeout()
    {
        if (Infinite)
        {
            return NtWaitTimeout.Infinite;
        }

        long total_timeout = MilliSecond + ((((Hour * 60L) + Minute) * 60L) + Second) * 1000L;
        if (total_timeout < 0)
        {
            throw new ArgumentException("Total timeout can't be negative.");
        }

        return NtWaitTimeout.FromMilliseconds(total_timeout);
    }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        WriteObject(GetTimeout());
    }
}
