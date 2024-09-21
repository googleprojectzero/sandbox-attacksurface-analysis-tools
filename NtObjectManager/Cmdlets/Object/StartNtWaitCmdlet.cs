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
/// <para type="synopsis">Wait on one or more NT objects to become signaled.</para>
/// <para type="description">This cmdlet allows you to issue a wait on one or more NT objects until they become signaled.
/// This is used for example to acquire a Mutant, decrement a Semaphore or wait for a Process to exit. The timeout
/// value is a combination of all the allowed time parameters, e.g. if you specify 1 second and 1000 milliseconds it will
/// wait 2 seconds in total. Specifying -Infinite overrides the time parameters and will wait indefinitely.</para>
/// </summary>
/// <example>
///   <code>$ev = Get-NtEvent \BaseNamedObjects\ABC&#x0A;Start-NtWait $ev -Second 10</code>
///   <para>Get an event and wait for 10 seconds for it to be signaled.</para>
/// </example>
/// <example>
///   <code>$ev = Get-NtEvent \BaseNamedObjects\ABC&#x0A;$ev | Start-NtWait -Infinite</code>
///   <para>Get an event and wait indefinitely for it to be signaled.</para>
/// </example>
/// <example>
///   <code>$ev = Get-NtEvent \BaseNamedObjects\ABC&#x0A;$ev | Start-NtWait -Infinite -Alertable</code>
///   <para>Get an event and wait indefinitely for it to be signaled or alerted.</para>
/// </example>
/// <example>
///   <code>$evs = @($ev1, $ev2)$&#x0A;Start-NtWait $evs -WaitAll -Second 100</code>
///   <para>Get a list of events and wait 100 seconds for all events to be signaled.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsLifecycle.Start, "NtWait")]
[OutputType(typeof(NtStatus))]
public class StartNtWaitCmdlet : GetNtWaitTimeoutCmdlet
{
    /// <summary>
    /// <para type="description">Specify a list of objects to wait on.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ValueFromPipeline = true)]
    [Alias("Objects")]
    public NtObject[] Object { get; set; }

    /// <summary>
    /// <para type="description">Specify the wait should be alertable.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Alertable { get; set; }

    /// <summary>
    /// <para type="description">Specify a multiple object wait should exit only when all objects becomes signaled.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter WaitAll { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (Object == null || Object.Length == 0)
        {
            throw new ArgumentException("Must specify at least one object to wait on.");
        }

        NtWaitTimeout timeout = GetTimeout();

        if (Object.Length == 1)
        {
            WriteObject(Object[0].Wait(Alertable, timeout));
        }
        else
        {
            WriteObject(NtWait.Wait(Object, Alertable, WaitAll, timeout));
        }
    }
}
