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

using NtApiDotNet;
using System;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Wait on one or more NT objects to become signalled.</para>
    /// <para type="description">This cmdlet allows you to issue a wait on one or more NT objects until they become signalled.
    /// This is used for example to acquire a Mutant, decrement a Semaphore or wait for a Process to exit. The timeout
    /// value is a combination of all the allowed time parameters, e.g. if you specify 1 second and 1000 milliseconds it will
    /// actually wait 2 seconds in total. Specifying -Infinite overrides the time parameters and will wait indefinitely.</para>
    /// </summary>
    /// <example>
    ///   <code>$ev = Get-NtEvent \BaseNamedObjects\ABC&#x0A;Start-NtWait $ev -Seconds 10</code>
    ///   <para>Get an event and wait for 10 seconds for it to be signalled.</para>
    /// </example>
    /// <example>
    ///   <code>$ev = Get-NtEvent \BaseNamedObjects\ABC&#x0A;$ev | Start-NtWait -Infinite</code>
    ///   <para>Get an event and wait indefinitely for it to be signalled.</para>
    /// </example>
    /// <example>
    ///   <code>$ev = Get-NtEvent \BaseNamedObjects\ABC&#x0A;$ev | Start-NtWait -Infinite -Alertable</code>
    ///   <para>Get an event and wait indefinitely for it to be signalled or alerted.</para>
    /// </example>
    /// <example>
    ///   <code>$evs = @($ev1, $ev2)$&#x0A;Start-NtWait $evs -WaitAll -Seconds 100</code>
    ///   <para>Get a list of events and wait 100 seconds for all events to be signalled.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet("Start", "NtWait")]
    [OutputType(typeof(NtStatus))]
    public class StartNtObjectWait : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify a list of objects to wait on.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ValueFromPipeline = true)]
        public NtObject[] Objects { get; set; }

        /// <summary>
        /// <para type="description">Specify a wait time in seconds.</para>
        /// </summary>
        [Parameter]
        [Alias(new string[] { "s" })]
        public int Seconds { get; set; }

        /// <summary>
        /// <para type="description">Specify a wait time in milliseconds.</para>
        /// </summary>
        [Parameter]
        [Alias(new string[] { "ms" })]
        public long MilliSeconds { get; set; }

        /// <summary>
        /// <para type="description">Specify a wait time in minutes.</para>
        /// </summary>
        [Parameter]
        [Alias(new string[] { "m" })]
        public int Minutes { get; set; }

        /// <summary>
        /// <para type="description">Specify a wait time in hours.</para>
        /// </summary>
        [Parameter]
        [Alias(new string[] { "h" })]
        public int Hours { get; set; }

        /// <summary>
        /// <para type="description">Specify an infinite wait time.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Infinite { get; set; }

        /// <summary>
        /// <para type="description">Specify the wait should be alertable.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Alertable { get; set; }

        /// <summary>
        /// <para type="description">Specify a multiple object wait should exit only when all objects becomes signalled.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter WaitAll { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (Objects == null || Objects.Length == 0)
            {
                throw new ArgumentException("Must specify at least one object to wait on.");
            }

            NtWaitTimeout timeout = null;

            if (Infinite)
            {
                timeout = NtWaitTimeout.Infinite;
            }
            else
            {
                long total_timeout = MilliSeconds + ((((Hours * 60L) + Minutes) * 60L) + Seconds) * 1000L;
                if (total_timeout < 0)
                {
                    throw new ArgumentException("Total timeout can't be negative.");
                }

                timeout = NtWaitTimeout.FromMilliseconds(total_timeout);
            }

            if (Objects.Length == 1)
            {
                WriteObject(Objects[0].Wait(Alertable, timeout));
            }
            else
            {
                WriteObject(NtWait.Wait(Objects, Alertable, WaitAll, timeout));
            }
        }
    }
}
