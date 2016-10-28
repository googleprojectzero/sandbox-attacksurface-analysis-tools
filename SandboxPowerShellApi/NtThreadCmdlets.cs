//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using NtApiDotNet;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Get NT threads.</para>
    /// <para type="description">This cmdlet gets all accessible threads on the system. You can specify a specific thread by setting the -ThreadId parameter.</para>
    /// <para>Note that thread objects need to be disposed of after use, therefore capture them in a Dispose List or manually Close them once used.</para>
    /// </summary>
    /// <example>
    ///   <code>$ts = Get-NtThread | Push-NtDisposeList</code>
    ///   <para>Get all NT threads accessible by the current user and put then in a dispose list.</para>
    /// </example>
    /// <example>
    ///   <code>$ts = Get-NtThread -Access Impersonate</code>
    ///   <para>Get all NT threads accessible by the current user for impersonate access.</para>
    /// </example>
    /// <example>
    ///   <code>$t = Get-NtThread 1234</code>
    ///   <para>Get a specific thread.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtThread")]
    [OutputType(typeof(NtThread))]
    public class GetNtThreadCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify a thread ID to open.</para>
        /// </summary>
        [Parameter(Position = 0)]
        public int ThreadId { get; set; }

        /// <summary>
        /// <para type="description">Specify access rights for each thread opened.</para>
        /// </summary>
        [Parameter]
        public ThreadAccessRights Access { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public GetNtThreadCmdlet()
        {
            Access = ThreadAccessRights.MaximumAllowed;
            ThreadId = -1;
        }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (ThreadId == -1)
            {
                WriteObject(NtThread.GetThreads(Access));
            }
            else
            {
                WriteObject(NtThread.Open(ThreadId, Access));
            }
        }
    }
}
