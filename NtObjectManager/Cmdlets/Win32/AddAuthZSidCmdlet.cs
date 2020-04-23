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

using NtApiDotNet;
using NtApiDotNet.Win32.Security.Authorization;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Win32
{
    /// <summary>
    /// <para type="synopsis">Adds a SID to the AuthZ context..</para>
    /// <para type="description">This cmdlet allows you to add SIDs to an AuthZ context. You can specify
    /// normal, restricted or device SIDs.</para>
    /// </summary>
    /// <example>
    ///   <code>Add-AuthZSid $ctx -Sid "WD"</code>
    ///   <para>Add the World SID to the normal groups in the context.</para>
    /// </example>
    /// <example>
    ///   <code>Add-AuthZSid $ctx -Sid "WD" -SidType Restricted</code>
    ///   <para>Add the World SID to the restricted SID groups in the context.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Add, "AuthZSid")]
    public class AddAuthZSidCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the AuthZ Client Context.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public AuthZContext Context { get; set; }

        /// <summary>
        /// <para type="description">Specify the Sids to Add.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 1)]
        public Sid[] Sid { get; set; }

        /// <summary>
        /// <para type="description">Specify the the type of SIDs to add.</para>
        /// </summary>
        [Parameter(Position = 2)]
        public AuthZGroupSidType SidType { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public AddAuthZSidCmdlet()
        {
            SidType = AuthZGroupSidType.Normal;
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            Context.ModifyGroups(SidType, Sid, AuthZSidOperation.Add);
        }
    }
}
