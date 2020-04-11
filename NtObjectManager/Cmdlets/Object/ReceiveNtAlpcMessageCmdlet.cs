//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// <para type="synopsis">Receives a message on an ALPC port.</para>
    /// <para type="description">This cmdlet receives a message on an ALPC port.</para>
    /// </summary>
    /// <example>
    ///   <code>$recv_msg = Receive-NtAlpcMessage -Port $port -ReceiveLength 80</code>
    ///   <para>Receive a message of up to 80 bytes.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommunications.Receive, "NtAlpcMessage")]
    public class ReceiveNtAlpcMessageCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the port to send the message on.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public NtAlpc Port { get; set; }

        /// <summary>
        /// <para type="description">Specify send flags.</para>
        /// </summary>
        [Parameter]
        public AlpcMessageFlags Flags { get; set; }

        /// <summary>
        /// <para type="description">Specify optional timeout in MS.</para>
        /// </summary>
        [Parameter]
        public long? TimeoutMs { get; set; }

        /// <summary>
        /// <para type="description">Specify the maximum length of message to receive.</para>
        /// </summary>
        [Parameter(Position = 1)]
        public int ReceiveLength { get; set; }

        /// <summary>
        /// <para type="description">Specify receive attributes.</para>
        /// </summary>
        [Parameter]
        public AlpcReceiveMessageAttributes ReceiveAttributes { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public ReceiveNtAlpcMessageCmdlet()
        {
            Flags = AlpcMessageFlags.ReleaseMessage;
            ReceiveLength = AlpcMessage.MaximumDataLength;
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            NtWaitTimeout timeout = TimeoutMs.HasValue
                ? NtWaitTimeout.FromMilliseconds(TimeoutMs.Value) : NtWaitTimeout.Infinite;

            var msg = Port.Receive(Flags, ReceiveLength, ReceiveAttributes, timeout);
            WriteObject(msg);
        }
    }
}
