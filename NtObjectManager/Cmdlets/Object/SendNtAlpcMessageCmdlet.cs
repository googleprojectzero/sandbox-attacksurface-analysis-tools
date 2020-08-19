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
    /// <para type="synopsis">Sends a message on an ALPC port and optionally receives one as well.</para>
    /// <para type="description">This cmdlet sends a message on an ALPC port and optionally receives ones.</para>
    /// </summary>
    /// <example>
    ///   <code>Send-NtAlpcMessage -Port $port -Message $msg</code>
    ///   <para>Send a message on a port.</para>
    /// </example>
    /// <example>
    ///   <code>$recv_msg = Send-NtAlpcMessage -Port $port -Message $msg -ReceiveLength 80 -Flags SyncMessage</code>
    ///   <para>Send a message on a port and waits for a message of up to 80 bytes.</para>
    /// </example>
    /// <example>
    ///   <code>Send-NtAlpcMessage -Port $port -Bytes @(0, 1, 2, 3)</code>
    ///   <para>Send a message on a port from a byte array.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommunications.Send, "NtAlpcMessage", DefaultParameterSetName = "FromMsg")]
    [OutputType(typeof(AlpcMessage))]
    public class SendNtAlpcMessageCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the port to send the message on.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public NtAlpc Port { get; set; }

        /// <summary>
        /// <para type="description">Specify message to send from a byte array.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromBytes")]
        public byte[] Bytes { get; set; }

        /// <summary>
        /// <para type="description">Specify message to send.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromMsg")]
        public AlpcMessage Message { get; set; }

        /// <summary>
        /// <para type="description">Specify send flags.</para>
        /// </summary>
        [Parameter]
        public AlpcMessageFlags Flags { get; set; }

        /// <summary>
        /// <para type="description">Specify send attributes.</para>
        /// </summary>
        [Parameter]
        public AlpcSendMessageAttributes SendAttributes { get; set; }

        /// <summary>
        /// <para type="description">Specify optional timeout in MS.</para>
        /// </summary>
        [Parameter]
        public long? TimeoutMs { get; set; }

        /// <summary>
        /// <para type="description">Specify optional length of message to receive.</para>
        /// </summary>
        [Parameter]
        public int? ReceiveLength { get; set; }

        /// <summary>
        /// <para type="description">Specify receive attributes.</para>
        /// </summary>
        [Parameter]
        public AlpcReceiveMessageAttributes ReceiveAttributes { get; set; }

        private AlpcMessage CreateReceiveMessage()
        {
            if (ReceiveLength.HasValue)
            {
                return new AlpcMessageRaw(ReceiveLength.Value);
            }
            return null;
        }

        private AlpcMessage Send(AlpcMessage msg)
        {
            NtWaitTimeout timeout = TimeoutMs.HasValue
                ? NtWaitTimeout.FromMilliseconds(TimeoutMs.Value) : NtWaitTimeout.Infinite;
            var recv_message = CreateReceiveMessage();
            if (!Port.SendReceive(Flags, msg, SendAttributes, recv_message, recv_message != null ? ReceiveAttributes : null, timeout))
            {
                WriteWarning("SendReceive timed out.");
                return null;
            }
            return recv_message;
            
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public SendNtAlpcMessageCmdlet()
        {
            Flags = AlpcMessageFlags.ReleaseMessage;
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (ParameterSetName == "FromBytes")
            {
                WriteObject(Send(new AlpcMessageRaw(Bytes)));
            }
            else
            {
                WriteObject(Send(Message));
            }
        }
    }
}
