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
using System;
using System.Management.Automation;
using System.Text;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Connects to an ALPC server by path.</para>
    /// <para type="description">This cmdlet connects to an existing NT ALPC server. The absolute path to the object in the NT object manager name space must be specified. 
    /// It's also possible to create the object relative to an existing object by specified the -Root parameter (if running on Win8+).</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Connect-NtAlpcClient "\RPC Control\ABC"</code>
    ///   <para>Connect to an ALPC object with an absolute path.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet("Connect", "NtAlpcClient", DefaultParameterSetName = "SidCheck")]
    [OutputType(typeof(NtAlpcClient))]
    public class ConnectNtAlpcClient : NtObjectBaseCmdlet
    {
        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected override bool CanCreateDirectories()
        {
            return false;
        }

        /// <summary>
        /// <para type="description">The NT object manager path to the object to use.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public override string Path { get; set; }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            if (ParameterSetName == "SidCheck")
            {
                return NtAlpcClient.Connect(Path, HandleObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage,
                    OutMessageAttributes, InMessageAttributes, Timeout);
            }
            else
            {
                return NtAlpcClient.Connect(obj_attributes, HandleObjectAttributes, PortAttributes, Flags, ServerSecurityRequirements, 
                    ConnectionMessage, OutMessageAttributes, InMessageAttributes, Timeout);
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public ConnectNtAlpcClient()
        {
            Flags = AlpcMessageFlags.SyncRequest;
        }

        /// <summary>
        /// <para type="description">Optional object attributes for the handle.</para>
        /// </summary>
        [Parameter]
        public ObjectAttributes HandleObjectAttributes { get; set; }

        /// <summary>
        /// <para type="description">Optional port attributes.</para>
        /// </summary>
        [Parameter]
        public AlpcPortAttributes PortAttributes { get; set; }

        /// <summary>
        /// <para type="description">Flags for sending the initial message.</para>
        /// </summary>
        [Parameter]
        public AlpcMessageFlags Flags { get; set; }

        /// <summary>
        /// <para type="description">Optional SID to verify the server's identity.</para>
        /// </summary>
        [Parameter(ParameterSetName = "SidCheck")]
        public Sid RequiredServerSid { get; set; }

        /// <summary>
        /// <para type="description">Optional security descriptor to verify the server's identity.</para>
        /// </summary>
        [Parameter(ParameterSetName = "SdCheck")]
        public SecurityDescriptor ServerSecurityRequirements { get; set; }

        /// <summary>
        /// <para type="description">Optional initial connection message.</para>
        /// </summary>
        [Parameter]
        public AlpcMessage ConnectionMessage { get; set; }

        /// <summary>
        /// <para type="description">Optional outbound message attributes.</para>
        /// </summary>
        [Parameter]
        public AlpcSendMessageAttributes OutMessageAttributes { get; set; }

        /// <summary>
        /// <para type="description">Optional inbound message attributes.</para>
        /// </summary>
        [Parameter]
        public AlpcReceiveMessageAttributes InMessageAttributes { get; set; }

        /// <summary>
        /// <para type="description">Optional connection timeout.</para>
        /// </summary>
        [Parameter]
        public NtWaitTimeout Timeout { get; set; }
    }

    /// <summary>
    /// <para type="synopsis">Accepts a connection on an ALPC server port.</para>
    /// <para type="description">This cmdlet accepts a connection on an ALPC server port and returns the new server port to communicate with the client.</para>
    /// </summary>
    /// <example>
    ///   <code>$conn = Connect-NtAlpcServer -Port $port -ConnectionRequest $msg</code>
    ///   <para>Accepts a connection on an ALPC server port.</para>
    /// </example>
    /// <example>
    ///   <code>$conn = Connect-NtAlpcServer -Port $port  -ConnectionRequest $msg -Reject</code>
    ///   <para>Reject a connection on an ALPC server port.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet("Connect", "NtAlpcServer")]
    [OutputType(typeof(NtAlpcServer))]
    public class ConnectNtAlpcServer : NtObjectBaseCmdlet
    {
        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected override bool CanCreateDirectories()
        {
            return false;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return Port.AcceptConnectPort(Flags, obj_attributes, PortAttributes, 
                PortContext, ConnectionMessage, ConnectionAttributes, !Reject);
        }

        /// <summary>
        /// <para type="description">The server port to accept the connection.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public NtAlpcServer Port { get; set; }

        /// <summary>
        /// <para type="description">Initial connection message from the initial receive call.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 1)]
        public AlpcMessage ConnectionMessage { get; set; }

        /// <summary>
        /// <para type="description">Optional context value for the new port.</para>
        /// </summary>
        [Parameter]
        public IntPtr PortContext { get; set; }

        /// <summary>
        /// <para type="description">Optional port attributes.</para>
        /// </summary>
        [Parameter]
        public AlpcPortAttributes PortAttributes { get; set; }

        /// <summary>
        /// <para type="description">Flags for sending the initial message.</para>
        /// </summary>
        [Parameter]
        public AlpcMessageFlags Flags { get; set; }

        /// <summary>
        /// <para type="description">Optional connection message attributes.</para>
        /// </summary>
        [Parameter]
        public AlpcSendMessageAttributes ConnectionAttributes { get; set; }

        /// <summary>
        /// <para type="description">Specify to reject the client connection.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Reject { get; set; }
    }

    /// <summary>
    /// <para type="synopsis">Creates a new ALPC server by path.</para>
    /// <para type="description">This cmdlet creates a new NT ALPC server. The absolute path to the object in the NT object manager name space must be specified.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>$obj = New-NtAlpcServer "\RPC Control\ABC"</code>
    ///   <para>Create a new ALPC server with an absolute path.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtAlpcServer")]
    [OutputType(typeof(NtAlpcServer))]
    public class NewNtAlpcServer : NtObjectBaseCmdlet
    {
        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected override bool CanCreateDirectories()
        {
            return true;
        }

        /// <summary>
        /// <para type="description">The NT object manager path to the object to use.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public override string Path { get; set; }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtAlpcServer.Create(obj_attributes, PortAttributes);
        }

        /// <summary>
        /// <para type="description">Optional port attributes.</para>
        /// </summary>
        [Parameter]
        public AlpcPortAttributes PortAttributes { get; set; }
    }

    /// <summary>
    /// <para type="synopsis">Creates a new ALPC port attributes structure.</para>
    /// <para type="description">This cmdlet creates a new ALPC port attributes structure based on single components.</para>
    /// </summary>
    /// <example>
    ///   <code>$attr = New-NtAlpcPortAttributes</code>
    ///   <para>Create a new ALPC port attributes structure with default values.</para>
    /// </example>
    /// <example>
    ///   <code>$attr = New-NtAlpcPortAttributes -Flags None</code>
    ///   <para>Create a new ALPC port attributes structure.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtAlpcPortAttributes")]
    [OutputType(typeof(AlpcPortAttributes))]
    public class NewNtAlpcPortAttributes : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Port attributes flags</para>
        /// </summary>
        [Parameter]
        public AlpcPortAttributeFlags Flags { get; set; }
        /// <summary>
        /// <para type="description">Security Quality of Service impersonation level.</para>
        /// </summary>
        [Parameter]
        public SecurityImpersonationLevel ImpersonationLevel { get; set; }
        /// <summary>
        /// <para type="description">Security Quality of Service context tracking mode.</para>
        /// </summary>
        [Parameter]
        public SecurityContextTrackingMode ContextTrackingMode { get; set; }
        /// <summary>
        /// <para type="description">Security Quality of Service effective only.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter EffectiveOnly { get; set; }
        /// <summary>
        /// <para type="description">Maximum message length.</para>
        /// </summary>
        [Parameter]
        public IntPtr MaxMessageLength { get; set; }
        /// <summary>
        /// <para type="description">Memory bandwidth.</para>
        /// </summary>
        [Parameter]
        public IntPtr MemoryBandwidth { get; set; }
        /// <summary>
        /// <para type="description">Max pool usage.</para>
        /// </summary>
        [Parameter]
        public IntPtr MaxPoolUsage { get; set; }
        /// <summary>
        /// <para type="description">Max section size.</para>
        /// </summary>
        [Parameter]
        public IntPtr MaxSectionSize { get; set; }
        /// <summary>
        /// <para type="description">Max view size.</para>
        /// </summary>
        [Parameter]
        public IntPtr MaxViewSize { get; set; }
        /// <summary>
        /// <para type="description">Max total section size.</para>
        /// </summary>
        [Parameter]
        public IntPtr MaxTotalSectionSize { get; set; }
        /// <summary>
        /// <para type="description">Duplicate object types..</para>
        /// </summary>
        [Parameter]
        public AlpcHandleObjectType DupObjectTypes { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public NewNtAlpcPortAttributes()
        {
            Flags = AlpcPortAttributeFlags.AllowDupObject | AlpcPortAttributeFlags.AllowLpcRequests;
            ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
            ContextTrackingMode = SecurityContextTrackingMode.Static;
            MaxMessageLength = new IntPtr(short.MaxValue);
            MemoryBandwidth = new IntPtr(-1);
            MaxPoolUsage = new IntPtr(-1);
            MaxSectionSize = new IntPtr(-1);
            MaxViewSize = new IntPtr(-1);
            MaxTotalSectionSize = new IntPtr(-1);
            DupObjectTypes = AlpcHandleObjectType.AllObjects;
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            var obj = new AlpcPortAttributes()
            {
                Flags = Flags,
                SecurityQos = new SecurityQualityOfServiceStruct(ImpersonationLevel,
                                                            ContextTrackingMode, EffectiveOnly),
                MaxMessageLength = MaxMessageLength,
                MemoryBandwidth = MemoryBandwidth,
                MaxPoolUsage = MaxPoolUsage,
                MaxSectionSize = MaxSectionSize,
                MaxViewSize = MaxViewSize,
                MaxTotalSectionSize = MaxTotalSectionSize,
                DupObjectTypes = DupObjectTypes
            };
            WriteObject(obj);
        }
    }

    /// <summary>
    /// <para type="synopsis">Creates a new ALPC message.</para>
    /// <para type="description">This cmdlet creates a new ALPC message based on a byte array or an length initializer.</para>
    /// </summary>
    /// <example>
    ///   <code>$msg = New-NtAlpcMessage -Bytes @(0, 1, 2, 3)</code>
    ///   <para>Create a new message from a byte array.</para>
    /// </example>
    /// <example>
    ///   <code>$msg = New-NtAlpcMessage -Bytes @(0, 1, 2, 3) -AllocatedDataLength 1000</code>
    ///   <para>Create a new message from a byte array with an allocated length of 1000 bytes.</para>
    /// </example>
    /// <example>
    ///   <code>$msg = New-NtAlpcMessage -AllocatedDataLength 1000</code>
    ///   <para>Create a new message with an allocated length of 1000 bytes.</para>
    /// </example>
    /// <example>
    ///   <code>$msg = New-NtAlpcMessage -String "Hello World!"</code>
    ///   <para>Create a new message from a unicode string.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtAlpcMessage", DefaultParameterSetName = "FromLength")]
    [OutputType(typeof(AlpcMessage))]
    public class NewNtAlpcMessage : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Create the message from a byte array.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromBytes")]
        public byte[] Bytes { get; set; }

        /// <summary>
        /// <para type="description">Create the message from a string.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromString")]
        public string String { get; set; }

        /// <summary>
        /// <para type="description">Specify the message with allocated length.</para>
        /// </summary>
        [Parameter(Position = 0, ParameterSetName = "FromLength")]
        [Parameter(Position = 1, ParameterSetName = "FromBytes")]
        [Parameter(Position = 1, ParameterSetName = "FromString")]
        public int AllocatedDataLength { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public NewNtAlpcMessage()
        {
            AllocatedDataLength = AlpcMessage.MaximumDataLength;
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (ParameterSetName == "FromBytes")
            {
                WriteObject(new AlpcMessageRaw(Bytes, AllocatedDataLength));
            }
            else if (ParameterSetName == "FromString")
            {
                WriteObject(new AlpcMessageRaw(Encoding.Unicode.GetBytes(String), AllocatedDataLength));
            }
            else
            {
                WriteObject(new AlpcMessageRaw(AllocatedDataLength));
            }
        }
    }

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
    [Cmdlet("Send", "NtAlpcMessage", DefaultParameterSetName = "FromMsg")]
    [OutputType(typeof(AlpcMessage))]
    public class SendNtAlpcMessage : PSCmdlet
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
            Port.SendReceive(Flags, msg, SendAttributes, recv_message, recv_message != null ? ReceiveAttributes : null, timeout);
            return recv_message;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public SendNtAlpcMessage()
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

    /// <summary>
    /// <para type="synopsis">Receives a message on an ALPC port.</para>
    /// <para type="description">This cmdlet receives a message on an ALPC port.</para>
    /// </summary>
    /// <example>
    ///   <code>$recv_msg = Receive-NtAlpcMessage -Port $port -ReceiveLength 80</code>
    ///   <para>Receive a message of up to 80 bytes.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet("Receive", "NtAlpcMessage")]
    public class ReceiveNtAlpcMessage : PSCmdlet
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
        public ReceiveNtAlpcMessage()
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
