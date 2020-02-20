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
using NtObjectManager.Utils;
using System;
using System.Management.Automation;
using System.Text;

namespace NtObjectManager.Cmdlets.Object
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
    [Cmdlet(VerbsCommunications.Connect, "NtAlpcClient", DefaultParameterSetName = "SidCheck")]
    [OutputType(typeof(NtAlpcClient))]
    public class ConnectNtAlpcClientCmdlet : NtObjectBaseCmdlet
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
        public ConnectNtAlpcClientCmdlet()
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
    ///   <code>$conn = Connect-NtAlpcServer -Port $port -ConnectionMessage $msg</code>
    ///   <para>Accepts a connection on an ALPC server port.</para>
    /// </example>
    /// <example>
    ///   <code>$conn = Connect-NtAlpcServer -Port $port  -ConnectionMessage $msg -Reject</code>
    ///   <para>Reject a connection on an ALPC server port.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommunications.Connect, "NtAlpcServer")]
    [OutputType(typeof(NtAlpcServer))]
    public class ConnectNtAlpcServerCmdlet : NtObjectBaseNoPathCmdlet
    {
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
    public class NewNtAlpcServerCmdlet : NtObjectBaseCmdlet
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
    public class NewNtAlpcPortAttributesCmdlet : PSCmdlet
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
        public NewNtAlpcPortAttributesCmdlet()
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
    /// <para type="description">This cmdlet creates a new ALPC message based on a byte array or an length initializer.
    /// You can also specify a text encoding which allows you to use the DataString property.</para>
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
    ///   <code>$msg = New-NtAlpcMessage -AllocatedDataLength 1000 -Encoding UTF8</code>
    ///   <para>Create a new message with an allocated length of 1000 bytes and the message encoding is UTF8.</para>
    /// </example>
    /// <example>
    ///   <code>$msg = New-NtAlpcMessage -String "Hello World!"</code>
    ///   <para>Create a new message from a unicode string.</para>
    /// </example>
    /// <example>
    ///   <code>$msg = New-NtAlpcMessage -String "Hello World!" -Encoding UTF8</code>
    ///   <para>Create a new message from a UTF8 string.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtAlpcMessage", DefaultParameterSetName = "FromLength")]
    [OutputType(typeof(AlpcMessage))]
    public class NewNtAlpcMessageCmdlet : PSCmdlet
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
        /// <para type="description">Get or set the text encoding for this message.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromLength")]
        [Parameter(ParameterSetName = "FromBytes")]
        [Parameter(ParameterSetName = "FromString")]
        public TextEncodingType Encoding { get; set; }

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
        public NewNtAlpcMessageCmdlet()
        {
            AllocatedDataLength = AlpcMessage.MaximumDataLength;
            Encoding = TextEncodingType.Unicode;
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            Encoding encoding = PSUtils.GetEncoding(Encoding);
            if (ParameterSetName == "FromBytes")
            {
                WriteObject(new AlpcMessageRaw(Bytes, AllocatedDataLength, encoding));
            }
            else if (ParameterSetName == "FromString")
            {
                WriteObject(new AlpcMessageRaw(encoding.GetBytes(String), AllocatedDataLength, encoding));
            }
            else
            {
                WriteObject(new AlpcMessageRaw(AllocatedDataLength, encoding));
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
            Port.SendReceive(Flags, msg, SendAttributes, recv_message, recv_message != null ? ReceiveAttributes : null, timeout);
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

    /// <summary>
    /// <para type="synopsis">Creates a new receive attributes buffer.</para>
    /// <para type="description">This cmdlet creates a new receive attributes buffer for the specified set of attributes. This defaults to all known attributes.</para>
    /// </summary>
    /// <example>
    ///   <code>$attrs = New-NtAlpcReceiveAttributes</code>
    ///   <para>Create a new receive attributes buffer with space for all known attributes.</para>
    /// </example>
    /// <example>
    ///   <code>$attrs = New-NtAlpcReceiveAttributes -Attributes View, Context</code>
    ///   <para>Create a new receive attributes buffer with space for only View and Context attributes.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtAlpcReceiveAttributes")]
    [OutputType(typeof(AlpcReceiveMessageAttributes))]
    public class NewNtAlpcReceiveAttributesCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the list of attributes for the receive buffer.</para>
        /// </summary>
        [Parameter(Position = 0)]
        public AlpcMessageAttributeFlags Attributes { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public NewNtAlpcReceiveAttributesCmdlet()
        {
            Attributes = AlpcMessageAttributeFlags.AllAttributes;
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            WriteObject(new AlpcReceiveMessageAttributes(Attributes));
        }
    }

    /// <summary>
    /// <para type="synopsis">Creates a new send attributes buffer.</para>
    /// <para type="description">This cmdlet creates a new send attributes buffer. The buffer can be initialized with a list of attributes or by specifying specific values.</para>
    /// </summary>
    /// <example>
    ///   <code>$attrs = New-NtAlpcSendAttributes</code>
    ///   <para>Create a new empty send attributes buffer.</para>
    /// </example>
    /// <example>
    ///   <code>$attrs = New-NtAlpcSendAttributes -Attributes $view, $handle</code>
    ///   <para>Create a new send attributes buffer with view and handle attribute objects.</para>
    /// </example>
    /// <example>
    ///   <code>$attrs = New-NtAlpcSendAttributes -Object $proc</code>
    ///   <para>Create a new send attributes buffer with a handle attribute from a process handle.</para>
    /// </example>
    /// <example>
    ///   <code>$attrs = New-NtAlpcSendAttributes -WorkOnBehalfOf</code>
    ///   <para>Create a new send attributes buffer with a Work on Behalf of attribute.</para>
    /// </example>
    /// <example>
    ///   <code>$attrs = New-NtAlpcSendAttributes -DataView $dataview</code>
    ///   <para>Create a new send attributes buffer with data view.</para>
    /// </example>
    [Cmdlet(VerbsCommon.New, "NtAlpcSendAttributes", DefaultParameterSetName = "FromAttributes")]
    [OutputType(typeof(AlpcSendMessageAttributes))]
    public class NewNtAlpcSendAttributesCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the list of attributes for the send buffer.</para>
        /// </summary>
        [Parameter(Position = 0, ParameterSetName = "FromAttributes")]
        public AlpcMessageAttribute[] Attributes { get; set; }

        /// <summary>
        /// <para type="description">Create a handle attribute from a list of objects.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromParts")]
        [Alias("os")]
        public NtObject[] Object { get; set; }

        /// <summary>
        /// <para type="description">Create a handle attribute from a list of handle entries.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromParts")]
        [Alias("hs")]
        public AlpcHandleMessageAttributeEntry[] Handle { get; set; }

        /// <summary>
        /// <para type="description">Add a Work on Behalf of attribute.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromParts")]
        public SwitchParameter WorkOnBehalfOf { get; set; }

        /// <summary>
        /// <para type="description">Add a data view attribute.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromParts")]
        [Alias("dv")]
        public SafeAlpcDataViewBuffer DataView { get; set; }

        /// <summary>
        /// <para type="description">Automatically create a security context attribute with a specified security quality of service.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromParts")]
        [Alias("sqos")]
        public SecurityQualityOfService SecurityQualityOfService { get; set; }

        /// <summary>
        /// <para type="description">Specify a security context attribute.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromParts")]
        [Alias("sctx")]
        public SafeAlpcSecurityContextHandle SecurityContext { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public NewNtAlpcSendAttributesCmdlet()
        {
            Attributes = new AlpcMessageAttribute[0];
            Object = new NtObject[0];
            Handle = new AlpcHandleMessageAttributeEntry[0];
        }

        private AlpcSendMessageAttributes CreateFromParts()
        {
            var attrs = new AlpcSendMessageAttributes();
            if (Object.Length > 0)
            {
                attrs.AddHandles(Object);
            }

            if (Handle.Length > 0)
            {
                attrs.AddHandles(Handle);
            }

            if (WorkOnBehalfOf)
            {
                attrs.Add(new AlpcWorkOnBehalfMessageAttribute());
            }

            if (DataView != null)
            {
                attrs.Add(DataView.ToMessageAttribute());
            }

            if (SecurityQualityOfService != null)
            {
                attrs.Add(AlpcSecurityMessageAttribute.CreateHandleAttribute(SecurityQualityOfService));
            }
            else if (SecurityContext != null)
            {
                attrs.Add(SecurityContext.ToMessageAttribute());
            }

            return attrs;
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            switch (ParameterSetName)
            {
                case "FromAttributes":
                    WriteObject(new AlpcSendMessageAttributes(Attributes));
                    break;
                case "FromParts":
                    WriteObject(CreateFromParts());
                    break;
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Creates a new port section from a port.</para>
    /// <para type="description">This cmdlet creates a new port section with a specified size and flags for a port. You can then write to buffer and pass it as a view attribute.</para>
    /// </summary>
    /// <example>
    ///   <code>$s = New-NtAlpcPortSection -Size 10000</code>
    ///   <para>Create a new port section of size 10000.</para>
    /// </example>
    /// <example>
    ///   <code>$s = New-NtAlpcPortSection -Size 10000 -Secure</code>
    ///   <para>Create a new secure port section of size 10000.</para>
    /// </example>
    /// <example>
    ///   <code>$s = New-NtAlpcPortSection -Section $sect</code>
    ///   <para>>Create a new port section backed by an existing section.</para>
    /// </example>
    /// <example>
    ///   <code>$s = New-NtAlpcPortSection -Section $sect -Size 10000</code>
    ///   <para>>Create a new port section backed by an existing section with an explicit view size.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtAlpcPortSection", DefaultParameterSetName = "FromSize")]
    [OutputType(typeof(AlpcPortSection))]
    public class NewNtAlpcPortSectionCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the port to create the port section from.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public NtAlpc Port { get; set; }

        /// <summary>
        /// <para type="description">Specify the size of the port section. This will be rounded up to the nearest allocation boundary.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromSize")]
        [Parameter(ParameterSetName = "FromSection")]
        public long Size { get; set; }

        /// <summary>
        /// <para type="description">Create a secure section.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSize")]
        public SwitchParameter Secure { get; set; }

        /// <summary>
        /// <para type="description">Specify an existing section to back the port section.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromSection")]
        public NtSection Section { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            switch (ParameterSetName)
            {
                case "FromSize":
                    WriteObject(Port.CreatePortSection(Secure ? AlpcCreatePortSectionFlags.Secure : 0, Size));
                    break;
                case "FromSection":
                    WriteObject(Port.CreatePortSection(AlpcCreatePortSectionFlags.None, Section, Size == 0 ? Section.Size : Size));
                    break;
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Creates a new data view from a port section.</para>
    /// <para type="description">This cmdlet creates a new data view from a port section specified size and flags.</para>
    /// </summary>
    /// <example>
    ///   <code>$s = New-NtAlpcDataView -Section $section -Size 10000</code>
    ///   <para>Create a new data view with size 10000.</para>
    /// </example>
    /// <example>
    ///   <code>$s = New-NtAlpcDataView -Size 10000 -Flags Secure</code>
    ///   <para>Create a new secure data view section of size 10000.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtAlpcDataView")]
    [OutputType(typeof(SafeAlpcDataViewBuffer))]
    public class NewNtAlpcDataViewCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the port to create the port section from.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public AlpcPortSection Section { get; set; }

        /// <summary>
        /// <para type="description">Specify the size of the data view. This will be rounded up to the nearest allocation boundary.</para>
        /// </summary>
        [Parameter(Position = 1)]
        public long Size { get; set; }

        /// <summary>
        /// <para type="description">Specify data view attribute flags.</para>
        /// </summary>
        [Parameter]
        public AlpcDataViewAttrFlags Flags { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            WriteObject(Section.CreateSectionView(Flags, Size == 0 ? Section.Size : Size));
        }
    }

    /// <summary>
    /// <para type="synopsis">Creates a new ALPC security context.</para>
    /// <para type="description">This cmdlet creates a new ALPC security context pages of a specified security quality of serice..</para>
    /// </summary>
    /// <example>
    ///   <code>$ctx = New-NtAlpcSecurityContext -Port $port</code>
    ///   <para>Create a new security context with default values.</para>
    /// </example>
    /// <example>
    ///   <code>$ctx = New-NtAlpcSecurityContext -Port $port -ImpersonationLevel Identification</code>
    ///   <para>Create a new security context with impersonation level of Identitification.</para>
    /// </example>
    /// <example>
    ///   <code>$ctx = New-NtAlpcSecurityContext -Port $port -SecurityQualityOfService $sqos</code>
    ///   <para>Create a new security context from a security quality of service.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtAlpcSecurityContext", DefaultParameterSetName = "FromParts")]
    [OutputType(typeof(SafeAlpcSecurityContextHandle))]
    public class NewNtAlpcSecurityContextCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the port to create the context from.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public NtAlpc Port { get; set; }

        /// <summary>
        /// <para type="description">Specify the creation flags.</para>
        /// </summary>
        [Parameter]
        public AlpcCreateSecurityContextFlags Flags { get; set; }

        /// <summary>
        /// <para type="description">Specify the impersonation level.</para>
        /// </summary>
        [Parameter(Position = 1, ParameterSetName = "FromParts")]
        [Alias("imp")]
        public SecurityImpersonationLevel ImpersonationLevel { get; set; }

        /// <summary>
        /// <para type="description">Specify the list of attributes for the receive buffer.</para>
        /// </summary>
        [Parameter(Position = 2, ParameterSetName = "FromParts")]
        [Alias("ctx")]
        public SecurityContextTrackingMode ContextTrackingMode { get; set; }

        /// <summary>
        /// <para type="description">Specify the list of attributes for the receive buffer.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromParts")]
        [Alias("eo")]
        public SwitchParameter EffectiveOnly { get; set; }

        /// <summary>
        /// <para type="description">Specify the list of attributes for the receive buffer.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSqos")]
        [Alias("sqos")]
        public SecurityQualityOfService SecurityQualityOfService { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public NewNtAlpcSecurityContextCmdlet()
        {
            ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
            ContextTrackingMode = SecurityContextTrackingMode.Static;
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            SecurityQualityOfService sqos = ParameterSetName == "FromSqos" 
                ? SecurityQualityOfService 
                : new SecurityQualityOfService(ImpersonationLevel, ContextTrackingMode, EffectiveOnly);
            WriteObject(Port.CreateSecurityContext(sqos));
        }
    }
}
