using NtApiDotNet;
using System;
using System.Management.Automation;

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
            if (ParameterSetName == "CheckSid")
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
        public AlpcMessageAttributeSet OutMessageAttributes { get; set; }

        /// <summary>
        /// <para type="description">Optional inbound message attributes.</para>
        /// </summary>
        [Parameter]
        public AlpcMessageAttributeSet InMessageAttributes { get; set; }

        /// <summary>
        /// <para type="description">Optional connection timeout.</para>
        /// </summary>
        [Parameter]
        public NtWaitTimeout Timeout { get; set; }
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
    ///   <code>$msg = New-NtAlpcMessage -Length 1000</code>
    ///   <para>Create a new message with length 1000.</para>
    /// </example>
    /// <example>
    ///   <code>$msg = New-NtAlpcMessage -Length 1000 -Initialize</code>
    ///   <para>Create a new message with length 1000 and initialize the header.</para>
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
        /// <para type="description">Create the message with an allocated length.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromLength")]
        public int Length { get; set; }
        /// <summary>
        /// <para type="description">Initialize the message headers for the allocated length.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromLength")]
        public SwitchParameter Initialize { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (ParameterSetName == "FromBytes")
            {
                WriteObject(AlpcMessage.Create(Bytes));
            }
            else
            {
                WriteObject(AlpcMessage.Create(Length, Initialize));
            }
        }
    }
}
