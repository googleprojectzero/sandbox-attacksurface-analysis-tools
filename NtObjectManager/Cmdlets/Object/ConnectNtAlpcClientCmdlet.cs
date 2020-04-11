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
}
