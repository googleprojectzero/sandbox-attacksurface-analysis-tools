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

namespace NtObjectManager.Cmdlets.Object
{
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
}
