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

using NtApiDotNet.Win32;
using System.IO;
using System.Management.Automation;
using System.Runtime.Serialization;
using System.Text;
using System.Xml;

namespace NtObjectManager.Cmdlets.Rpc
{
    /// <summary>
    /// <para type="synopsis">Get the names from a RPC server as XML.</para>
    /// <para type="description">This cmdlet extracts the names from a RPC server instance and
    /// generates an XML file for easy editing. You can then update the names with Set-RpcServerName.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-RpcServerName -Server $server</code>
    ///   <para>Get names for an RPC server object.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "RpcServerName")]
    [OutputType(typeof(string))]
    public sealed class GetRpcServerName : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the server object to get the names from.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public RpcServer Server { get; set; }
        /// <summary>
        /// Process record override.
        /// </summary>
        protected override void ProcessRecord()
        {
            RpcServerNameData name_data = new RpcServerNameData(Server);
            WriteObject(name_data.ToXml());
        }
    }

    /// <summary>
    /// <para type="synopsis">Set the names of a RPC server from XML.</para>
    /// <para type="description">This cmdlet extracts updates the names for a RPC server instance from
    /// XML data. You can get the names with Get-RpcServerName.</para>
    /// </summary>
    /// <example>
    ///   <code>Set-RpcServerName -Server $server -Names $xml</code>
    ///   <para>Set names for an RPC server object from a string.</para>
    /// </example>
    /// <example>
    ///   <code>Get-Content names.xml | Set-RpcServerName -Server $server</code>
    ///   <para>Set names for an RPC server object from a file.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Set, "RpcServerName")]
    public sealed class SetRpcServerName : PSCmdlet
    {
        private StringBuilder _builder = new StringBuilder();

        /// <summary>
        /// <para type="description">Specify the server object to update the names on.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public RpcServer Server { get; set; }

        /// <summary>
        /// <para type="description">Specify the XML data which contains the names to update.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true, ValueFromPipeline = true)]
        public string Xml { get; set; }

        private void UpdateNames()
        {
            DataContractSerializer ser = new DataContractSerializer(typeof(RpcServerNameData));
            StringReader string_reader = new StringReader(_builder.ToString());
            using (var reader = XmlReader.Create(string_reader))
            {
                var name_data = (RpcServerNameData)ser.ReadObject(reader);
                name_data.UpdateNames(Server);
            }
        }

        /// <summary>
        /// Process record override.
        /// </summary>
        protected override void ProcessRecord()
        {
            _builder.AppendLine(Xml);
        }

        /// <summary>
        /// End processing override.
        /// </summary>
        protected override void EndProcessing()
        {
            UpdateNames();
        }
    }
}
