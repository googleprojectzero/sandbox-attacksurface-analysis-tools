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
using System.Management.Automation;
using System.Text;

namespace NtObjectManager.Cmdlets.Object
{
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
}
