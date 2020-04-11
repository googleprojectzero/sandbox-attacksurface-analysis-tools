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
}
