//  Copyright 2016 Google Inc. All Rights Reserved.
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

using NtCoreLib;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.Token;
using NtObjectManager.Utils;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// Base object cmdlet.
/// </summary>
public abstract class NtObjectBaseNoPathCmdlet : PSCmdlet, IDisposable
{
    /// <summary>
    /// <para type="description">Object Attribute flags used during Open/Create calls.</para>
    /// </summary>
    [Parameter]
    [Alias("ObjectAttributes", "AttributesFlags")]
    public AttributeFlags AttributeFlags { get; set; }

    /// <summary>
    /// <para type="description">Set to provide an explicit security descriptor to a newly created object.</para>
    /// </summary>
    [Parameter]
    public SecurityDescriptor SecurityDescriptor { get; set; }

    /// <summary>
    /// <para type="description">Set to mark the new handle as inheritable. Can be used with ObjectAttributes.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Inherit { get; set; }

    /// <summary>
    /// <para type="description">Set to provide an explicit security descriptor to a newly created object in SDDL format.</para>
    /// </summary>
    [Parameter]
    public string Sddl
    {
        get => SecurityDescriptor?.ToSddl();
        set => SecurityDescriptor = new SecurityDescriptor(value);
    }

    /// <summary>
    /// <para type="description">Set to provide an explicit security quality of service when opening files/namedpipes.</para>
    /// </summary>
    [Parameter]
    public SecurityQualityOfService SecurityQualityOfService { get; set; }

    /// <summary>
    /// <para type="description">Close the object immediately and don't pass to the output. This is useful to create permanent objects
    /// without needing to close the handle manually.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Close { get; set; }

    /// <summary>
    /// <para type="description">Invoke a script block on the created object before writing it to the output. Can be used in combination with the Close to map objects to some value.</para>
    /// </summary>
    [Parameter]
    public ScriptBlock ScriptBlock { get; set; }

    /// <summary>
    /// Base constructor.
    /// </summary>
    protected NtObjectBaseNoPathCmdlet()
    {
        AttributeFlags = AttributeFlags.CaseInsensitive;
    }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected abstract object CreateObject(ObjectAttributes obj_attributes);

    /// <summary>
    /// Indicates that the path is raw and should be passed through Base64 decode.
    /// </summary>
    protected virtual bool IsRawPath { get; }

    private ObjectAttributes CreateAttributes(string path, AttributeFlags attributes, NtObject root,
        SecurityQualityOfService security_quality_of_service, SecurityDescriptor security_descriptor)
    {
        if (IsRawPath)
        {
            return ObjectAttributes.CreateWithRawName(Convert.FromBase64String(path), attributes, 
                root, security_quality_of_service, security_descriptor);
        }
        return new ObjectAttributes(path, attributes, root, security_quality_of_service, security_descriptor);
    }

    /// <summary>
    /// Create object from components.
    /// </summary>
    /// <param name="path">The path to the object.</param>
    /// <param name="attributes">The object attributes.</param>
    /// <param name="root">The root object.</param>
    /// <param name="security_quality_of_service">Security quality of service.</param>
    /// <param name="security_descriptor">Security descriptor.</param>
    /// <returns>The created object.</returns>
    protected object CreateObject(string path, AttributeFlags attributes, NtObject root, 
        SecurityQualityOfService security_quality_of_service, SecurityDescriptor security_descriptor)
    {
        if (Inherit)
        {
            attributes |= AttributeFlags.Inherit;
        }

        using var obja = CreateAttributes(path, attributes, root,
            security_quality_of_service, security_descriptor);
        return CreateObject(obja);
    }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        WriteToOutput(CreateObject(null, AttributeFlags, null, SecurityQualityOfService, SecurityDescriptor));
    }

    private protected void WriteToOutput(object obj)
    {
        if (obj != null)
        {
            try
            {
                if (ScriptBlock != null)
                {
                    WriteObject(PSUtils.InvokeWithArg(ScriptBlock, obj), true);
                }

                if (!Close)
                {
                    WriteObject(obj, true);
                }
            }
            finally
            {
                if (Close)
                {
                    PSUtils.Dispose(obj);
                }
            }
        }
    }

    #region IDisposable Support
    /// <summary>
    /// Dispose object.
    /// </summary>
    protected virtual void Dispose(bool disposing)
    {
    }

    /// <summary>
    /// Finalizer.
    /// </summary>
    ~NtObjectBaseNoPathCmdlet()
    {
        Dispose(false);
    }

    /// <summary>
    /// Dispose object.
    /// </summary>
    void IDisposable.Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    #endregion
}
