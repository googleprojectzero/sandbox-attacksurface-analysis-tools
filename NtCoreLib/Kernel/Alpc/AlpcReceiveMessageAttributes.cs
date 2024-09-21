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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Utilities.Collections;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Kernel.Alpc;

/// <summary>
/// Class to represent a set of received attributes.
/// </summary>
public sealed class AlpcReceiveMessageAttributes : IDisposable, IMessageAttributes
{
    #region Private Members
    private Dictionary<AlpcMessageAttributeFlags, AlpcMessageAttribute> _attributes;
    private DisposableList<NtObject> _handles;

    SafeAlpcMessageAttributesBuffer IMessageAttributes.ToSafeBuffer()
    {
        return SafeAlpcMessageAttributesBuffer.Create(AllocatedAttributes);
    }

    #endregion

    #region Constructors
    /// <summary>
    /// Constructor. Allocated space for all known attributes.
    /// </summary>
    public AlpcReceiveMessageAttributes()
        : this(AlpcMessageAttributeFlags.AllAttributes)
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    public AlpcReceiveMessageAttributes(AlpcMessageAttributeFlags allocated_attributes)
    {
        AllocatedAttributes = allocated_attributes;
        _attributes = new Dictionary<AlpcMessageAttributeFlags, AlpcMessageAttribute>();
        _handles = new DisposableList<NtObject>();
        DataView = new SafeAlpcDataViewBuffer();
        SecurityContext = new SafeAlpcSecurityContextHandle();
    }
    #endregion

    #region Public Properties

    /// <summary>
    /// Get the allocated attributes.
    /// </summary>
    public AlpcMessageAttributeFlags AllocatedAttributes { get; set; }

    /// <summary>
    /// Get the list of valid attributes.
    /// </summary>
    public AlpcMessageAttributeFlags ValidAttributes { get; private set; }

    /// <summary>
    /// Get a list of the valid attributes.
    /// </summary>
    public IEnumerable<AlpcMessageAttribute> Attributes => _attributes.Values;

    /// <summary>
    /// Get list of passed handles.
    /// </summary>
    public IEnumerable<NtObject> Handles => _handles.AsReadOnly();

    /// <summary>
    /// Get the mapped data view. If no view sent this property is invalid.
    /// </summary>
    public SafeAlpcDataViewBuffer DataView { get; private set; }

    /// <summary>
    /// Get the security context. If no security context this property is invalid.
    /// </summary>
    public SafeAlpcSecurityContextHandle SecurityContext { get; private set; }

    #endregion

    #region Public Methods
    /// <summary>
    /// Dispose method.
    /// </summary>
    public void Dispose()
    {
        _handles.Dispose();
        DataView.Dispose();
        SecurityContext.Dispose();
    }

    /// <summary>
    /// Get a typed attribute.
    /// </summary>
    /// <typeparam name="T">The type of attribute to get.</typeparam>
    /// <returns>The attribute. Returns a default initialized object if not valid.</returns>
    public T GetAttribute<T>() where T : AlpcMessageAttribute, new()
    {
        T result = new();
        if (_attributes.ContainsKey(result.AttributeFlag))
        {
            return (T)_attributes[result.AttributeFlag];
        }
        return result;
    }

    /// <summary>
    /// Get an attribute.
    /// </summary>
    /// <param name="flag">The attribute flag to get.</param>
    /// <returns>The attribute. Returns null if not found.</returns>
    public AlpcMessageAttribute GetAttribute(AlpcMessageAttributeFlags flag)
    {
        if (_attributes.ContainsKey(flag))
        {
            return _attributes[flag];
        }
        return null;
    }

    /// <summary>
    /// Convert this set of attributes to a buffer to send.
    /// </summary>
    /// <returns>The send attributes.</returns>
    public AlpcSendMessageAttributes ToSendAttributes()
    {
        return new AlpcSendMessageAttributes(Attributes);
    }

    /// <summary>
    /// Convert this set of attributes to one which can be used to free on continuation required.
    /// </summary>
    /// <param name="attributes">The attributes to </param>
    /// <returns>The send attributes.</returns>
    public AlpcSendMessageAttributes ToContinuationAttributes(AlpcMessageAttributeFlags attributes)
    {
        AlpcSendMessageAttributes ret = new();
        if ((ValidAttributes & attributes & AlpcMessageAttributeFlags.View) != 0)
        {
            ret.Add(new AlpcDataViewMessageAttribute(0, 0, 0, AlpcDataViewAttrFlags.ReleaseView));
        }
        if ((ValidAttributes & attributes & AlpcMessageAttributeFlags.Handle) != 0)
        {
            ret.Add(new AlpcHandleMessageAttribute());
        }
        return ret;
    }

    /// <summary>
    /// Checks if an attribute flag is valid.
    /// </summary>
    /// <param name="attribute">The attribute to test.</param>
    /// <returns>True if the attribute is value.</returns>
    public bool HasValidAttribute(AlpcMessageAttributeFlags attribute)
    {
        return ValidAttributes.HasFlag(attribute);
    }

    #endregion

    #region Internal Members
    internal T AddAttribute<T>(SafeAlpcMessageAttributesBuffer buffer,
        NtAlpc port, AlpcMessage message) where T : AlpcMessageAttribute, new()
    {
        T attribute = new();
        attribute.FromSafeBuffer(buffer, port, message);
        _attributes.Add(attribute.AttributeFlag, attribute);
        ValidAttributes |= attribute.AttributeFlag;
        return attribute;
    }

    internal void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port, AlpcMessage message)
    {
        var result = buffer.Result;
        var valid_attrs = result.ValidAttributes;

        if (valid_attrs.HasFlag(AlpcMessageAttributeFlags.Token))
        {
            AddAttribute<AlpcTokenMessageAttribute>(buffer, port, message);
        }
        if (valid_attrs.HasFlag(AlpcMessageAttributeFlags.Context))
        {
            AddAttribute<AlpcContextMessageAttribute>(buffer, port, message);
        }
        if (valid_attrs.HasFlag(AlpcMessageAttributeFlags.Handle))
        {
            var attribute = AddAttribute<AlpcHandleMessageAttribute>(buffer, port, message);
            _handles.AddRange(attribute.Handles.Select(h => NtObjectUtils.FromHandle(h.Handle, true)));
        }
        if (valid_attrs.HasFlag(AlpcMessageAttributeFlags.Security))
        {
            var attr = AddAttribute<AlpcSecurityMessageAttribute>(buffer, port, message);
            SecurityContext = new SafeAlpcSecurityContextHandle(attr.ContextHandle, true, port, attr.Flags, attr.SecurityQoS);
        }
        if (valid_attrs.HasFlag(AlpcMessageAttributeFlags.View))
        {
            var attr = AddAttribute<AlpcDataViewMessageAttribute>(buffer, port, message);
            DataView = new SafeAlpcDataViewBuffer(new IntPtr(attr.ViewBase), attr.ViewSize,
                new SafeAlpcPortSectionHandle(attr.SectionHandle, true, port), attr.Flags, true);
        }
        if (valid_attrs.HasFlag(AlpcMessageAttributeFlags.WorkOnBehalfOf))
        {
            AddAttribute<AlpcWorkOnBehalfMessageAttribute>(buffer, port, message);
        }
    }
    #endregion
}
