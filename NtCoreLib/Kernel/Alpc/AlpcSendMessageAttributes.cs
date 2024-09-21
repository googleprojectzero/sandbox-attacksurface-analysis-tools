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

using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Kernel.Alpc;

/// <summary>
/// Class to represent a set of sending attributes.
/// </summary>
public sealed class AlpcSendMessageAttributes : IMessageAttributes
{
    #region Private Members
    private Dictionary<AlpcMessageAttributeFlags, AlpcMessageAttribute> _attributes;

    private AlpcHandleMessageAttribute GetHandleAttribute()
    {
        if (!_attributes.ContainsKey(AlpcMessageAttributeFlags.Handle))
        {
            _attributes[AlpcMessageAttributeFlags.Handle] = new AlpcHandleMessageAttribute();
        }
        return (AlpcHandleMessageAttribute)_attributes[AlpcMessageAttributeFlags.Handle];
    }

    SafeAlpcMessageAttributesBuffer IMessageAttributes.ToSafeBuffer()
    {
        if (_attributes.Count == 0)
        {
            return SafeAlpcMessageAttributesBuffer.Null;
        }

        AlpcMessageAttributeFlags flags = AllocatedAttributes;

        using var buffer = SafeAlpcMessageAttributesBuffer.Create(flags);
        foreach (var attr in _attributes.Values)
        {
            attr.ToSafeBuffer(buffer);
        }

        var result = buffer.Result;
        result.ValidAttributes = flags;
        buffer.Result = result;
        return buffer.Detach();
    }

    #endregion

    #region Constructors
    /// <summary>
    /// Constructor.
    /// </summary>
    public AlpcSendMessageAttributes() : this(new AlpcMessageAttribute[0])
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="attributes">List of attributes to send.</param>
    public AlpcSendMessageAttributes(IEnumerable<AlpcMessageAttribute> attributes)
    {
        _attributes = new Dictionary<AlpcMessageAttributeFlags, AlpcMessageAttribute>(attributes.ToDictionary(a => a.AttributeFlag, a => a));
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Add an attribute object.
    /// </summary>
    /// <param name="attribute">The attribute to add.</param>
    public void Add(AlpcMessageAttribute attribute)
    {
        _attributes.Add(attribute.AttributeFlag, attribute);
    }

    /// <summary>
    /// Remove an attribute object.
    /// </summary>
    /// <param name="flag">The attribute flag to remove.</param>
    public void Remove(AlpcMessageAttributeFlags flag)
    {
        _attributes.Remove(flag);
    }

    /// <summary>
    /// Remove an attribute object.
    /// </summary>
    /// <param name="attribute">The attribute to remove.</param>
    public void Remove(AlpcMessageAttribute attribute)
    {
        _attributes.Remove(attribute.AttributeFlag);
    }

    /// <summary>
    /// Add a list of handles to the send attributes.
    /// </summary>
    /// <param name="objects">The list of objects.</param>
    /// <remarks>This method doesn't maintain a reference to the objects. You need to keep them alive elsewhere.</remarks>
    public void AddHandles(IEnumerable<NtObject> objects)
    {
        AddHandles(objects.Select(h => new AlpcHandleMessageAttributeEntry(h)));
    }

    /// <summary>
    /// Add a list of handles to the send attributes.
    /// </summary>
    /// <param name="handles">The list of handles.</param>
    public void AddHandles(IEnumerable<AlpcHandleMessageAttributeEntry> handles)
    {
        GetHandleAttribute().AddHandles(handles);
    }

    /// <summary>
    /// Add a list of handles to the send attributes.
    /// </summary>
    /// <param name="handle">The handle to add.</param>
    /// <remarks>This method doesn't maintain a reference to the objects. You need to keep them alive elsewhere.</remarks>
    public void AddHandle(NtObject handle)
    {
        AddHandles(new NtObject[] { handle });
    }

    /// <summary>
    /// Add a list of handles to the send attributes.
    /// </summary>
    /// <param name="handle">The handle to add.</param>
    public void AddHandle(AlpcHandleMessageAttributeEntry handle)
    {
        AddHandles(new AlpcHandleMessageAttributeEntry[] { handle });
    }

    #endregion

    #region Public Properties
    /// <summary>
    /// Get the allocated attributes.
    /// </summary>
    public AlpcMessageAttributeFlags AllocatedAttributes
    {
        get
        {
            AlpcMessageAttributeFlags flags = AlpcMessageAttributeFlags.None;
            foreach (var flag in _attributes.Keys)
            {
                flags |= flag;
            }
            return flags;
        }
    }
    #endregion
}
