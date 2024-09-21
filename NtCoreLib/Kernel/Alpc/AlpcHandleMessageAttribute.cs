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
/// Class representing a handle message attribute.
/// </summary>
public sealed class AlpcHandleMessageAttribute : AlpcMessageAttribute
{
    private readonly List<AlpcHandleMessageAttributeEntry> _handles;

    /// <summary>
    /// Constructor.
    /// </summary>
    public AlpcHandleMessageAttribute()
        : this(new AlpcHandleMessageAttributeEntry[0])
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="handles">List of handle entries.</param>
    public AlpcHandleMessageAttribute(IEnumerable<AlpcHandleMessageAttributeEntry> handles)
        : base(AlpcMessageAttributeFlags.Handle)
    {
        _handles = new List<AlpcHandleMessageAttributeEntry>(handles);
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="handle">The handle entry.</param>
    public AlpcHandleMessageAttribute(AlpcHandleMessageAttributeEntry handle)
        : this(new AlpcHandleMessageAttributeEntry[] { handle })
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="objs">List of objects to create the handle entries.</param>
    /// <remarks>This constructor takes copies of the objects.</remarks>
    public AlpcHandleMessageAttribute(IEnumerable<NtObject> objs)
        : this(objs.Select(o => new AlpcHandleMessageAttributeEntry(o)))
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="obj">A single object to send.</param>
    /// <remarks>This constructor takes copies of the object.</remarks>
    public AlpcHandleMessageAttribute(NtObject obj)
        : this(new NtObject[] { obj })
    {
    }

    /// <summary>
    /// List of handles in this attribute.
    /// </summary>
    public IEnumerable<AlpcHandleMessageAttributeEntry> Handles => _handles.AsReadOnly();

    internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port, AlpcMessage message)
    {
        buffer.GetHandleAttribute(this, port, message);
    }

    internal override void ToSafeBuffer(SafeAlpcMessageAttributesBuffer buffer)
    {
        buffer.SetHandleAttribute(this);
    }

    internal void SetHandles(IEnumerable<AlpcHandleMessageAttributeEntry> handles)
    {
        _handles.Clear();
        _handles.AddRange(handles);
    }

    internal void AddHandles(IEnumerable<AlpcHandleMessageAttributeEntry> handles)
    {
        _handles.AddRange(handles);
    }
}
