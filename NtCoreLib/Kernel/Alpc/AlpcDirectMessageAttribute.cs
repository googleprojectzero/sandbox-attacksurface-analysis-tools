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

using System;

namespace NtCoreLib.Kernel.Alpc;

/// <summary>
/// Class representing a direct message attribute.
/// </summary>
public sealed class AlpcDirectMessageAttribute : AlpcMessageAttribute
{
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="event_object">The event object.</param>
    public AlpcDirectMessageAttribute(NtEvent event_object)
        : base(AlpcMessageAttributeFlags.Direct)
    {
        Event = event_object.Duplicate();
    }

    /// <summary>
    /// The event object.
    /// </summary>
    public NtEvent Event { get; private set; }

    internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port, AlpcMessage message)
    {
        throw new NotImplementedException();
    }

    internal override void ToSafeBuffer(SafeAlpcMessageAttributesBuffer buffer)
    {
        buffer.SetDirectAttribute(this);
    }
}
