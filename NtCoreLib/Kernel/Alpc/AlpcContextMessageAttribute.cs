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
/// Class representing a security message attribute.
/// </summary>
public sealed class AlpcContextMessageAttribute : AlpcMessageAttribute
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public AlpcContextMessageAttribute()
        : base(AlpcMessageAttributeFlags.Context)
    {
    }

    /// <summary>
    /// Port context.
    /// </summary>
    public long PortContext { get; set; }
    /// <summary>
    /// Message context.
    /// </summary>
    public long MessageContext { get; set; }
    /// <summary>
    /// Sequence number.
    /// </summary>
    public int Sequence { get; set; }
    /// <summary>
    /// Message ID.
    /// </summary>
    public int MessageId { get; set; }
    /// <summary>
    /// Callback ID.
    /// </summary>
    public int CallbackId { get; set; }

    internal override void ToSafeBuffer(SafeAlpcMessageAttributesBuffer buffer)
    {
        buffer.SetContextAttribute(this);
    }

    internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port, AlpcMessage message)
    {
        buffer.GetContextAttribute(this);
    }

    internal AlpcContextAttr ToStruct()
    {
        return new AlpcContextAttr()
        {
            PortContext = new IntPtr(PortContext),
            MessageContext = new IntPtr(MessageContext),
            MessageId = MessageId,
            Sequence = Sequence,
            CallbackId = CallbackId,
        };
    }
}
