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

namespace NtCoreLib.Kernel.Alpc;

/// <summary>
/// Class representing a security message attribute.
/// </summary>
public sealed class AlpcTokenMessageAttribute : AlpcMessageAttribute
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public AlpcTokenMessageAttribute()
        : base(AlpcMessageAttributeFlags.Token)
    {
    }

    /// <summary>
    /// Token ID of token.
    /// </summary>
    public Luid TokenId { get; set; }
    /// <summary>
    /// Authentication ID of token.
    /// </summary>
    public Luid AuthenticationId { get; set; }
    /// <summary>
    /// Modified ID of token
    /// </summary>
    public Luid ModifiedId { get; set; }

    internal override void ToSafeBuffer(SafeAlpcMessageAttributesBuffer buffer)
    {
        buffer.SetTokenAttribute(this);
    }

    internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port, AlpcMessage message)
    {
        buffer.GetTokenAttribute(this);
    }
}
