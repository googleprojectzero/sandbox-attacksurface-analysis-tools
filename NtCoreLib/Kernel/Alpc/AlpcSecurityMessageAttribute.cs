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

using NtCoreLib.Security.Token;
using NtCoreLib.Utilities.Memory;
using System;

namespace NtCoreLib.Kernel.Alpc;

/// <summary>
/// Class representing a security message attribute.
/// </summary>
public sealed class AlpcSecurityMessageAttribute : AlpcMessageAttribute
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public AlpcSecurityMessageAttribute()
        : base(AlpcMessageAttributeFlags.Security)
    {
    }

    internal AlpcSecurityMessageAttribute(AlpcSecurityAttr attr) : this()
    {
        FromStruct(attr);
    }

    /// <summary>
    /// Security attribute flags.
    /// </summary>
    public AlpcSecurityAttrFlags Flags { get; set; }

    /// <summary>
    /// Security quality of service.
    /// </summary>
    public SecurityQualityOfService SecurityQoS { get; set; }

    /// <summary>
    /// Context handle.
    /// </summary>
    public long ContextHandle { get; set; }

    /// <summary>
    /// Create an attribute which with create a handle automatically.
    /// </summary>
    /// <param name="security_quality_of_service">The security quality of service.</param>
    /// <returns>The security message attribute.</returns>
    public static AlpcSecurityMessageAttribute CreateHandleAttribute(SecurityQualityOfService security_quality_of_service)
    {
        return new AlpcSecurityMessageAttribute()
        {
            Flags = AlpcSecurityAttrFlags.CreateHandle,
            SecurityQoS = security_quality_of_service,
            ContextHandle = -2
        };
    }

    internal void FromStruct(AlpcSecurityAttr attr)
    {
        Flags = attr.Flags;
        ContextHandle = attr.ContextHandle.Value;
        if (attr.QoS != IntPtr.Zero)
        {
            SecurityQoS = attr.QoS.ReadStruct<SecurityQualityOfService>();
        }
        else
        {
            SecurityQoS = null;
        }
    }

    internal override void ToSafeBuffer(SafeAlpcMessageAttributesBuffer buffer)
    {
        buffer.SetSecurityAttribute(this);
    }

    internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port, AlpcMessage message)
    {
        buffer.GetSecurityAttribute(this);
    }
}
