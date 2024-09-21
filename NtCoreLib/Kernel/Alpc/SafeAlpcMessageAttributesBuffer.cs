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
using NtCoreLib.Utilities.Collections;
using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace NtCoreLib.Kernel.Alpc;

/// <summary>
/// Safe buffer to store an allocated set of ALPC atributes.
/// </summary>
public sealed class SafeAlpcMessageAttributesBuffer : SafeStructureInOutBuffer<AlpcMessageAttributes>
{
    private readonly DisposableList _resources;

    private SafeAlpcMessageAttributesBuffer(int total_length) : base(total_length, false)
    {
        SafeBufferUtils.ZeroBuffer(this);
        _resources = new DisposableList();
    }

    private SafeAlpcMessageAttributesBuffer(IntPtr buffer, int length, bool owns_handle)
        : base(buffer, length, owns_handle)
    {
    }

    private SafeAlpcMessageAttributesBuffer()
        : this(IntPtr.Zero, 0, false)
    {
    }

    /// <summary>
    /// Get a pointer to an allocated attribute. Returns NULL if not available.
    /// </summary>
    /// <param name="attribute">The attribute to get.</param>
    /// <returns>The pointer to the attribute buffer, IntPtr.Zero if not found.</returns>
    public IntPtr GetAttributePointer(AlpcMessageAttributeFlags attribute)
    {
        return NtAlpcNativeMethods.AlpcGetMessageAttribute(this, attribute);
    }

    /// <summary>
    /// Get an attribute as a structured type.
    /// </summary>
    /// <typeparam name="T">The attribute type.</typeparam>
    /// <param name="attribute">The attribute.</param>
    /// <returns>A buffer which represents the structured type.</returns>
    /// <exception cref="NtException">Thrown if attribute doesn't exist.</exception>
    public SafeStructureInOutBuffer<T> GetAttribute<T>(AlpcMessageAttributeFlags attribute) where T : new()
    {
        IntPtr attr = GetAttributePointer(attribute);
        if (attr == IntPtr.Zero)
        {
            throw new NtException(NtStatus.STATUS_INVALID_PARAMETER);
        }
        return new SafeStructureInOutBuffer<T>(attr, Marshal.SizeOf(typeof(T)), false);
    }

    /// <summary>
    /// Create a new buffer with allocations for a specified set of attributes.
    /// </summary>
    /// <param name="flags">The attributes to allocate.</param>
    /// <returns>The allocated buffed.</returns>
    public static SafeAlpcMessageAttributesBuffer Create(AlpcMessageAttributeFlags flags)
    {
        NtStatus status = NtAlpcNativeMethods.AlpcInitializeMessageAttribute(flags, Null, 0, out int size);
        if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
        {
            throw new NtException(status);
        }

        SafeAlpcMessageAttributesBuffer buffer = new(size);
        NtAlpcNativeMethods.AlpcInitializeMessageAttribute(flags, buffer, buffer.Length, out size).ToNtException();
        return buffer;
    }

    internal void SetSecurityAttribute(AlpcSecurityMessageAttribute security_attribute)
    {
        var attr = GetAttribute<AlpcSecurityAttr>(AlpcMessageAttributeFlags.Security);
        var qos = _resources.AddStructure(security_attribute.SecurityQoS);

        attr.Result = new AlpcSecurityAttr()
        {
            Flags = security_attribute.Flags,
            QoS = qos.DangerousGetHandle(),
            ContextHandle = security_attribute.ContextHandle
        };
    }

    internal void SetTokenAttribute(AlpcTokenMessageAttribute token_attribute)
    {
        var attr = GetAttribute<AlpcTokenAttr>(AlpcMessageAttributeFlags.Token);
        attr.Result = new AlpcTokenAttr()
        {
            TokenId = token_attribute.TokenId,
            AuthenticationId = token_attribute.AuthenticationId,
            ModifiedId = token_attribute.ModifiedId
        };
    }

    internal void GetSecurityAttribute(AlpcSecurityMessageAttribute attribute)
    {
        var attr = GetAttribute<AlpcSecurityAttr>(AlpcMessageAttributeFlags.Security).Result;
        attribute.FromStruct(attr);
    }

    internal void GetTokenAttribute(AlpcTokenMessageAttribute attribute)
    {
        var attr = GetAttribute<AlpcTokenAttr>(AlpcMessageAttributeFlags.Token).Result;
        attribute.TokenId = attr.TokenId;
        attribute.ModifiedId = attr.ModifiedId;
        attribute.AuthenticationId = attr.AuthenticationId;
    }

    internal void GetContextAttribute(AlpcContextMessageAttribute attribute)
    {
        var attr = GetAttribute<AlpcContextAttr>(AlpcMessageAttributeFlags.Context).Result;
        attribute.PortContext = attr.PortContext.ToInt64();
        attribute.MessageContext = attr.MessageContext.ToInt64();
        attribute.MessageId = attr.MessageId;
        attribute.Sequence = attr.Sequence;
        attribute.CallbackId = attr.CallbackId;
    }

    internal void SetContextAttribute(AlpcContextMessageAttribute attribute)
    {
        var attr = GetAttribute<AlpcContextAttr>(AlpcMessageAttributeFlags.Context);
        attr.Result = attribute.ToStruct();
    }

    internal void GetViewAttribute(AlpcDataViewMessageAttribute attribute)
    {
        var attr = GetAttribute<AlpcDataViewAttr>(AlpcMessageAttributeFlags.View).Result;
        attribute.FromStruct(attr);
    }

    internal void SetViewAttribute(AlpcDataViewMessageAttribute attribute)
    {
        var attr = GetAttribute<AlpcDataViewAttr>(AlpcMessageAttributeFlags.View);
        attr.Result = attribute.ToStruct();
    }

    internal void GetIndirectHandleAttribute(AlpcHandleMessageAttribute attribute, NtAlpc port, AlpcMessage message)
    {
        // Indirect handle attributes need to be queried from the port.
        var attr = GetAttribute<AlpcHandleAttrIndirect>(AlpcMessageAttributeFlags.Handle).Result;
        attribute.SetHandles(Enumerable.Range(0, attr.HandleCount).Select(i => port.GetHandleInformation(message, i)));
    }

    internal void GetHandleAttribute(AlpcHandleMessageAttribute attribute, NtAlpc port, AlpcMessage message)
    {
        var attr = GetAttribute<AlpcHandleAttr>(AlpcMessageAttributeFlags.Handle).Result;
        if ((attr.Flags & AlpcHandleAttrFlags.Indirect) == AlpcHandleAttrFlags.Indirect)
        {
            if (port == null || message == null)
            {
                throw new ArgumentException("Can't rebuild indirect handle attribute without port and message");
            }
            GetIndirectHandleAttribute(attribute, port, message);
        }
        else if (attr.Handle != IntPtr.Zero)
        {
            attribute.SetHandles(new AlpcHandleMessageAttributeEntry[] { new AlpcHandleMessageAttributeEntry(attr) });
        }
        else
        {
            attribute.SetHandles(new AlpcHandleMessageAttributeEntry[0]);
        }
    }

    internal void GetWorkOnBehalfAttribute(AlpcWorkOnBehalfMessageAttribute attribute)
    {
        var attr = GetAttribute<AlpcWorkOnBehalfAttr>(AlpcMessageAttributeFlags.WorkOnBehalfOf).Result;
        attribute.ThreadId = attr.ThreadId;
        attribute.ThreadCreationTimeLow = attr.ThreadCreationTimeLow;
    }

    internal void SetWorkOnBehalfAttribute(AlpcWorkOnBehalfMessageAttribute attribute)
    {
        var attr = GetAttribute<AlpcWorkOnBehalfAttr>(AlpcMessageAttributeFlags.WorkOnBehalfOf);
        attr.Result = new AlpcWorkOnBehalfAttr()
        {
            ThreadId = attribute.ThreadId,
            ThreadCreationTimeLow = attribute.ThreadCreationTimeLow
        };
    }

    internal void SetDirectAttribute(AlpcDirectMessageAttribute attribute)
    {
        var attr = GetAttribute<AlpcDirectAttr>(AlpcMessageAttributeFlags.Direct);
        attr.Result = new AlpcDirectAttr()
        {
            Event = attribute.Event.Handle.DangerousGetHandle()
        };
    }

    internal void SetHandleAttribute(AlpcHandleMessageAttribute attribute)
    {
        // If no handle attributes then just zero the buffer.
        if (!attribute.Handles.Any())
        {
            var attr = GetAttribute<AlpcHandleAttr>(AlpcMessageAttributeFlags.Handle);
            attr.Result = new AlpcHandleAttr()
            {
                Flags = 0,
                ObjectType = 0,
                Handle = IntPtr.Zero,
                DesiredAccess = 0
            };
            return;
        }

        int count = attribute.Handles.Count();

        if (count > 1)
        {
            var attr = GetAttribute<AlpcHandleAttrIndirect>(AlpcMessageAttributeFlags.Handle);
            var handles = attribute.Handles.Select(h => new AlpcHandleAttr32()
            {
                Handle = h.Handle,
                ObjectType = h.ObjectType,
                Flags = h.Flags,
                DesiredAccess = h.DesiredAccess
            }
            );
            var handle_buffer = _resources.AddResource(handles.ToArray().ToBuffer());
            attr.Result = new AlpcHandleAttrIndirect()
            {
                HandleAttrArray = handle_buffer.DangerousGetHandle(),
                HandleCount = count,
                Flags = AlpcHandleAttrFlags.Indirect
            };
        }
        else
        {
            var attr = GetAttribute<AlpcHandleAttr>(AlpcMessageAttributeFlags.Handle);
            AlpcHandleMessageAttributeEntry handle = attribute.Handles.First();
            attr.Result = new AlpcHandleAttr()
            {
                Flags = handle.Flags,
                ObjectType = handle.ObjectType,
                Handle = new IntPtr(handle.Handle),
                DesiredAccess = handle.DesiredAccess
            };
        }
    }

    /// <summary>
    /// Dispose the safe buffer.
    /// </summary>
    /// <param name="disposing">True if disposing</param>
    protected override void Dispose(bool disposing)
    {
        _resources?.Dispose();
        base.Dispose(disposing);
    }

    /// <summary>
    /// Detaches the current buffer and allocates a new one.
    /// </summary>
    /// <returns>The detached buffer.</returns>
    /// <remarks>The original buffer will become invalid after this call.</remarks>
    [ReliabilityContract(Consistency.MayCorruptInstance, Cer.MayFail)]
    new public SafeAlpcMessageAttributesBuffer Detach()
    {
        RuntimeHelpers.PrepareConstrainedRegions();
        try // Needed for constrained region.
        {
            IntPtr handle = DangerousGetHandle();
            SetHandleAsInvalid();
            return new SafeAlpcMessageAttributesBuffer(handle, Length, true);
        }
        finally
        {
        }
    }

    /// <summary>
    /// Get the NULL buffer.
    /// </summary>
    new public static SafeAlpcMessageAttributesBuffer Null => new();
}
