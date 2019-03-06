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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent a set of ALPC message attributes.
    /// </summary>
    /// <remarks>This class is used both as an input and out for many calls to ALPC APIs.</remarks>
    public sealed class AlpcMessageAttributeSet : Dictionary<AlpcMessageAttributeFlags, AlpcMessageAttribute>, IDisposable
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public AlpcMessageAttributeSet()
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="attrs">List of attributes to build the buffer from.</param>
        public AlpcMessageAttributeSet(IEnumerable<AlpcMessageAttribute> attrs) 
            : base(attrs.ToDictionary(a => a.AttributeFlag, a => a))
        {
        }

        /// <summary>
        /// Dispose method.
        /// </summary>
        public void Dispose()
        {
            foreach (var attr in Values)
            {
                attr.Dispose();
            }
        }

        /// <summary>
        /// Add an attribute object.
        /// </summary>
        /// <param name="attribute">The attribute to add.</param>
        public void Add(AlpcMessageAttribute attribute)
        {
            Add(attribute.AttributeFlag, attribute);
        }

        /// <summary>
        /// Remove an attribute object.
        /// </summary>
        /// <param name="attribute">The attribute to remove.</param>
        public void Remove(AlpcMessageAttribute attribute)
        {
            Remove(attribute.AttributeFlag);
        }

        /// <summary>
        /// Convert the set to a safe buffer.
        /// </summary>
        /// <returns>The converted safe buffer.</returns>
        public SafeAlpcMessageAttributesBuffer ToSafeBuffer()
        {
            if (Count == 0)
            {
                return SafeAlpcMessageAttributesBuffer.Null;
            }

            AlpcMessageAttributeFlags flags = AlpcMessageAttributeFlags.None;
            foreach (var flag in Keys)
            {
                flags |= flag;
            }

            using (var buffer = SafeAlpcMessageAttributesBuffer.Create(flags))
            {
                foreach (var attr in Values)
                {
                    attr.ToSafeBuffer(buffer);
                }
                return buffer.Detach();
            }
        }

        internal void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port)
        {
            foreach (var attr in Values)
            {
                attr.FromSafeBuffer(buffer, port);
            }
        }
    }

    /// <summary>
    /// Base class to represent a message attribute.
    /// </summary>
    public abstract class AlpcMessageAttribute : IDisposable
    {
        /// <summary>
        /// The flag for this attribute.
        /// </summary>
        public AlpcMessageAttributeFlags AttributeFlag { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="attribute_flag">The single attribute flag which this represents.</param>
        protected AlpcMessageAttribute(AlpcMessageAttributeFlags attribute_flag)
        {
            AttributeFlag = attribute_flag;
        }

        internal abstract void ToSafeBuffer(SafeAlpcMessageAttributesBuffer buffer);

        internal abstract void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port);

        /// <summary>
        /// Dispose this message attribute.
        /// </summary>
        public virtual void Dispose()
        {
        }
    }

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

        internal override void ToSafeBuffer(SafeAlpcMessageAttributesBuffer buffer)
        {
            buffer.SetSecurityAttribute(this);
        }

        internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port)
        {
            buffer.GetSecurityAttribute(this);
        }
    }

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

        internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port)
        {
            buffer.GetTokenAttribute(this);
        }
    }

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

        internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port)
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

    /// <summary>
    /// Class representing a data view message attribute.
    /// </summary>
    public sealed class AlpcViewMessageAttribute : AlpcMessageAttribute
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public AlpcViewMessageAttribute()
            : base(AlpcMessageAttributeFlags.View)
        {
        }

        /// <summary>
        /// View flags.
        /// </summary>
        public AlpcDataViewAttrFlags Flags { get; set; }
        /// <summary>
        /// Handle to section.
        /// </summary>
        public long SectionHandle { get; set; }
        /// <summary>
        /// View base.
        /// </summary>
        public long ViewBase { get; set; }
        /// <summary>
        /// View size.
        /// </summary>
        public long ViewSize { get; set; }

        internal override void ToSafeBuffer(SafeAlpcMessageAttributesBuffer buffer)
        {
            buffer.SetViewAttribute(this);
        }

        internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port)
        {
            buffer.GetViewAttribute(this);
        }
    }

    /// <summary>
    /// Handle attribute entry.
    /// </summary>
    public class AlpcHandleEntry
    {
        /// <summary>
        /// Handle flags.
        /// </summary>
        public AlpcHandleAttrFlags Flags { get; set; }
        /// <summary>
        /// The handle value.
        /// </summary>
        public int Handle { get; set; }
        /// <summary>
        /// The object type for the handle.
        /// </summary>
        public AlpcHandleObjectType ObjectType { get; set; }
        /// <summary>
        /// Desired access for the handle.
        /// </summary>
        public AccessMask DesiredAccess { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="attr">Handle attribute to initialize from.</param>
        public AlpcHandleEntry(AlpcHandleAttr attr)
        {
            Flags = attr.Flags;
            Handle = attr.Handle.ToInt32();
            ObjectType = attr.ObjectType;
            DesiredAccess = attr.DesiredAccess;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="attr">Handle attribute to initialize from.</param>
        public AlpcHandleEntry(AlpcHandleAttr32 attr)
        {
            Flags = attr.Flags;
            Handle = attr.Handle;
            ObjectType = attr.ObjectType;
            DesiredAccess = attr.DesiredAccess;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public AlpcHandleEntry()
        {
        }
    }

    /// <summary>
    /// Class representing a handle message attribute.
    /// </summary>
    public sealed class AlpcHandleMessageAttribute : AlpcMessageAttribute
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public AlpcHandleMessageAttribute() 
            : base(AlpcMessageAttributeFlags.Handle)
        {
            Handles = new List<AlpcHandleEntry>();
        }

        /// <summary>
        /// List of handles in this attribute.
        /// </summary>
        public IList<AlpcHandleEntry> Handles { get; }

        internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port)
        {
            buffer.GetHandleAttribute(this);
        }

        internal override void ToSafeBuffer(SafeAlpcMessageAttributesBuffer buffer)
        {
            buffer.SetHandleAttribute(this);
        }
    }

    /// <summary>
    /// Safe buffer to store an allocated set of ALPC atributes.
    /// </summary>
    public sealed class SafeAlpcMessageAttributesBuffer : SafeStructureInOutBuffer<AlpcMessageAttributes>
    {
        private readonly DisposableList _resources;

        private SafeAlpcMessageAttributesBuffer(int total_length) : base(total_length, false)
        {
            BufferUtils.ZeroBuffer(this);
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

            SafeAlpcMessageAttributesBuffer buffer = new SafeAlpcMessageAttributesBuffer(size);
            NtAlpcNativeMethods.AlpcInitializeMessageAttribute(flags, buffer, buffer.Length, out size).ToNtException();
            return buffer;
        }

        internal void SetSecurityAttribute(AlpcSecurityMessageAttribute security_attribute)
        {
            var attr = GetAttribute<AlpcSecurityAttr>(AlpcMessageAttributeFlags.Security);
            var qos = _resources.AddStructure(security_attribute.SecurityQoS);

            attr.Result = new AlpcSecurityAttr() { Flags = security_attribute.Flags,
                QoS = qos.DangerousGetHandle(), ContextHandle = security_attribute.ContextHandle
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
            attribute.Flags = attr.Flags;
            attribute.ContextHandle = attr.ContextHandle.Value;
            if (attr.QoS != IntPtr.Zero)
            {
                attribute.SecurityQoS = (SecurityQualityOfService)Marshal.PtrToStructure(attr.QoS,
                                                typeof(SecurityQualityOfService));
            }
            else
            {
                attribute.SecurityQoS = null;
            }
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

        internal void GetViewAttribute(AlpcViewMessageAttribute attribute)
        {
            var attr = GetAttribute<AlpcDataViewAttr>(AlpcMessageAttributeFlags.View).Result;
            attribute.Flags = attr.Flags;
            attribute.SectionHandle = attr.SectionHandle.Value;
            attribute.ViewBase = attr.ViewBase.ToInt64();
            attribute.ViewSize = attr.ViewSize.ToInt64();
        }

        internal void SetViewAttribute(AlpcViewMessageAttribute attribute)
        {
            var attr = GetAttribute<AlpcDataViewAttr>(AlpcMessageAttributeFlags.View);
            attr.Result = new AlpcDataViewAttr()
            {
                Flags = attribute.Flags,
                SectionHandle = attribute.SectionHandle,
                ViewBase = new IntPtr(attribute.ViewBase),
                ViewSize = new IntPtr(attribute.ViewSize)
            };
        }

        internal void GetHandleAttribute(AlpcHandleMessageAttribute attribute)
        {
            var attr = GetAttribute<AlpcHandleAttr>(AlpcMessageAttributeFlags.Handle).Result;
            if ((attr.Flags & AlpcHandleAttrFlags.Indirect) == AlpcHandleAttrFlags.Indirect)
            {
                throw new ArgumentException("Can't read an indirect handle attribute.", nameof(attribute));
            }

            attribute.Handles.Clear();
            attribute.Handles.Add(new AlpcHandleEntry(attr));
        }

        internal void SetHandleAttribute(AlpcHandleMessageAttribute attribute)
        {
            if (attribute.Handles.Count == 0)
            {
                throw new ArgumentException("Handle attribute must contain at least one handle", nameof(attribute));
            }

            if (attribute.Handles.Count > 1)
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
                    HandleCount = attribute.Handles.Count,
                    Flags = AlpcHandleAttrFlags.Indirect
                };
            }
            else
            {
                var attr = GetAttribute<AlpcHandleAttr>(AlpcMessageAttributeFlags.Handle);
                AlpcHandleEntry handle = attribute.Handles[0];
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
        new public static SafeAlpcMessageAttributesBuffer Null => new SafeAlpcMessageAttributesBuffer();
    }
}
