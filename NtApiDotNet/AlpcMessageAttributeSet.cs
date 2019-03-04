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

        /// <summary>
        /// Set the security attribute.
        /// </summary>
        /// <param name="security_attribute">The security attribute.</param>
        /// <remarks>The attribute must have allocated otherwise this will throw an exception.</remarks>
        public void SetSecurityAttribute(AlpcSecurityMessageAttribute security_attribute)
        {
            var attr = GetAttribute<AlpcSecurityAttr>(AlpcMessageAttributeFlags.Security);
            var qos = _resources.AddStructure(security_attribute.SecurityQoS);

            attr.Result = new AlpcSecurityAttr() { Flags = security_attribute.Flags,
                QoS = qos.DangerousGetHandle(), ContextHandle = security_attribute.ContextHandle
            };
        }

        /// <summary>
        /// Set the token attribute.
        /// </summary>
        /// <param name="token_attribute">The token attribute.</param>
        /// <remarks>The attribute must have allocated otherwise this will throw an exception.</remarks>
        public void SetTokenAttribute(AlpcTokenMessageAttribute token_attribute)
        {
            var attr = GetAttribute<AlpcTokenAttr>(AlpcMessageAttributeFlags.Token);
            attr.Result = new AlpcTokenAttr()
            {
                TokenId = token_attribute.TokenId,
                AuthenticationId = token_attribute.AuthenticationId,
                ModifiedId = token_attribute.ModifiedId
            };
        }

        /// <summary>
        /// Get the security attribute.
        /// </summary>
        /// <param name="attribute">The attribute to populate</param>
        public void GetSecurityAttribute(AlpcSecurityMessageAttribute attribute)
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

        /// <summary>
        /// Get the token attribute.
        /// </summary>
        /// <param name="attribute">The attribute to populate</param>
        public void GetTokenAttribute(AlpcTokenMessageAttribute attribute)
        {
            var attr = GetAttribute<AlpcTokenAttr>(AlpcMessageAttributeFlags.Token).Result;
            attribute.TokenId = attr.TokenId;
            attribute.ModifiedId = attr.ModifiedId;
            attribute.AuthenticationId = attr.AuthenticationId;
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
