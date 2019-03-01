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
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent a set of ALPC message attributes.
    /// </summary>
    public sealed class AlpcMessageAttributeSet : Dictionary<AlpcMessageAttributeFlags, AlpcMessageAttribute>
    {
        /// <summary>
        /// Add a message attribute.
        /// </summary>
        /// <param name="attribute">The message attribute to add.</param>
        public void Add(AlpcMessageAttribute attribute)
        {
            Add(attribute.AttributeFlag, attribute);
        }

        /// <summary>
        /// Add a message attribute.
        /// </summary>
        /// <param name="attribute"></param>
        public void Remove(AlpcMessageAttribute attribute)
        {
            Remove(attribute.AttributeFlag);
        }

        /// <summary>
        /// Allocate a safe buffer for this attribute set.
        /// </summary>
        /// <returns>The allocated safe buffer. If the set is empty then a Null buffer is returned.</returns>
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
                    attr.Add(buffer);
                }
                return buffer.Detach();
            }
        }

        /// <summary>
        /// Re-populate the set based on the results of a request.
        /// </summary>
        public void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer)
        {
            foreach(var attr in Values)
            {
                attr.Initialize(buffer);
            }
        }
    }

    /// <summary>
    /// Base class to represent a message attribute.
    /// </summary>
    public abstract class AlpcMessageAttribute
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

        /// <summary>
        /// Method to add the attribute to a buffer.
        /// </summary>
        /// <param name="buffer">The buffer to add the attribute to.</param>
        public abstract void Add(SafeAlpcMessageAttributesBuffer buffer);

        /// <summary>
        /// Method to initialize this attribute from a value in a safe buffer.
        /// </summary>
        /// <param name="buffer">The safe buffer to initialize from.</param>
        public abstract void Initialize(SafeAlpcMessageAttributesBuffer buffer);
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
        public IntPtr ContextHandle { get; set; }

        /// <summary>
        /// Method to add the attribute to a buffer.
        /// </summary>
        /// <param name="buffer">The buffer to add the attribute to.</param>
        public sealed override void Add(SafeAlpcMessageAttributesBuffer buffer)
        {
            buffer.SetSecurityAttribute(this);
        }

        /// <summary>
        /// Method to initialize this attribute from a value in a safe buffer.
        /// </summary>
        /// <param name="buffer">The safe buffer to initialize from.</param>
        public override void Initialize(SafeAlpcMessageAttributesBuffer buffer)
        {
            buffer.GetSecurityAttribute(this);
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
        /// <remarks>The security attribute must have allocated otherwise this will throw an exception.</remarks>
        public void SetSecurityAttribute(AlpcSecurityMessageAttribute security_attribute)
        {
            var attr = GetAttribute<AlpcSecurityAttr>(AlpcMessageAttributeFlags.Security);
            var qos = _resources.AddStructure(security_attribute.SecurityQoS);

            attr.Result = new AlpcSecurityAttr() { Flags = security_attribute.Flags,
                QoS = qos.DangerousGetHandle(), ContextHandle = security_attribute.ContextHandle
            };
        }

        /// <summary>
        /// Get the security attribute.
        /// </summary>
        /// <param name="security_attribute">The security attribute to populate</param>
        /// <remarks>The security attribute must have allocated otherwise this will throw an exception.</remarks>
        public void GetSecurityAttribute(AlpcSecurityMessageAttribute security_attribute)
        {
            var attr = GetAttribute<AlpcSecurityAttr>(AlpcMessageAttributeFlags.Security).Result;
            security_attribute.Flags = attr.Flags;
            security_attribute.ContextHandle = attr.ContextHandle;
            if (attr.QoS != IntPtr.Zero)
            {
                security_attribute.SecurityQoS = (SecurityQualityOfService)Marshal.PtrToStructure(attr.QoS,
                                                typeof(SecurityQualityOfService));
            }
            else
            {
                security_attribute.SecurityQoS = null;
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
