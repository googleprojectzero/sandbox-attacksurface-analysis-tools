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
    internal interface IMessageAttributes
    {
        SafeAlpcMessageAttributesBuffer ToSafeBuffer();
    }

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

            using (var buffer = SafeAlpcMessageAttributesBuffer.Create(flags))
            {
                foreach (var attr in _attributes.Values)
                {
                    attr.ToSafeBuffer(buffer);
                }

                var result = buffer.Result;
                result.ValidAttributes = flags;
                buffer.Result = result;
                return buffer.Detach();
            }
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

    /// <summary>
    /// Class to represent a set of received attributes.
    /// </summary>
    public sealed class AlpcReceiveMessageAttributes : IDisposable, IMessageAttributes
    {
        #region Private Members
        private Dictionary<AlpcMessageAttributeFlags, AlpcMessageAttribute> _attributes;
        private DisposableList<NtObject> _handles;

        SafeAlpcMessageAttributesBuffer IMessageAttributes.ToSafeBuffer()
        {
            return SafeAlpcMessageAttributesBuffer.Create(AllocatedAttributes);
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Constructor. Allocated space for all known attributes.
        /// </summary>
        public AlpcReceiveMessageAttributes() 
            : this(AlpcMessageAttributeFlags.AllAttributes)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public AlpcReceiveMessageAttributes(AlpcMessageAttributeFlags allocated_attributes)
        {
            AllocatedAttributes = allocated_attributes;
            _attributes = new Dictionary<AlpcMessageAttributeFlags, AlpcMessageAttribute>();
            _handles = new DisposableList<NtObject>();
            DataView = new SafeAlpcDataViewBuffer();
            SecurityContext = new SafeAlpcSecurityContextHandle();
        }
        #endregion

        #region Public Properties

        /// <summary>
        /// Get the allocated attributes.
        /// </summary>
        public AlpcMessageAttributeFlags AllocatedAttributes { get; set; }

        /// <summary>
        /// Get the list of valid attributes.
        /// </summary>
        public AlpcMessageAttributeFlags ValidAttributes { get; private set; }

        /// <summary>
        /// Get a list of the valid attributes.
        /// </summary>
        public IEnumerable<AlpcMessageAttribute> Attributes => _attributes.Values;

        /// <summary>
        /// Get list of passed handles.
        /// </summary>
        public IEnumerable<NtObject> Handles => _handles.AsReadOnly();

        /// <summary>
        /// Get the mapped data view. If no view sent this property is invalid.
        /// </summary>
        public SafeAlpcDataViewBuffer DataView { get; private set; }

        /// <summary>
        /// Get the security context. If no security context this property is invalid.
        /// </summary>
        public SafeAlpcSecurityContextHandle SecurityContext { get; private set; }

        #endregion

        #region Public Methods
        /// <summary>
        /// Dispose method.
        /// </summary>
        public void Dispose()
        {
            _handles.Dispose();
            DataView.Dispose();
            SecurityContext.Dispose();
        }

        /// <summary>
        /// Get a typed attribute.
        /// </summary>
        /// <typeparam name="T">The type of attribute to get.</typeparam>
        /// <returns>The attribute. Returns a default initialized object if not valid.</returns>
        public T GetAttribute<T>() where T : AlpcMessageAttribute, new()
        {
            T result = new T();
            if (_attributes.ContainsKey(result.AttributeFlag))
            {
                return (T)_attributes[result.AttributeFlag];
            }
            return result;
        }

        /// <summary>
        /// Get an attribute.
        /// </summary>
        /// <param name="flag">The attribute flag to get.</param>
        /// <returns>The attribute. Returns null if not found.</returns>
        public AlpcMessageAttribute GetAttribute(AlpcMessageAttributeFlags flag)
        {
            if (_attributes.ContainsKey(flag))
            {
                return _attributes[flag];
            }
            return null;
        }

        /// <summary>
        /// Convert this set of attributes to a buffer to send.
        /// </summary>
        /// <returns>The send attributes.</returns>
        public AlpcSendMessageAttributes ToSendAttributes()
        {
            return new AlpcSendMessageAttributes(Attributes);
        }

        /// <summary>
        /// Convert this set of attributes to one which can be used to free on continuation required.
        /// </summary>
        /// <param name="attributes">The attributes to </param>
        /// <returns>The send attributes.</returns>
        public AlpcSendMessageAttributes ToContinuationAttributes(AlpcMessageAttributeFlags attributes)
        {
            AlpcSendMessageAttributes ret = new AlpcSendMessageAttributes();
            if ((ValidAttributes & attributes & AlpcMessageAttributeFlags.View) != 0)
            {
                ret.Add(new AlpcDataViewMessageAttribute(0, 0, 0, AlpcDataViewAttrFlags.ReleaseView));
            }
            if ((ValidAttributes & attributes & AlpcMessageAttributeFlags.Handle) != 0)
            {
                ret.Add(new AlpcHandleMessageAttribute());
            }
            return ret;
        }

        /// <summary>
        /// Checks if an attribute flag is valid.
        /// </summary>
        /// <param name="attribute">The attribute to test.</param>
        /// <returns>True if the attribute is value.</returns>
        public bool HasValidAttribute(AlpcMessageAttributeFlags attribute)
        {
            return ValidAttributes.HasFlag(attribute);
        }

        #endregion

        #region Internal Members
        internal T AddAttribute<T>(SafeAlpcMessageAttributesBuffer buffer, 
            NtAlpc port, AlpcMessage message) where T : AlpcMessageAttribute, new()
        {
            T attribute = new T();
            attribute.FromSafeBuffer(buffer, port, message);
            _attributes.Add(attribute.AttributeFlag, attribute);
            ValidAttributes |= attribute.AttributeFlag;
            return attribute;
        }

        internal void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port, AlpcMessage message)
        {
            var result = buffer.Result;
            var valid_attrs = result.ValidAttributes;

            if (valid_attrs.HasFlag(AlpcMessageAttributeFlags.Token))
            {
                AddAttribute<AlpcTokenMessageAttribute>(buffer, port, message);
            }
            if (valid_attrs.HasFlag(AlpcMessageAttributeFlags.Context))
            {
                AddAttribute<AlpcContextMessageAttribute>(buffer, port, message);
            }
            if (valid_attrs.HasFlag(AlpcMessageAttributeFlags.Handle))
            {
                var attribute = AddAttribute<AlpcHandleMessageAttribute>(buffer, port, message);
                _handles.AddRange(attribute.Handles.Select(h => NtObjectUtils.FromHandle(h.Handle, true)));
            }
            if (valid_attrs.HasFlag(AlpcMessageAttributeFlags.Security))
            {
                var attr = AddAttribute<AlpcSecurityMessageAttribute>(buffer, port, message);
                SecurityContext = new SafeAlpcSecurityContextHandle(attr.ContextHandle, true, port, attr.Flags, attr.SecurityQoS);
            }
            if (valid_attrs.HasFlag(AlpcMessageAttributeFlags.View))
            {
                var attr = AddAttribute<AlpcDataViewMessageAttribute>(buffer, port, message);
                DataView = new SafeAlpcDataViewBuffer(new IntPtr(attr.ViewBase), attr.ViewSize,
                    new SafeAlpcPortSectionHandle(attr.SectionHandle, true, port), attr.Flags, true);
            }
            if (valid_attrs.HasFlag(AlpcMessageAttributeFlags.WorkOnBehalfOf))
            {
                AddAttribute<AlpcWorkOnBehalfMessageAttribute>(buffer, port, message);
            }
        }
        #endregion
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

        internal abstract void ToSafeBuffer(SafeAlpcMessageAttributesBuffer buffer);

        internal abstract void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port, AlpcMessage message);
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
                SecurityQoS = (SecurityQualityOfService)Marshal.PtrToStructure(attr.QoS,
                                                typeof(SecurityQualityOfService));
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

    /// <summary>
    /// Class representing a data view message attribute.
    /// </summary>
    public sealed class AlpcDataViewMessageAttribute : AlpcMessageAttribute
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public AlpcDataViewMessageAttribute()
            : base(AlpcMessageAttributeFlags.View)
        {
        }

        internal AlpcDataViewMessageAttribute(long view_base, long view_size, long section_handle, 
            AlpcDataViewAttrFlags flags) : this()
        {
            Flags = flags;
            ViewBase = view_base;
            ViewSize = view_size;
            SectionHandle = section_handle;
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

        internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port, AlpcMessage message)
        {
            buffer.GetViewAttribute(this);
        }

        internal void FromStruct(AlpcDataViewAttr attr)
        {
            Flags = attr.Flags;
            SectionHandle = attr.SectionHandle.Value;
            ViewBase = attr.ViewBase.ToInt64();
            ViewSize = attr.ViewSize.ToInt64();
        }

        internal AlpcDataViewAttr ToStruct()
        {
            return new AlpcDataViewAttr()
            {
                Flags = Flags,
                SectionHandle = SectionHandle,
                ViewBase = new IntPtr(ViewBase),
                ViewSize = new IntPtr(ViewSize)
            };
        }
    }

    /// <summary>
    /// Handle attribute entry.
    /// </summary>
    public class AlpcHandleMessageAttributeEntry
    {
        /// <summary>
        /// Handle flags.
        /// </summary>
        public AlpcHandleAttrFlags Flags { get; set; }
        /// <summary>
        /// The NT object.
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
        public AlpcHandleMessageAttributeEntry(AlpcHandleAttr attr)
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
        public AlpcHandleMessageAttributeEntry(AlpcHandleAttr32 attr)
        {
            Flags = attr.Flags;
            Handle = attr.Handle;
            ObjectType = attr.ObjectType;
            DesiredAccess = attr.DesiredAccess;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="info">Information structure to initialize from.</param>
        public AlpcHandleMessageAttributeEntry(AlpcMessageHandleInformation info)
        {
            Flags = info.Flags;
            Handle = info.Handle;
            ObjectType = info.ObjectType;
            DesiredAccess = info.GrantedAccess;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public AlpcHandleMessageAttributeEntry()
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="obj">The object to construct the entry from. Will take a copy of the handle.</param>
        public AlpcHandleMessageAttributeEntry(NtObject obj)
        {
            Flags = AlpcHandleAttrFlags.SameAccess | AlpcHandleAttrFlags.SameAttributes;
            Handle = obj.Handle.DangerousGetHandle().ToInt32();
        }
    }

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

    /// <summary>
    /// Class representing a work on behalf of message attribute.
    /// </summary>
    public sealed class AlpcWorkOnBehalfMessageAttribute : AlpcMessageAttribute
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public AlpcWorkOnBehalfMessageAttribute()
            : base(AlpcMessageAttributeFlags.WorkOnBehalfOf)
        {
        }

        /// <summary>
        /// Thread ID.
        /// </summary>
        public int ThreadId { get; set; }

        /// <summary>
        /// Thread creation time (low).
        /// </summary>
        public int ThreadCreationTimeLow { get; set; }

        internal override void FromSafeBuffer(SafeAlpcMessageAttributesBuffer buffer, NtAlpc port, AlpcMessage message)
        {
            buffer.GetWorkOnBehalfAttribute(this);
        }

        internal override void ToSafeBuffer(SafeAlpcMessageAttributesBuffer buffer)
        {
            buffer.SetWorkOnBehalfAttribute(this);
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
                    Handle =  new IntPtr(handle.Handle),
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
