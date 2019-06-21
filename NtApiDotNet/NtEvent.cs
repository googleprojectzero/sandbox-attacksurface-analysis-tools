//  Copyright 2016 Google Inc. All Rights Reserved.
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

using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class representing a NT Event object
    /// </summary>
    [NtType("Event")]
    public sealed class NtEvent : NtObjectWithDuplicateAndInfo<NtEvent, EventAccessRights, EventInformationClass, EventInformationClass>
    {
        #region Constructors
        internal NtEvent(SafeKernelObjectHandle handle) 
            : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtEvent> OpenInternal(ObjectAttributes obj_attributes,
                EventAccessRights desired_access, bool throw_on_error)
            {
                return NtEvent.Open(obj_attributes, desired_access, throw_on_error);
            }
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Create an event object
        /// </summary>
        /// <param name="name">The path to the event</param>
        /// <param name="root">The root object for relative path names</param>
        /// <param name="type">The type of the event</param>
        /// <param name="initial_state">The initial state of the event</param>
        /// <returns>The event object</returns>
        public static NtEvent Create(string name, NtObject root, EventType type, bool initial_state)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, type, initial_state, EventAccessRights.MaximumAllowed);
            }
        }

        /// <summary>
        /// Create an event object
        /// </summary>
        /// <param name="object_attributes">The event object attributes</param>
        /// <param name="type">The type of the event</param>
        /// <param name="initial_state">The initial state of the event</param>
        /// <param name="desired_access">The desired access for the event</param>
        /// <returns>The event object</returns>
        public static NtEvent Create(ObjectAttributes object_attributes, EventType type, bool initial_state, EventAccessRights desired_access)
        {
            return Create(object_attributes, type, initial_state, desired_access, true).Result;
        }


        /// <summary>
        /// Create an event object
        /// </summary>
        /// <param name="object_attributes">The event object attributes</param>
        /// <param name="type">The type of the event</param>
        /// <param name="initial_state">The initial state of the event</param>
        /// <param name="desired_access">The desired access for the event</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtEvent> Create(ObjectAttributes object_attributes, EventType type, bool initial_state, EventAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtCreateEvent(out SafeKernelObjectHandle handle, desired_access, 
                object_attributes, type, initial_state).CreateResult(throw_on_error, () => new NtEvent(handle));
        }

        /// <summary>
        /// Create an event object
        /// </summary>
        /// <param name="name">The path to the event</param>
        /// <param name="type">The type of the event</param>
        /// <param name="initial_state">The initial state of the event</param>
        /// <returns>The event object</returns>
        public static NtEvent Create(string name, EventType type, bool initial_state)
        {
            return Create(name, null, type, initial_state);
        }
        /// <summary>
        /// Open an event object
        /// </summary>
        /// <param name="name">The path to the event</param>
        /// <param name="root">The root object for relative path names</param>
        /// <param name="desired_access">The desired access for the event</param>
        /// <returns>The event object</returns>
        public static NtEvent Open(string name, NtObject root, EventAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access);
            }
        }

        /// <summary>
        /// Open an event object
        /// </summary>
        /// <param name="object_attributes">The event object attributes</param>
        /// <param name="desired_access">The desired access for the event</param>
        /// <returns>The event object.</returns>
        public static NtEvent Open(ObjectAttributes object_attributes, EventAccessRights desired_access)
        {
            return Open(object_attributes, desired_access, true).Result;
        }

        /// <summary>
        /// Open an event object
        /// </summary>
        /// <param name="object_attributes">The event object attributes</param>
        /// <param name="desired_access">The desired access for the event</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtEvent> Open(ObjectAttributes object_attributes, EventAccessRights desired_access, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            return NtSystemCalls.NtOpenEvent(out handle, desired_access, object_attributes).CreateResult(throw_on_error, () => new NtEvent(handle));
        }

        /// <summary>
        /// Open an event object
        /// </summary>
        /// <param name="name">The path to the event</param>
        /// <param name="root">The root object for relative path names</param>
        /// <returns>The event object</returns>
        public static NtEvent Open(string name, NtObject root)
        {
            return Open(name, root, EventAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open an event object
        /// </summary>
        /// <param name="name">The path to the event</param>
        /// <returns>The event object</returns>
        public static NtEvent Open(string name)
        {
            return Open(name, null);
        }
        #endregion

        #region Public Methods

        /// <summary>
        /// Set the event state
        /// </summary>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The previous state of the event and NT status.</returns>
        public NtResult<int> Set(bool throw_on_error)
        {
            return NtSystemCalls.NtSetEvent(Handle, out int previous_state).CreateResult(throw_on_error, () => previous_state);
        }

        /// <summary>
        /// Set the event state
        /// </summary>
        /// <returns>The previous state of the event</returns>
        public int Set()
        {
            return Set(true).Result;
        }

        /// <summary>
        /// Clear the event state
        /// </summary>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Clear(bool throw_on_error)
        {
            return NtSystemCalls.NtClearEvent(Handle).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Clear the event state
        /// </summary>
        public void Clear()
        {
            Clear(true);
        }

        /// <summary>
        /// Pulse the event state.
        /// </summary>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The previous state of the event and NT status.</returns>
        public NtResult<int> Pulse(bool throw_on_error)
        {
            return NtSystemCalls.NtPulseEvent(Handle, out int previous_state).CreateResult(throw_on_error, () => previous_state);
        }

        /// <summary>
        /// Pulse the event state.
        /// </summary>
        /// <returns>The previous state of the event</returns>
        public int Pulse()
        {
            return Pulse(true).Result;
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(EventInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryEvent(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Get event type.
        /// </summary>
        public EventType EventType => Query<EventBasicInformation>(EventInformationClass.EventBasicInformation).EventType;

        /// <summary>
        /// Get current event state.
        /// </summary>
        public int EventState => Query<EventBasicInformation>(EventInformationClass.EventBasicInformation).EventState;

        #endregion
    }
}
