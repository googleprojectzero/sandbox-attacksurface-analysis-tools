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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum EventAccessRights : uint
    {
        QueryState = 1,
        ModifyState = 2,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }
    public enum EventType
    {
        NotificationEvent,
        SynchronizationEvent
    }    

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateEvent(
            out SafeKernelObjectHandle EventHandle,
            EventAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            EventType EventType,
            bool InitialState);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenEvent(
            out SafeKernelObjectHandle EventHandle,
            EventAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetEvent(
            SafeHandle EventHandle,
            out int PreviousState);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtClearEvent(
            SafeHandle EventHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPulseEvent(
            SafeHandle EventHandle,
            out int PreviousState);
    }
#pragma warning restore 1591

    /// <summary>
    /// Class representing a NT Event object
    /// </summary>
    public class NtEvent : NtObjectWithDuplicate<NtEvent, EventAccessRights>
    {
        internal NtEvent(SafeKernelObjectHandle handle) 
            : base(handle)
        {
        }

        /// <summary>
        /// Set the event state
        /// </summary>
        /// <returns>The previous state of the event</returns>
        public int Set()
        {
            int previous_state;
            NtSystemCalls.NtSetEvent(Handle, out previous_state).ToNtException();
            return previous_state;
        }

        /// <summary>
        /// Clear the event state
        /// </summary>
        public void Clear()
        {            
            NtSystemCalls.NtClearEvent(Handle).ToNtException();
        }

        /// <summary>
        /// Pulse the event state.
        /// </summary>
        /// <returns>The previous state of the event</returns>
        public int Pulse()
        {
            int previous_state;
            NtSystemCalls.NtPulseEvent(Handle, out previous_state).ToNtException();
            return previous_state;
        }

        /// <summary>
        /// Create an event object
        /// </summary>
        /// <param name="name">The path to the event</param>
        /// <param name="root">The root object for relative path names</param>
        /// <param name="type">The type of the even</param>
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
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtCreateEvent(out handle, desired_access, object_attributes, type, initial_state).ToNtException();
            return new NtEvent(handle);        
        }

        /// <summary>
        /// Create an event object
        /// </summary>
        /// <param name="name">The path to the event</param>
        /// <param name="type">The type of the even</param>
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
                SafeKernelObjectHandle handle;
                NtSystemCalls.NtOpenEvent(out handle, desired_access, obja).ToNtException();
                return new NtEvent(handle);
            }
        }

        /// <summary>
        /// Open an event object
        /// </summary>
        /// <param name="object_attributes">The event object attributes</param>
        /// <param name="desired_access">The desired access for the event</param>
        /// <returns></returns>
        public static NtEvent Open(ObjectAttributes object_attributes, EventAccessRights desired_access)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtOpenEvent(out handle, desired_access, object_attributes).ToNtException();
            return new NtEvent(handle);        
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
    }
}
