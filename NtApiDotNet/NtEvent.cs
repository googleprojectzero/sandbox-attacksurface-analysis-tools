//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System.Runtime.InteropServices;

namespace NtApiDotNet
{
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
            ObjectAttributes ObjectAttributes,
            EventType EventType,
            bool InitialState);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenEvent(
            out SafeKernelObjectHandle EventHandle,
            EventAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes);

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

    public class NtEvent : NtObjectWithDuplicate<NtEvent, EventAccessRights>
    {
        internal NtEvent(SafeKernelObjectHandle handle) 
            : base(handle)
        {
        }

        public int Set()
        {
            int previous_state;
            StatusToNtException(NtSystemCalls.NtSetEvent(Handle, out previous_state));
            return previous_state;
        }

        public void Clear()
        {            
            StatusToNtException(NtSystemCalls.NtClearEvent(Handle));            
        }

        public int Pulse()
        {
            int previous_state;
            StatusToNtException(NtSystemCalls.NtPulseEvent(Handle, out previous_state));
            return previous_state;
        }

        public static NtEvent Create(string name, NtObject root, EventType type, bool initial_state)
        {            
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtCreateEvent(out handle, EventAccessRights.MaximumAllowed, obja, type, initial_state));
                return new NtEvent(handle);
            }
        }

        public static NtEvent Create(string name, EventType type, bool initial_state)
        {
            return Create(name, null, type, initial_state);
        }

        public static NtEvent Open(string name, NtObject root, EventAccessRights access)
        {            
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtOpenEvent(out handle, access, obja));
                return new NtEvent(handle);
            }
        }

        public static NtEvent Open(string name, NtObject root)
        {
            return Open(name, root, EventAccessRights.MaximumAllowed);
        }

        public static NtEvent Open(string name)
        {
            return Open(name, null);
        }
    }
}
