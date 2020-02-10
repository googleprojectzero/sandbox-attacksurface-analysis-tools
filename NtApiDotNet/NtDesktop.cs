//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class which represents a desktop object.
    /// </summary>
    [NtType("Desktop")]
    public class NtDesktop : NtObjectWithDuplicate<NtDesktop, DesktopAccessRights>
    {
        internal NtDesktop(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtDesktop> OpenInternal(ObjectAttributes obj_attributes,
                DesktopAccessRights desired_access, bool throw_on_error)
            {
                return NtDesktop.Open(obj_attributes, CreateDesktopFlags.None, desired_access, throw_on_error);
            }
        }

        /// <summary>
        /// Open a desktop by name.
        /// </summary>
        /// <param name="object_attributes">The object attributes for opening.</param>
        /// <param name="flags">Flags for opening the desktop.</param>
        /// <param name="desired_access">Desired access.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The instance of the desktop.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtDesktop> Open(ObjectAttributes object_attributes, CreateDesktopFlags flags, 
            DesktopAccessRights desired_access, bool throw_on_error)
        {
            SafeKernelObjectHandle handle = NtSystemCalls.NtUserOpenDesktop(object_attributes, flags, desired_access);
            if (handle.IsInvalid)
            {
                return NtObjectUtils.CreateResultFromDosError<NtDesktop>(Marshal.GetLastWin32Error(), throw_on_error);
            }
            return new NtResult<NtDesktop>(NtStatus.STATUS_SUCCESS, new NtDesktop(handle));
        }

        /// <summary>
        /// Open a desktop by name.
        /// </summary>
        /// <param name="object_attributes">The object attributes for opening.</param>
        /// <param name="flags">Flags for opening the desktop.</param>
        /// <param name="desired_access">Desired access.</param>
        /// <returns>The instance of the desktop.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtDesktop Open(ObjectAttributes object_attributes, CreateDesktopFlags flags,
            DesktopAccessRights desired_access)
        {
            return Open(object_attributes, flags, desired_access, true).Result;
        }

        /// <summary>
        /// Open a desktop by name.
        /// </summary>
        /// <param name="desktop_name">The name of the desktop.</param>
        /// <param name="root">Optional root object</param>
        /// <returns>An instance of NtDesktop.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtDesktop Open(string desktop_name, NtObject root)
        {
            using (ObjectAttributes obj_attributes 
                = new ObjectAttributes(desktop_name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obj_attributes, 0, DesktopAccessRights.MaximumAllowed, true).Result;
            }
        }

        /// <summary>
        /// Open a desktop by name.
        /// </summary>
        /// <param name="desktop_name">The name of the desktop.</param>
        /// <returns>An instance of NtDesktop.</returns>
        public static NtDesktop Open(string desktop_name)
        {
            return Open(desktop_name, null);
        }

        /// <summary>
        /// Create a new desktop.
        /// </summary>
        /// <param name="object_attributes">The object attributes for opening.</param>
        /// <param name="flags">Flags for opening the desktop.</param>
        /// <param name="desired_access">Desired access.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <param name="device">Device name.</param>
        /// <param name="dev_mode">Device mode.</param>
        /// <param name="heap_size">Heap size.</param>
        /// <returns>An instance of NtDesktop.</returns>
        public static NtResult<NtDesktop> Create(ObjectAttributes object_attributes, string device, 
            DEVMODE dev_mode, CreateDesktopFlags flags, DesktopAccessRights desired_access, int heap_size,
            bool throw_on_error)
        {

            SafeKernelObjectHandle handle = NtSystemCalls.NtUserCreateDesktopEx(object_attributes, 
                string.IsNullOrEmpty(device) ? null : new UnicodeString(device),
                dev_mode, flags, desired_access, heap_size);
            if (handle.IsInvalid)
            {
                return NtObjectUtils.CreateResultFromDosError<NtDesktop>(Marshal.GetLastWin32Error(), throw_on_error);
            }
            return new NtResult<NtDesktop>(NtStatus.STATUS_SUCCESS, new NtDesktop(handle));
        }

        /// <summary>
        /// Create a new desktop.
        /// </summary>
        /// <param name="object_attributes">The object attributes for opening.</param>
        /// <param name="flags">Flags for opening the desktop.</param>
        /// <param name="desired_access">Desired access.</param>
        /// <param name="device">Device name.</param>
        /// <param name="dev_mode">Device mode.</param>
        /// <param name="heap_size">Heap size.</param>
        /// <returns>An instance of NtDesktop.</returns>
        public static NtDesktop Create(ObjectAttributes object_attributes, string device,
            DEVMODE dev_mode, CreateDesktopFlags flags, DesktopAccessRights desired_access, int heap_size)
        {
            return Create(object_attributes, device, dev_mode, flags, desired_access, heap_size, true).Result;
        }

        /// <summary>
        /// Create a new desktop.
        /// </summary>
        /// <param name="desktop_name">The name of the desktop.</param>
        /// <param name="root">Optional root object</param>
        /// <returns>An instance of NtDesktop.</returns>
        public static NtDesktop Create(string desktop_name, NtObject root)
        {
            using (ObjectAttributes obj_attributes = new ObjectAttributes(desktop_name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obj_attributes, null, null, 0, DesktopAccessRights.MaximumAllowed, 0, true).Result;
            }
        }

        /// <summary>
        /// Create a new desktop.
        /// </summary>
        /// <param name="desktop_name">The name of the desktop.</param>
        /// <returns>An instance of NtDesktop.</returns>
        public static NtDesktop Create(string desktop_name)
        {
            return Create(desktop_name, null);
        }

        /// <summary>
        /// Get the desktop for a thread.
        /// </summary>
        /// <param name="thread_id">The thread ID of the thread.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The desktop result.</returns>
        public static NtResult<NtDesktop> GetThreadDesktop(int thread_id, bool throw_on_error)
        {
            var handle = NtSystemCalls.NtUserGetThreadDesktop(thread_id);
            if (handle == IntPtr.Zero)
            {
                return NtObjectUtils.CreateResultFromDosError<NtDesktop>(Marshal.GetLastWin32Error(), throw_on_error);
            }
            return new NtDesktop(new SafeKernelObjectHandle(handle, false)).CreateResult();
        }

        /// <summary>
        /// Get the desktop for a thread.
        /// </summary>
        /// <param name="thread_id">The thread ID of the thread.</param>
        /// <returns>The desktop result.</returns>
        public static NtDesktop GetThreadDesktop(int thread_id)
        {
            return GetThreadDesktop(thread_id, true).Result;
        }

        /// <summary>
        /// Get desktop for current thread.
        /// </summary>
        public static NtDesktop Current => GetThreadDesktop(NtThread.Current.ThreadId);

        /// <summary>
        /// Get list of top level Windows for this Desktop.
        /// </summary>
        public IEnumerable<NtWindow> Windows => NtWindow.GetWindows(this, NtWindow.Null, false, true, 0);

        /// <summary>
        /// Close the Desktop. This is different from normal Close as it destroys the Desktop.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status.</returns>
        public NtStatus CloseDesktop(bool throw_on_error = true)
        {
            if (!NtSystemCalls.NtUserCloseDesktop(Handle))
            {
                return NtObjectUtils.MapDosErrorToStatus().ToNtException(throw_on_error);
            }
            Handle.SetHandleAsInvalid();
            return NtStatus.STATUS_SUCCESS;
        }
    }
}
