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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum DesktopAccessRights : uint
    {
        ReadObjects         = 0x0001,
        CreateWindow        = 0x0002,
        CreateMenu          = 0x0004,
        HookControl         = 0x0008,
        JournalRecord       = 0x0010,
        JournalPlayback     = 0x0020,
        Enumerate           = 0x0040,
        WriteObjects        = 0x0080,
        SwitchDesktop       = 0x0100,
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

    public static partial class NtSystemCalls
    {
        [DllImport("win32u.dll", SetLastError = true)]
        public static extern SafeKernelObjectHandle NtUserOpenDesktop(
            ObjectAttributes ObjectAttributes, int Flags,
            DesktopAccessRights DesiredAccess);

        [DllImport("win32u.dll", SetLastError = true)]
        public static extern SafeKernelObjectHandle NtUserCreateDesktopEx(
            ObjectAttributes ObjectAttributes, UnicodeString Device, 
            IntPtr DevMode, int Flags,
            DesktopAccessRights DesiredAccess, 
            int HeapSize);
    }

#pragma warning restore

    /// <summary>
    /// Class which represents a desktop object.
    /// </summary>
    [NtType("Desktop")]
    public class NtDesktop : NtObjectWithDuplicate<NtDesktop, DesktopAccessRights>
    {
        internal NtDesktop(SafeKernelObjectHandle handle) : base(handle)
        {
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
        public static NtResult<NtDesktop> Open(ObjectAttributes object_attributes, int flags, DesktopAccessRights desired_access, bool throw_on_error)
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
            IntPtr dev_mode, int flags, DesktopAccessRights desired_access, int heap_size,
            bool throw_on_error)
        {

            SafeKernelObjectHandle handle = NtSystemCalls.NtUserCreateDesktopEx(object_attributes, 
                device == null ? null : new UnicodeString(device),
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
        /// <param name="desktop_name">The name of the desktop.</param>
        /// <param name="root">Optional root object</param>
        /// <returns>An instance of NtDesktop.</returns>
        public static NtDesktop Create(string desktop_name, NtObject root)
        {
            using (ObjectAttributes obj_attributes = new ObjectAttributes(desktop_name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obj_attributes, null, IntPtr.Zero, 0, DesktopAccessRights.MaximumAllowed, 0, true).Result;
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

        internal static NtResult<NtObject> FromName(ObjectAttributes object_attributes, AccessMask desired_access, bool throw_on_error)
        {
            return Open(object_attributes, 0, desired_access.ToSpecificAccess<DesktopAccessRights>(), throw_on_error).Cast<NtObject>();
        }
    }
}
