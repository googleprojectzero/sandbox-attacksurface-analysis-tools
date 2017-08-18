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
using System.ComponentModel;
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
        /// <param name="desktop_name">The name of the desktop.</param>
        /// <param name="root">Optional root object</param>
        /// <returns>An instance of NtDesktop.</returns>
        /// <exception cref="Win32Exception">Thrown on error.</exception>
        public static NtDesktop Open(string desktop_name, NtObject root)
        {
            using (ObjectAttributes obj_attributes 
                = new ObjectAttributes(desktop_name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle = NtSystemCalls.NtUserOpenDesktop(obj_attributes, 0, DesktopAccessRights.MaximumAllowed);
                if (handle.IsInvalid)
                {
                    throw new Win32Exception();
                }
                return new NtDesktop(handle);
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
        /// <param name="desktop_name">The name of the desktop.</param>
        /// <param name="root">Optional root object</param>
        /// <returns>An instance of NtDesktop.</returns>
        public static NtDesktop Create(string desktop_name, NtObject root)
        {
            using (ObjectAttributes obj_attributes = new ObjectAttributes(desktop_name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle = NtSystemCalls.NtUserCreateDesktopEx(obj_attributes, null, 
                    IntPtr.Zero, 0, DesktopAccessRights.MaximumAllowed, 0);
                if (handle.IsInvalid)
                {
                    throw new Win32Exception();
                }
                return new NtDesktop(handle);
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
    }
}
