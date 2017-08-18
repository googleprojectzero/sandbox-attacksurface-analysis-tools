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
    public enum WindowStationAccessRights : uint
    {
        EnumDesktops         = 0x0001,
        ReadAttributes       = 0x0002,
        AccessClipboard      = 0x0004,
        CreateDesktop        = 0x0008,
        WriteAttributes      = 0x0010,
        AccessGlobalAtoms    = 0x0020,
        ExitWindows          = 0x0040,
        Enumerate            = 0x0100,
        ReadScreen           = 0x0200,
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
        public static extern SafeKernelObjectHandle NtUserOpenWindowStation(
            ObjectAttributes ObjectAttributes,
            DesktopAccessRights DesiredAccess);
    }

#pragma warning restore

    /// <summary>
    /// Class which represents a window station object.
    /// </summary>
    [NtType("WindowStation")]
    public class NtWindowStation : NtObjectWithDuplicate<NtWindowStation, WindowStationAccessRights>
    {
        internal NtWindowStation(SafeKernelObjectHandle handle) 
            : base(handle)
        {
        }

        /// <summary>
        /// Open a window station by name.
        /// </summary>
        /// <param name="winsta_name">The name of the window station</param>
        /// <param name="root">Optional root object</param>
        /// <returns>The instance of the window station</returns>
        /// <exception cref="Win32Exception">Thrown on error.</exception>
        public static NtWindowStation Open(string winsta_name, NtObject root)
        {
            using (ObjectAttributes obj_attr = new ObjectAttributes(winsta_name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle = NtSystemCalls.NtUserOpenWindowStation(obj_attr, DesktopAccessRights.MaximumAllowed);
                if (handle.IsInvalid)
                {
                    throw new Win32Exception();
                }
                return new NtWindowStation(handle);
            }
        }

        /// <summary>
        /// Open a window station by name.
        /// </summary>
        /// <param name="winsta_name"></param>
        /// <returns>The instance of the window station</returns>
        /// <exception cref="Win32Exception">Thrown on error.</exception>
        public static NtWindowStation Open(string winsta_name)
        {
            return Open(winsta_name, null);
        }
    }
}
