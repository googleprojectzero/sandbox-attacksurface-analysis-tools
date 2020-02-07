//  Copyright 2020 Google Inc. All Rights Reserved.
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
    public enum WindowStationAccessRights : uint
    {
        EnumDesktops = 0x0001,
        ReadAttributes = 0x0002,
        AccessClipboard = 0x0004,
        CreateDesktop = 0x0008,
        WriteAttributes = 0x0010,
        AccessGlobalAtoms = 0x0020,
        ExitWindows = 0x0040,
        Enumerate = 0x0100,
        ReadScreen = 0x0200,
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
            WindowStationAccessRights DesiredAccess);

        [DllImport("win32u.dll", SetLastError = true)]
        public static extern SafeKernelObjectHandle NtUserCreateWindowStation(
            ObjectAttributes ObjectAttributes,
            WindowStationAccessRights DesiredAccess,
            SafeKernelObjectHandle KbdDllHandle,
            IntPtr KbdTablesOffset,     // Offset of tables returned from Ordinal 1 call from DLL base.
            IntPtr NlsTablesOffset,     // Offset of tables returned from Ordinal 2 call from DLL base.
            SafeBuffer KbdMultiDescriptor, // Buffer 0x318 bytes in size. Can be extracted using Ordinal 6.
            UnicodeString LanguageIdString, // e.g. "00000409"
            int KeyboardLocale); // e.g. 0x04090409 is US English and US Layout

        [DllImport("win32u.dll", SetLastError = true)]
        public static extern NtStatus NtUserBuildNameList(
            SafeKernelObjectHandle Handle, int Size, SafeBuffer NameList, out int RequiredSize);

        [DllImport("win32u.dll", SetLastError = true)]
        public static extern IntPtr NtUserGetProcessWindowStation();

        [DllImport("win32u.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool NtUserCloseWindowStation(SafeKernelObjectHandle handle);

        [DllImport("win32u.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool NtUserSetProcessWindowStation(SafeKernelObjectHandle handle);
    }

#pragma warning restore
}
