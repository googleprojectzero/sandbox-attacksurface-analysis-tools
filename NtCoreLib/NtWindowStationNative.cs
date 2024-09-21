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

using NtApiDotNet.Utilities.Reflection;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum WindowStationAccessRights : uint
    {
        [SDKName("WINSTA_ENUMDESKTOPS")]
        EnumDesktops = 0x0001,
        [SDKName("WINSTA_READATTRIBUTES")]
        ReadAttributes = 0x0002,
        [SDKName("WINSTA_ACCESSCLIPBOARD")]
        AccessClipboard = 0x0004,
        [SDKName("WINSTA_CREATEDESKTOP")]
        CreateDesktop = 0x0008,
        [SDKName("WINSTA_WRITEATTRIBUTES")]
        WriteAttributes = 0x0010,
        [SDKName("WINSTA_ACCESSGLOBALATOMS")]
        AccessGlobalAtoms = 0x0020,
        [SDKName("WINSTA_EXITWINDOWS")]
        ExitWindows = 0x0040,
        [SDKName("WINSTA_ENUMERATE")]
        Enumerate = 0x0100,
        [SDKName("WINSTA_READSCREEN")]
        ReadScreen = 0x0200,
        [SDKName("GENERIC_READ")]
        GenericRead = GenericAccessRights.GenericRead,
        [SDKName("GENERIC_WRITE")]
        GenericWrite = GenericAccessRights.GenericWrite,
        [SDKName("GENERIC_EXECUTE")]
        GenericExecute = GenericAccessRights.GenericExecute,
        [SDKName("GENERIC_ALL")]
        GenericAll = GenericAccessRights.GenericAll,
        [SDKName("DELETE")]
        Delete = GenericAccessRights.Delete,
        [SDKName("READ_CONTROL")]
        ReadControl = GenericAccessRights.ReadControl,
        [SDKName("WRITE_DAC")]
        WriteDac = GenericAccessRights.WriteDac,
        [SDKName("WRITE_OWNER")]
        WriteOwner = GenericAccessRights.WriteOwner,
        [SDKName("SYNCHRONIZE")]
        Synchronize = GenericAccessRights.Synchronize,
        [SDKName("MAXIMUM_ALLOWED")]
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        [SDKName("ACCESS_SYSTEM_SECURITY")]
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
