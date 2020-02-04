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
    public enum DesktopAccessRights : uint
    {
        ReadObjects = 0x0001,
        CreateWindow = 0x0002,
        CreateMenu = 0x0004,
        HookControl = 0x0008,
        JournalRecord = 0x0010,
        JournalPlayback = 0x0020,
        Enumerate = 0x0040,
        WriteObjects = 0x0080,
        SwitchDesktop = 0x0100,
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

    [Flags]
    public enum CreateDesktopFlags
    {
        None = 0,
        AllowOtherAccountHook = 1,
    }

    public static partial class NtSystemCalls
    {
        [DllImport("win32u.dll", SetLastError = true)]
        public static extern SafeKernelObjectHandle NtUserOpenDesktop(
            ObjectAttributes ObjectAttributes, CreateDesktopFlags Flags,
            DesktopAccessRights DesiredAccess);

        [DllImport("win32u.dll", SetLastError = true)]
        public static extern SafeKernelObjectHandle NtUserCreateDesktopEx(
            ObjectAttributes ObjectAttributes, UnicodeString Device,
            IntPtr DevMode, CreateDesktopFlags Flags,
            DesktopAccessRights DesiredAccess,
            int HeapSize);

        [DllImport("win32u.dll", SetLastError = true)]
        public static extern IntPtr NtUserGetThreadDesktop(int dwThreadId);
    }

#pragma warning restore
}
