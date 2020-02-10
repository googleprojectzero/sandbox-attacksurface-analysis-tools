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

    [StructLayout(LayoutKind.Sequential)]
    public struct DEVMODE_S1
    {
        public short dmOrientation;
        public short dmPaperSize;
        public short dmPaperLength;
        public short dmPaperWidth;
        public short dmScale;
        public short dmCopies;
        public short dmDefaultSource;
        public short dmPrintQuality;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct POINTL
    {
        public int x;
        public int y;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DEVMODE_S2
    {
        public POINTL dmPosition;
        public int dmDisplayOrientation;
        public int dmDisplayFixedOutput;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct DEVMODE_UNION1
    {
        [FieldOffset(0)]
        public DEVMODE_S1 s1;
        [FieldOffset(0)]
        public DEVMODE_S2 s2;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct DEVMODE_UNION2
    {
        [FieldOffset(0)]
        public int dmDisplayFlags;
        [FieldOffset(0)]
        public int dmNup;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public class DEVMODE
    {
        public const int CCHDEVICENAME = 32;
        public const int CCHFORMNAME = 32;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCHDEVICENAME)]
        public string dmDeviceName;
        public short dmSpecVersion;
        public short dmDriverVersion;
        public short dmSize;
        public short dmDriverExtra;
        public int dmFields;
        public DEVMODE_UNION1 u1;
        public short dmColor;
        public short dmDuplex;
        public short dmYResolution;
        public short dmTTOption;
        public short dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCHFORMNAME)]
        public string dmFormName;
        public short dmLogPixels;
        public int dmBitsPerPel;
        public int dmPelsWidth;
        public int dmPelsHeight;
        public DEVMODE_UNION2 u2;
        public int dmDisplayFrequency;
        public int dmICMMethod;
        public int dmICMIntent;
        public int dmMediaType;
        public int dmDitherType;
        public int dmReserved1;
        public int dmReserved2;
        public int dmPanningWidth;
        public int dmPanningHeight;
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
            DEVMODE DevMode, CreateDesktopFlags Flags,
            DesktopAccessRights DesiredAccess,
            int HeapSize);

        [DllImport("win32u.dll", SetLastError = true)]
        public static extern IntPtr NtUserGetThreadDesktop(int dwThreadId);

        [DllImport("win32u.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool NtUserCloseDesktop(SafeKernelObjectHandle handle);
    }

#pragma warning restore
}
