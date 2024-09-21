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
    public enum DesktopAccessRights : uint
    {
        [SDKName("DESKTOP_READOBJECTS")]
        ReadObjects = 0x0001,
        [SDKName("DESKTOP_CREATEWINDOW")]
        CreateWindow = 0x0002,
        [SDKName("DESKTOP_CREATEMENU")]
        CreateMenu = 0x0004,
        [SDKName("DESKTOP_HOOKCONTROL")]
        HookControl = 0x0008,
        [SDKName("DESKTOP_JOURNALRECORD")]
        JournalRecord = 0x0010,
        [SDKName("DESKTOP_JOURNALPLAYBACK")]
        JournalPlayback = 0x0020,
        [SDKName("DESKTOP_ENUMERATE")]
        Enumerate = 0x0040,
        [SDKName("DESKTOP_WRITEOBJECTS")]
        WriteObjects = 0x0080,
        [SDKName("DESKTOP_SWITCHDESKTOP")]
        SwitchDesktop = 0x0100,
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
