//  Copyright 2023 Google LLC. All Rights Reserved.
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

#nullable enable

using NtCoreLib.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NtCoreLib.Win32.Loader.Interop;

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
internal delegate bool EnumResTypeProc(IntPtr hModule, IntPtr lpszType, IntPtr lParam);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
internal delegate bool EnumResNameProcDelegate(IntPtr hModule, IntPtr lpszType, IntPtr lpszName, IntPtr lParam);

[Flags]
internal enum FormatFlags
{
    AllocateBuffer = 0x00000100,
    FromHModule = 0x00000800,
    FromSystem = 0x00001000,
    IgnoreInserts = 0x00000200
}

internal static class NativeMethods
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeLoadLibraryHandle LoadLibraryEx(string name, IntPtr reserved, LoadLibraryFlags flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr GetProcAddress(SafeLoadLibraryHandle hModule, string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int GetModuleFileName(SafeLoadLibraryHandle hModule, [Out] StringBuilder lpFilename, int nSize);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    internal static extern IntPtr GetProcAddress(SafeLoadLibraryHandle hModule, IntPtr name);

    [DllImport("dbghelp.dll", SetLastError = true)]
    internal static extern IntPtr ImageDirectoryEntryToData(SafeLoadLibraryHandle Base, bool MappedAsImage, ushort DirectoryEntry, out int Size);

    [DllImport("dbghelp.dll", SetLastError = true)]
    internal static extern IntPtr ImageDirectoryEntryToDataEx(SafeLoadLibraryHandle Base, bool MappedAsImage, ushort DirectoryEntry, out int Size, out IntPtr FoundHeader);

    [DllImport("dbghelp.dll", SetLastError = true)]
    internal static extern IntPtr ImageNtHeader(
        IntPtr Base
    );

    [DllImport("dbghelp.dll", SetLastError = true)]
    internal static extern IntPtr ImageRvaToVa(
      IntPtr NtHeaders,
      IntPtr Base,
      int Rva,
      IntPtr LastRvaSection
    );

    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal static extern bool EnumResourceTypes(SafeLoadLibraryHandle hModule, EnumResTypeProc lpEnumFunc, IntPtr lParam);

    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal static extern bool EnumResourceNames(SafeLoadLibraryHandle hModule, SafeHandle lpszType,
        EnumResNameProcDelegate lpEnumFunc, IntPtr lParam);

    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal static extern IntPtr LoadResource(SafeLoadLibraryHandle hModule, IntPtr hResInfo);

    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal static extern IntPtr LockResource(IntPtr hResData);

    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal static extern int SizeofResource(SafeLoadLibraryHandle hModule, IntPtr hResInfo);

    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal static extern IntPtr FindResource(SafeLoadLibraryHandle hModule, SafeHandle lpName, SafeHandle lpType);

    [DllImport("user32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal static extern int LoadString(
        SafeLoadLibraryHandle hInstance,
        int uID,
        StringBuilder lpBuffer,
        int cchBufferMax
    );

    internal const int GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x00000004;
    internal const int GET_MODULE_HANDLE_EX_FLAG_PIN = 0x00000001;
    internal const int GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x00000002;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool GetModuleHandleEx(int dwFlags, IntPtr lpModuleName, out SafeLoadLibraryHandle phModule);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetModuleHandleExW")]
    internal static extern bool GetModuleHandleEx(int dwFlags, string lpModuleName, out SafeLoadLibraryHandle phModule);

    internal const ushort IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
    internal const ushort IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
    internal const ushort IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
    internal const ushort IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
    internal const ushort IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
    internal const int IMAGE_DEBUG_TYPE_CODEVIEW = 2;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int FormatMessage(
        FormatFlags dwFlags,
        IntPtr lpSource,
        uint dwMessageId,
        int dwLanguageId,
        out SafeLocalAllocBuffer lpBuffer,
        int nSize,
        IntPtr Arguments
    );
}