//  Copyright 2019 Google Inc. All Rights Reserved.
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
    public static class NtLdrNative
    {
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus LdrLoadDll(
            string DllPath,
            OptionalInt32 DllCharacteristics,
            UnicodeString DllName,
            out IntPtr DllHandle
        );

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus LdrLoadDll(
            IntPtr Flags,
            OptionalInt32 DllCharacteristics,
            UnicodeString DllName,
            out IntPtr DllHandle
        );

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus LdrUnloadDll(
            IntPtr DllHandle
        );

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus LdrGetProcedureAddress(
            IntPtr DllHandle,
            [In] AnsiString ProcedureName,
            int ProcedureNumber,
            out IntPtr ProcedureAddress
        );
    }

    [Flags]
    public enum RtlImageNtHeaderExFlags
    {
        None = 0,
        NoRangeCheck = 1,
    }

    public static partial class NtRtl
    {
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus RtlImageNtHeaderEx(
            RtlImageNtHeaderExFlags Flags,
            IntPtr Base,
            long Size,
            out IntPtr OutHeaders // PIMAGE_NT_HEADERS
        );
    }
#pragma warning restore 1591
}
