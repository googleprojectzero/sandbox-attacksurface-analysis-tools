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
//  limitations under the License

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591

    public enum QueryWindowType
    {
        ProcessId = 0,
        Owner = 1,
        ThreadId = 2,
        Hung = 5,
    }

    public static partial class NtSystemCalls
    {
        [DllImport("win32u.dll")]
        public static extern NtStatus NtUserBuildHwndList(SafeKernelObjectHandle Desktop, IntPtr ParentWindow,
            [MarshalAs(UnmanagedType.Bool)] bool EnumerateChildren, bool HideImmersiveWindows, int ThreadId, int BufferCount,
            [Out, MarshalAs(UnmanagedType.LPArray)] IntPtr[] Buffer, out int RequiredCount);

        [DllImport("win32u.dll", SetLastError = true)]
        public static extern int NtUserQueryWindow(IntPtr Window, QueryWindowType query);

        [DllImport("win32u.dll", SetLastError = true)]
        public static extern int NtUserGetClassName(IntPtr Window, [MarshalAs(UnmanagedType.Bool)] bool RealName, UnicodeStringAllocated Name);
    }

#pragma warning restore
}
