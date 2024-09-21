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

using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.SideBySide.Interop;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal class ACTCTX
{
    public int cbSize;
    public ACTCTX_FLAG dwFlags;
    public string lpSource;
    public ushort wProcessorArchitecture;
    public ushort wLangId;
    public string lpAssemblyDirectory;
    public IntPtr lpResourceName;
    public string lpApplicationName;
    public IntPtr hModule;

    public ACTCTX()
    {
        cbSize = Marshal.SizeOf<ACTCTX>();
    }

    public ACTCTX(string path, SafeHandle resource) : this()
    {
        lpSource = path;
        if (resource != null)
        {
            lpResourceName = resource.DangerousGetHandle();
            dwFlags |= ACTCTX_FLAG.ACTCTX_FLAG_RESOURCE_NAME_VALID;
        }
    }
}
