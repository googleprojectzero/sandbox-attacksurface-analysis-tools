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
using NtCoreLib.Image.Security;

namespace NtCoreLib.Image.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct IMAGE_ENCLAVE_CONFIG
{
    public int Size;
    public int MinimumRequiredConfigSize;
    public ImageEnclavePolicyFlags PolicyFlags;
    public int NumberOfImports;
    public int ImportList;
    public int ImportEntrySize;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] FamilyID;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] ImageID;
    public int ImageVersion;
    public int SecurityVersion;
    public IntPtr EnclaveSize;
    public int NumberOfThreads;
    public ImageEnclaveFlag EnclaveFlags;
}
