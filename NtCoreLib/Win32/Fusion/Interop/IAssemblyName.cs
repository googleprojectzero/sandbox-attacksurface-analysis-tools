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
using System.Text;

namespace NtCoreLib.Win32.Fusion.Interop;

[ComImport, Guid("CD193BC0-B4BC-11d2-9833-00C04FC31D2E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IAssemblyName
{
    void SetProperty(
          int PropertyId,
          IntPtr pvProperty,
          int cbProperty);
    void GetProperty(
        int PropertyId,
        IntPtr pvProperty,
        ref int pcbProperty);

    void FinalizeCom();

    void GetDisplayName([In, Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder szDisplayName,
        ref int pccDisplayName,
        ASM_DISPLAY_FLAGS dwDisplayFlags);

    void Reserved();

    void GetName(ref int lpcwBuffer,
        [In, Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pwzName);

    void GetVersion(out int pdwVersionHi, out int pdwVersionLow);

    [PreserveSig]
    int IsEqual(IAssemblyName pName, int dwCmpFlags);

    IAssemblyName Clone();
};
