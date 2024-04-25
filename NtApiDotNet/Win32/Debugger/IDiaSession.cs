//  Copyright 2018 Google Inc. All Rights Reserved.
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

// NOTE: This file is a modified version of SymbolResolver.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Debugger
{
    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("2F609EE1-D1C8-4E24-8288-3326BADCD211")]
    internal interface IDiaSession
    {
        [DispId(1)]
        ulong loadAddress
        {
            get;
            [param: In]
            set;
        }

        [DispId(2)]
        IDiaSymbol globalScope
        {
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }
        void getEnumTables();
        void getSymbolsByAddr();
        void findChildren();
        void findChildrenEx();
        void findChildrenExByAddr();
        void findChildrenExByVA();
        void findChildrenExByRVA();
        void findSymbolByAddr();
        void findSymbolByRVA();
        [PreserveSig]
        int findSymbolByVA([In] long va, [In] SymTagEnum symTag, [MarshalAs(UnmanagedType.Interface)] out IDiaSymbol ppSymbol);
    }
}
