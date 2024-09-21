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

using NtCoreLib.Utilities.Data;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Rpc.Interop;

[StructLayout(LayoutKind.Sequential), DataStart("IfId")]
internal class RPC_IF_ID_VECTOR
{
    public int Count;
    public IntPtr IfId; // RPC_IF_ID*
};
#pragma warning restore 1591
