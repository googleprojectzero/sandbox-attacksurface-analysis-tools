//  Copyright 2021 Google Inc. All Rights Reserved.
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

using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Net.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct MIB_TCP6ROW_OWNER_MODULE
{
    public IPv6Address ucLocalAddr;
    public uint dwLocalScopeId;
    public int dwLocalPort;
    public IPv6Address ucRemoteAddr;
    public uint dwRemoteScopeId;
    public int dwRemotePort;
    public int dwState;
    public int dwOwningPid;
    public LargeIntegerStruct liCreateTimestamp;
    public ulong OwningModuleInfo0;
    public ulong OwningModuleInfo1;
    public ulong OwningModuleInfo2;
    public ulong OwningModuleInfo3;
    public ulong OwningModuleInfo4;
    public ulong OwningModuleInfo5;
    public ulong OwningModuleInfo6;
    public ulong OwningModuleInfo7;
    public ulong OwningModuleInfo8;
    public ulong OwningModuleInfo9;
    public ulong OwningModuleInfo10;
    public ulong OwningModuleInfo11;
    public ulong OwningModuleInfo12;
    public ulong OwningModuleInfo13;
    public ulong OwningModuleInfo14;
    public ulong OwningModuleInfo15;
}
