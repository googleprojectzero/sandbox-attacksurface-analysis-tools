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

using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.TerminalServices.Interop;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct WTS_SESSION_INFO_1
{
    public int ExecEnvId;
    public ConsoleSessionConnectState State;
    public int SessionId;
    [MarshalAs(UnmanagedType.LPWStr)]
    public string pSessionName;
    [MarshalAs(UnmanagedType.LPWStr)]
    public string pHostName;
    [MarshalAs(UnmanagedType.LPWStr)]
    public string pUserName;
    [MarshalAs(UnmanagedType.LPWStr)]
    public string pDomainName;
    [MarshalAs(UnmanagedType.LPWStr)]
    public string pFarmName;
}
