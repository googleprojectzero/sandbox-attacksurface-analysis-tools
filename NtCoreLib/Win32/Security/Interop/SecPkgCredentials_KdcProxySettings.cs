//  Copyright 2022 Google LLC. All Rights Reserved.
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

namespace NtCoreLib.Win32.Security.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct SecPkgCredentials_KdcProxySettings
{
    internal const int KDC_PROXY_SETTINGS_V1 = 1;
    internal const int KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY = 0x1;

    public int Version;
    public int Flags;
    public ushort ProxyServerOffset;
    public ushort ProxyServerLength;
    public ushort ClientTlsCredOffset;
    public ushort ClientTlsCredLength;
}
