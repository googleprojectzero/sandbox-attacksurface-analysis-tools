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

#nullable enable

using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.AppModel.Interop;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct INET_FIREWALL_APP_CONTAINER
{
    public IntPtr appContainerSid;
    public IntPtr userSid;
    public string appContainerName;
    public string displayName;
    public string description;
    public INET_FIREWALL_AC_CAPABILITIES capabilities;
    public INET_FIREWALL_AC_BINARIES binaries;
    public string workingDirectory;
    public string packageFullName;
}
