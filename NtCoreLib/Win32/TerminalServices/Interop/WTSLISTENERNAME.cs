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

#nullable enable

using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.TerminalServices.Interop;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct WTSLISTENERNAME
{
    const int WTS_LISTENER_NAME_LENGTH = 32;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WTS_LISTENER_NAME_LENGTH+1)]
    public string Name;

    public WTSLISTENERNAME()
    {
        Name = new string('\0', WTS_LISTENER_NAME_LENGTH + 1);
    }

    public string GetName()
    {
        int index = Name.IndexOf('\0');
        if (index >= 0)
        {
            return Name.Substring(0, index);
        }
        return Name;
    }
}
