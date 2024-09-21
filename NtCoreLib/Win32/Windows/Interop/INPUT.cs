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

using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Windows.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct INPUT
{
    internal INPUT_TYPE type;
    internal InputUnion U;

    public INPUT(VirtualKey vk, bool key_up)
    {
        type = INPUT_TYPE.KEYBOARD;
        U = new InputUnion
        {
            ki = new KEYBDINPUT()
            {
                wVk = vk,
                dwFlags = key_up ? KEYEVENTF.KEYUP : 0
            }
        };
    }
}
