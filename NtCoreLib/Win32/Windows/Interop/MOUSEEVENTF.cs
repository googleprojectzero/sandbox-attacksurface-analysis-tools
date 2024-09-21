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

namespace NtCoreLib.Win32.Windows.Interop;

// From https://pinvoke.net/default.aspx/Structures/KEYBDINPUT.html.
[Flags]
internal enum MOUSEEVENTF
{
    ABSOLUTE = 0x8000,
    HWHEEL = 0x01000,
    MOVE = 0x0001,
    MOVE_NOCOALESCE = 0x2000,
    LEFTDOWN = 0x0002,
    LEFTUP = 0x0004,
    RIGHTDOWN = 0x0008,
    RIGHTUP = 0x0010,
    MIDDLEDOWN = 0x0020,
    MIDDLEUP = 0x0040,
    VIRTUALDESK = 0x4000,
    WHEEL = 0x0800,
    XDOWN = 0x0080,
    XUP = 0x0100
}
