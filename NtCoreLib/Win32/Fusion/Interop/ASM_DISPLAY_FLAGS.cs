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

namespace NtCoreLib.Win32.Fusion.Interop;

[Flags]
internal enum ASM_DISPLAY_FLAGS 
{
    ASM_DISPLAYF_VERSION = 0x01,
    ASM_DISPLAYF_CULTURE = 0x02,
    ASM_DISPLAYF_PUBLIC_KEY_TOKEN = 0x04,
    ASM_DISPLAYF_PUBLIC_KEY = 0x08,
    ASM_DISPLAYF_CUSTOM = 0x10,
    ASM_DISPLAYF_PROCESSORARCHITECTURE = 0x20,
    ASM_DISPLAYF_LANGUAGEID = 0x40,
    ASM_DISPLAYF_RETARGET = 0x80,
    ASM_DISPLAYF_CONFIG_MASK = 0x100,
    ASM_DISPLAYF_MVID = 0x200,
    ASM_DISPLAYF_FULL =
                      ASM_DISPLAYF_VERSION |
                      ASM_DISPLAYF_CULTURE |
                      ASM_DISPLAYF_PUBLIC_KEY_TOKEN |
                      ASM_DISPLAYF_RETARGET |
                      ASM_DISPLAYF_PROCESSORARCHITECTURE

}
