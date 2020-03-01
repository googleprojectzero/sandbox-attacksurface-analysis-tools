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

using System;

namespace NtApiDotNet.Win32.Debugger
{
    [Flags]
    enum SymOptions : uint
    {
        CASE_INSENSITIVE          = 0x00000001,
        UNDNAME                   = 0x00000002,
        DEFERRED_LOADS            = 0x00000004,
        NO_CPP                    = 0x00000008,
        LOAD_LINES                = 0x00000010,
        OMAP_FIND_NEAREST         = 0x00000020,
        LOAD_ANYTHING             = 0x00000040,
        IGNORE_CVREC              = 0x00000080,
        NO_UNQUALIFIED_LOADS      = 0x00000100,
        FAIL_CRITICAL_ERRORS      = 0x00000200,
        EXACT_SYMBOLS             = 0x00000400,
        ALLOW_ABSOLUTE_SYMBOLS    = 0x00000800,
        IGNORE_NT_SYMPATH         = 0x00001000,
        INCLUDE_32BIT_MODULES     = 0x00002000,
        PUBLICS_ONLY              = 0x00004000,
        NO_PUBLICS                = 0x00008000,
        AUTO_PUBLICS              = 0x00010000,
        NO_IMAGE_SEARCH           = 0x00020000,
        SECURE                    = 0x00040000,
        NO_PROMPTS                = 0x00080000,
        OVERWRITE                 = 0x00100000,
        IGNORE_IMAGEDIR           = 0x00200000,
        FLAT_DIRECTORY            = 0x00400000,
        FAVOR_COMPRESSED          = 0x00800000,
        ALLOW_ZERO_ADDRESS        = 0x01000000,
        DISABLE_SYMSRV_AUTODETECT = 0x02000000,
        READONLY_CACHE            = 0x04000000,
        SYMPATH_LAST              = 0x08000000,
        DISABLE_FAST_SYMBOLS      = 0x10000000,
        DISABLE_SYMSRV_TIMEOUT    = 0x20000000,
        DISABLE_SRVSTAR_ON_STARTUP = 0x40000000,
        DEBUG                     = 0x80000000,
    }
}
