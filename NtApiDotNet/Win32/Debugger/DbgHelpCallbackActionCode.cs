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

// NOTE: This file is a modified version of SymbolResolver.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

namespace NtApiDotNet.Win32.Debugger
{
    internal enum DbgHelpCallbackActionCode : uint
    {
        CBA_DEFERRED_SYMBOL_LOAD_START = 0x00000001,
        CBA_DEFERRED_SYMBOL_LOAD_COMPLETE = 0x00000002,
        CBA_DEFERRED_SYMBOL_LOAD_FAILURE = 0x00000003,
        CBA_SYMBOLS_UNLOADED = 0x00000004,
        CBA_DUPLICATE_SYMBOL = 0x00000005,
        CBA_READ_MEMORY = 0x00000006,
        CBA_DEFERRED_SYMBOL_LOAD_CANCEL = 0x00000007,
        CBA_SET_OPTIONS = 0x00000008,
        CBA_EVENT = 0x00000010,
        CBA_DEFERRED_SYMBOL_LOAD_PARTIAL = 0x00000020,
        CBA_DEBUG_INFO = 0x10000000,
        CBA_SRCSRV_INFO = 0x20000000,
        CBA_SRCSRV_EVENT = 0x40000000,
        CBA_UPDATE_STATUS_BAR = 0x50000000,
        CBA_ENGINE_PRESENT = 0x60000000,
        CBA_CHECK_ENGOPT_DISALLOW_NETWORK_PATHS = 0x70000000,
        CBA_CHECK_ARM_MACHINE_THUMB_TYPE_OVERRIDE = 0x80000000,
        CBA_XML_LOG = 0x90000000,
    }
}
