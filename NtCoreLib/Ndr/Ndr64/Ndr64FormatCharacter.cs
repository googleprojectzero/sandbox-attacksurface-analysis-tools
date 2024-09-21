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

using System;

namespace NtCoreLib.Ndr.Ndr64;

/// <summary>
/// NDR64 format characters.
/// </summary>
[Serializable]
public enum Ndr64FormatCharacter : byte
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    FC64_ZERO = 0x0,
    FC64_UINT8 = 0x1,
    FC64_INT8 = 0x2,
    FC64_UINT16 = 0x3,
    FC64_INT16 = 0x4,
    FC64_INT32 = 0x5,
    FC64_UINT32 = 0x6,
    FC64_INT64 = 0x7,
    FC64_UINT64 = 0x8,
    FC64_INT128 = 0x9,
    FC64_UINT128 = 0xA,
    FC64_FLOAT32 = 0xB,
    FC64_FLOAT64 = 0xC,
    FC64_FLOAT80 = 0xD,
    FC64_FLOAT128 = 0xE,
    FC64_CHAR = 0x10,
    FC64_WCHAR = 0x11,
    FC64_IGNORE = 0x12,
    FC64_ERROR_STATUS_T = 0x13,
    FC64_POINTER = 0x14,
    FC64_RP = 0x20,
    FC64_UP = 0x21,
    FC64_OP = 0x22,
    FC64_FP = 0x23,
    FC64_IP = 0x24,
    FC64_STRUCT = 0x30,
    FC64_PSTRUCT = 0x31,
    FC64_CONF_STRUCT = 0x32,
    FC64_CONF_PSTRUCT = 0x33,
    FC64_BOGUS_STRUCT = 0x34,
    FC64_FORCED_BOGUS_STRUCT = 0x35,
    FC64_CONF_BOGUS_STRUCT = 0x36,
    FC64_FORCED_CONF_BOGUS_STRUCT = 0x37,
    FC64_SYSTEM_HANDLE = 0x3C,
    FC64_FIX_ARRAY = 0x40,
    FC64_CONF_ARRAY = 0x41,
    FC64_VAR_ARRAY = 0x42,
    FC64_CONFVAR_ARRAY = 0x43,
    FC64_FIX_FORCED_BOGUS_ARRAY = 0x44,
    FC64_FIX_BOGUS_ARRAY = 0x45,
    FC64_FORCED_BOGUS_ARRAY = 0x46,
    FC64_BOGUS_ARRAY = 0x47,
    FC64_ENCAPSULATED_UNION = 0x50,
    FC64_NON_ENCAPSULATED_UNION = 0x51,
    FC64_CHAR_STRING = 0x60,
    FC64_WCHAR_STRING = 0x61,
    FC64_STRUCT_STRING = 0x62,
    FC64_CONF_CHAR_STRING = 0x63,
    FC64_CONF_WCHAR_STRING = 0x64,
    FC64_CONF_STRUCT_STRING = 0x65,
    FC64_BIND_CONTEXT = 0x70,
    FC64_BIND_GENERIC = 0x71,
    FC64_BIND_PRIMITIVE = 0x72,
    FC64_AUTO_HANDLE = 0x73,
    FC64_CALLBACK_HANDLE = 0x74,
    FC64_SUPPLEMENT = 0x75,
    FC64_NO_REPEAT = 0x80,
    FC64_FIXED_REPEAT = 0x81,
    FC64_VARIABLE_REPEAT = 0x82,
    FC64_FIXED_OFFSET = 0x83,
    FC64_VARIABLE_OFFSET = 0x84,
    FC64_STRUCTPADN = 0x90,
    FC64_EMBEDDED_COMPLEX = 0x91,
    FC64_BUFFER_ALIGN = 0x92,
    FC64_END = 0x93,
    FC64_TRANSMIT_AS = 0xA0,
    FC64_REPRESENT_AS = 0xA1,
    FC64_USER_MARSHAL = 0xA2,
    FC64_PIPE = 0xA3,
    FC64_RANGE = 0xA4,
    FC64_PAD = 0xA5,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
