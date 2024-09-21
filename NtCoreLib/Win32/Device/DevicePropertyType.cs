//  Copyright 2019 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Win32.Device;

/// <summary>
/// Device property types.
/// </summary>
public enum DevicePropertyType
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    EMPTY = 0x00000000, // nothing, no property data
    NULL = 0x00000001, // null property data
    SBYTE = 0x00000002, // 8-bit signed int (SBYTE)
    BYTE = 0x00000003, // 8-bit unsigned int (BYTE)
    INT16 = 0x00000004, // 16-bit signed int (SHORT)
    UINT16 = 0x00000005, // 16-bit unsigned int (USHORT)
    INT32 = 0x00000006, // 32-bit signed int (LONG)
    UINT32 = 0x00000007, // 32-bit unsigned int (ULONG)
    INT64 = 0x00000008, // 64-bit signed int (LONG64)
    UINT64 = 0x00000009, // 64-bit unsigned int (ULONG64)
    FLOAT = 0x0000000A, // 32-bit floating-point (FLOAT)
    DOUBLE = 0x0000000B, // 64-bit floating-point (DOUBLE)
    DECIMAL = 0x0000000C, // 128-bit data (DECIMAL)
    GUID = 0x0000000D, // 128-bit unique identifier (GUID)
    CURRENCY = 0x0000000E, // 64 bit signed int currency value (CURRENCY)
    DATE = 0x0000000F, // date (DATE)
    FILETIME = 0x00000010, // file time (FILETIME)
    BOOLEAN = 0x00000011, // 8-bit boolean (DEVPROP_BOOLEAN)
    STRING = 0x00000012, // null-terminated string
    STRING_LIST = (STRING | LIST), // multi-sz string list
    SECURITY_DESCRIPTOR = 0x00000013, // self-relative binary SECURITY_DESCRIPTOR
    SECURITY_DESCRIPTOR_STRING = 0x00000014, // security descriptor string (SDDL format)
    DEVPROPKEY = 0x00000015, // device property key (DEVPROPKEY)
    DEVPROPTYPE = 0x00000016, // device property type (DEVPROPTYPE)
    BINARY   =   (BYTE|ARRAY), // custom binary data
    ERROR = 0x00000017, // 32-bit Win32 system error code
    NTSTATUS = 0x00000018, // 32-bit NTSTATUS code
    STRING_INDIRECT = 0x00000019, // string resource (@[path\]<dllname>,-<strId>)
    ARRAY = 0x00001000,  // array of fixed-sized data elements
    LIST = 0x00002000,  // list of variable-sized data elements
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
