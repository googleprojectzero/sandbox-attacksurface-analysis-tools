//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtCoreLib.Utilities.Reflection;
using System;

namespace NtCoreLib.Win32.Printing;

/// <summary>
/// Attributes for a printer object.
/// </summary>
[Flags]
public enum PrinterAttributes
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    None = 0,
    [SDKName("PRINTER_ATTRIBUTE_QUEUED")]
    Queued = 0x00000001,
    [SDKName("PRINTER_ATTRIBUTE_DIRECT")]
    Direct = 0x00000002,
    [SDKName("PRINTER_ATTRIBUTE_DEFAULT")]
    Default = 0x00000004,
    [SDKName("PRINTER_ATTRIBUTE_SHARED")]
    Shared = 0x00000008,
    [SDKName("PRINTER_ATTRIBUTE_NETWORK")]
    Network = 0x00000010,
    [SDKName("PRINTER_ATTRIBUTE_HIDDEN")]
    Hidden = 0x00000020,
    [SDKName("PRINTER_ATTRIBUTE_LOCAL")]
    Local = 0x00000040,
    [SDKName("PRINTER_ATTRIBUTE_ENABLE_DEVQ")]
    EnableDevQ = 0x00000080,
    [SDKName("PRINTER_ATTRIBUTE_KEEPPRINTEDJOBS")]
    KeepPrintedJobs = 0x00000100,
    [SDKName("PRINTER_ATTRIBUTE_DO_COMPLETE_FIRST")]
    DoCompleteFirst = 0x00000200,
    [SDKName("PRINTER_ATTRIBUTE_WORK_OFFLINE")]
    WorkOffline = 0x00000400,
    [SDKName("PRINTER_ATTRIBUTE_ENABLE_BIDI")]
    EnableBiDi = 0x00000800,
    [SDKName("PRINTER_ATTRIBUTE_RAW_ONLY")]
    RawOnly = 0x00001000,
    [SDKName("PRINTER_ATTRIBUTE_PUBLISHED")]
    Published = 0x00002000,
    [SDKName("PRINTER_ATTRIBUTE_FAX")]
    Fax = 0x00004000,
    [SDKName("PRINTER_ATTRIBUTE_TS")]
    Ts = 0x00008000,
    [SDKName("PRINTER_ATTRIBUTE_PUSHED_USER")]
    PushedUser = 0x00020000,
    [SDKName("PRINTER_ATTRIBUTE_PUSHED_MACHINE")]
    PushedMachine = 0x00040000,
    [SDKName("PRINTER_ATTRIBUTE_MACHINE")]
    Machine = 0x00080000,
    [SDKName("PRINTER_ATTRIBUTE_FRIENDLY_NAME")]
    FriendlyName = 0x00100000,
    [SDKName("PRINTER_ATTRIBUTE_TS_GENERIC_DRIVER")]
    TsGenericDriver = 0x00200000,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
