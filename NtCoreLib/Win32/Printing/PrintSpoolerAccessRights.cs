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

using NtApiDotNet.Utilities.Reflection;
using System;

namespace NtApiDotNet.Win32.Printing
{
    /// <summary>
    /// Access rights for a print spooler object.
    /// </summary>
    [Flags]
    public enum PrintSpoolerAccessRights : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("SERVER_ACCESS_ADMINISTER")]
        ServerAdminister    = 0x00000001,
        [SDKName("SERVER_ACCESS_ENUMERATE")]
        ServerEnumerate     = 0x00000002,
        [SDKName("PRINTER_ACCESS_ADMINISTER")]
        PrinterAdminister   = 0x00000004,
        [SDKName("PRINTER_ACCESS_USE")]
        PrinterUse          = 0x00000008,
        [SDKName("JOB_ACCESS_ADMINISTER")]
        JobAdminister       = 0x00000010,
        [SDKName("JOB_ACCESS_READ")]
        JobRead             = 0x00000020,
        [SDKName("PRINTER_ACCESS_MANAGE_LIMITED")]
        PrinterManageLimited = 0x00000040,
        [SDKName("GENERIC_READ")]
        GenericRead = GenericAccessRights.GenericRead,
        [SDKName("GENERIC_WRITE")]
        GenericWrite = GenericAccessRights.GenericWrite,
        [SDKName("GENERIC_EXECUTE")]
        GenericExecute = GenericAccessRights.GenericExecute,
        [SDKName("GENERIC_ALL")]
        GenericAll = GenericAccessRights.GenericAll,
        [SDKName("DELETE")]
        Delete = GenericAccessRights.Delete,
        [SDKName("READ_CONTROL")]
        ReadControl = GenericAccessRights.ReadControl,
        [SDKName("WRITE_DAC")]
        WriteDac = GenericAccessRights.WriteDac,
        [SDKName("WRITE_OWNER")]
        WriteOwner = GenericAccessRights.WriteOwner,
        [SDKName("MAXIMUM_ALLOWED")]
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        [SDKName("ACCESS_SYSTEM_SECURITY")]
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
