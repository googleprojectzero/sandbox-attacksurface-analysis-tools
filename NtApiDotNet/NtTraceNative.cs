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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    /// <summary>
    /// Access rights for Trace
    /// </summary>
    [Flags]
    public enum TraceAccessRights : uint
    {
        None = 0,
        Query = 0x0001,
        Set = 0x0002,
        Notification = 0x0004,
        ReadDescription = 0x0008,
        Execute = 0x0010,
        CreateRealtime = 0x0020,
        CreateOnDisk = 0x0040,
        GuidEnable = 0x0080,
        AccessKernelLogger = 0x0100,
        CreateInproc = 0x0200,
        RegisterGuids = 0x0800,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtTraceEvent(
            SafeKernelObjectHandle TraceHandle,
            int Flags,
            int FieldSize,
            SafeBuffer Fields
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtTraceControl(
            int FunctionCode,
            SafeBuffer InBuffer,
            int InBufferLen,
            SafeBuffer OutBuffer,
            int OutBufferLen,
            out int ReturnLength
        );
    }
#pragma warning restore 1591
}
