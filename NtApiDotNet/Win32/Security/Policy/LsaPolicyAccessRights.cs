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

namespace NtApiDotNet.Win32.Security.Policy
{
    [Flags]
    internal enum LsaPolicyAccessRights : uint
    {
        ViewLocalInformation = 0x00000001,
        ViewAuditInformation = 0x00000002,
        GetPrivateInformation = 0x00000004,
        TrustAdmin = 0x00000008,
        CreateAccount = 0x00000010,
        CreateSecret = 0x00000020,
        CreatePrivilege = 0x00000040,
        SetDefaultQuotaLimits = 0x00000080,
        SetAuditRequirements = 0x00000100,
        AuditLogAdmin = 0x00000200,
        ServerAdmin = 0x00000400,
        LookupNames = 0x00000800,
        Notification = 0x00001000,
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
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity,
    }
}
