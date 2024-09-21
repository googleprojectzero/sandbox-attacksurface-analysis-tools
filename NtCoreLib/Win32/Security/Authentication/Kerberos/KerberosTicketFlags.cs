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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
#pragma warning disable 1591
    /// <summary>
    /// Flags for a Kerberos Ticket.
    /// </summary>
    [Flags]
    public enum KerberosTicketFlags : uint
    {
        None = 0,
        Reserved = 0x1,
        Forwardable = 0x2,
        Forwarded = 0x4,
        Proxiable = 0x8,
        Proxy = 0x10,
        MayPostDate = 0x20,
        PostDated = 0x40,
        Invalid = 0x80,
        Renewable = 0x100,
        Initial = 0x200,
        PreAuthent = 0x400,
        HwAuthent = 0x800,
        TransitedPolicyChecked = 0x1000,
        OkAsDelegate = 0x2000,
        Reserved2 = 0x4000,
        EncPARep = 0x8000,
        Anonymous = 0x10000,
    }
}
