//  Copyright 2022 Google LLC. All Rights Reserved.
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
    /// <summary>
    /// Flags for the KDC-REQ.
    /// </summary>
    [Flags]
    public enum KerberosKDCOptions : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        Forwardable = (1 << 1),
        Forwarded = (1 << 2),
        Proxiable = (1 << 3),
        Proxy = (1 << 4),
        AllowPostdate = (1 << 5),
        Postdated = (1 << 6),
        Renewable = (1 << 8),
        OptHardwareAuth = (1 << 11),
        ClientNameInAdditionalTicket = (1 << 14),
        Canonicalize = (1 << 15),
        RequestAnonymous = (1 << 16),
        DisableTransitedCheck = (1 << 26),
        RenewableOk = (1 << 27),
        EncTicketInSessionKey = (1 << 28),
        Renew = (1 << 30),
        Validate = (1U << 31)
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
