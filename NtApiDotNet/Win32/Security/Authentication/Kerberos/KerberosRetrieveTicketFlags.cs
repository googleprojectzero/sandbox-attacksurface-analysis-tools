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

using NtApiDotNet.Utilities.Reflection;
using System;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Flags for retrieving a ticket.
    /// </summary>
    [Flags]
    public enum KerberosRetrieveTicketFlags
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("KERB_RETRIEVE_TICKET_DEFAULT")]
        Default = 0,
        [SDKName("KERB_RETRIEVE_TICKET_DONT_USE_CACHE")]
        DontUseCache = 1,
        [SDKName("KERB_RETRIEVE_TICKET_USE_CACHE_ONLY")]
        UseCacheOnly = 2,
        [SDKName("KERB_RETRIEVE_TICKET_USE_CREDHANDLE")]
        UseCredHandle = 4,
        [SDKName("KERB_RETRIEVE_TICKET_AS_KERB_CRED")]
        AsKerbCred = 8,
        [SDKName("KERB_RETRIEVE_TICKET_WITH_SEC_CRED")]
        WithSecCred = 0x10,
        [SDKName("KERB_RETRIEVE_TICKET_CACHE_TICKET")]
        CacheTicket = 0x20,
        [SDKName("KERB_RETRIEVE_TICKET_MAX_LIFETIME")]
        MaxLifetime = 0x40
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
