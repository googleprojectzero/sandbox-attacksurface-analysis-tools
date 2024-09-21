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

using NtCoreLib.Utilities.Reflection;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Security.Interop;

[Flags]
enum KerberosPurgeTicketCacheExFlags
{
    None = 0,
    [SDKName("KERB_PURGE_ALL_TICKETS")]
    PurgeAllTickets = 1,
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct KERB_PURGE_TKT_CACHE_EX_REQUEST
{
    public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    public Luid LogonId;
    public KerberosPurgeTicketCacheExFlags Flags;
    public KERB_TICKET_CACHE_INFO_EX TicketTemplate;
}
