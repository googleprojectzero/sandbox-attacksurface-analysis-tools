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

namespace NtApiDotNet.Win32.Rpc.Transport.PDU
{
    internal enum PDUType : byte
    {
        Request = 0,
        Ping = 1,
        Response = 2,
        Fault = 3,
        Working = 4,
        NoCall = 5,
        Reject = 6,
        Ack = 7,
        ClCancel = 8,
        FAck = 9,
        CancelAck = 10,
        Bind = 11,
        BindAck = 12,
        BindNack = 13,
        AlterContext = 14,
        AlterContextResp = 15,
        Auth3 = 16,
        Shutdown = 17,
        CoCancel = 18,
        Orphaned = 19,
    }
}
