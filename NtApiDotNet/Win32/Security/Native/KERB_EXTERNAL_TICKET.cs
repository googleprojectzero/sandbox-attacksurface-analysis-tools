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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Native
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct KERB_EXTERNAL_TICKET
    {
        public IntPtr ServiceName; // PKERB_EXTERNAL_NAME
        public IntPtr TargetName;  // PKERB_EXTERNAL_NAME
        public IntPtr ClientName;  // PKERB_EXTERNAL_NAME
        public UnicodeStringOut DomainName;
        public UnicodeStringOut TargetDomainName;
        public UnicodeStringOut AltTargetDomainName;
        public KERB_CRYPTO_KEY SessionKey;
        public uint TicketFlags;
        public int Flags;
        public LargeIntegerStruct KeyExpirationTime;
        public LargeIntegerStruct StartTime;
        public LargeIntegerStruct EndTime;
        public LargeIntegerStruct RenewUntil;
        public LargeIntegerStruct TimeSkew;
        public int EncodedTicketSize;
        public IntPtr EncodedTicket;

        internal byte[] ReadTicket()
        {
            byte[] ret = new byte[EncodedTicketSize];
            Marshal.Copy(EncodedTicket, ret, 0, ret.Length);
            return ret;
        }
    }
}
