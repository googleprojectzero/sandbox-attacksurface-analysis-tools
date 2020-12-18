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
    internal enum BindRejectionReason
    {
        REASON_NOT_SPECIFIED = 0,
        TEMPORARY_CONGESTION = 1,
        LOCAL_LIMIT_EXCEEDED = 2,
        CALLED_PADDR_UNKNOWN = 3,
        PROTOCOL_VERSION_NOT_SUPPORTED = 4,
        DEFAULT_CONTEXT_NOT_SUPPORTED = 5,
        USER_DATA_NOT_READABLE = 6,
        NO_PSAP_AVAILABLE = 7,
    }
}
