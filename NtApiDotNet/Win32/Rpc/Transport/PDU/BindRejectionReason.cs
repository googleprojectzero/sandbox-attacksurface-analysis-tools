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
        ResonaNotSpecified = 0,
        TemporaryCongestion = 1,
        LocalLimitExceeded = 2,
        CalledPAddrUnknown = 3,
        ProtocolVersionNotSupported = 4,
        DefaultContextNotSupported = 5,
        UserDataNotReadable = 6,
        NoPSAPAvailable = 7,
        AuthenticationTypeNotRecognized = 8,
        InvalidChecksum = 9,
    }
}
