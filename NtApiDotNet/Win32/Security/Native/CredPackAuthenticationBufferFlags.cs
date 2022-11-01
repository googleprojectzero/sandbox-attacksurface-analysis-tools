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

namespace NtApiDotNet.Win32.Security.Native
{
    internal enum CredPackAuthenticationBufferFlags
    {
        CRED_PACK_PROTECTED_CREDENTIALS = 0x1,
        CRED_PACK_WOW_BUFFER = 0x2,
        CRED_PACK_GENERIC_CREDENTIALS = 0x4,
        CRED_PACK_ID_PROVIDER_CREDENTIALS = 0x8
    }
}
