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

namespace NtApiDotNet.Win32.Security.Native
{
    internal enum SECPKG_ATTR
    {
        SIZES = 0,
        NAMES = 1,
        LIFESPAN = 2,
        DCE_INFO = 3,
        STREAM_SIZES = 4,
        KEY_INFO = 5,
        AUTHORITY = 6,
        PROTO_INFO = 7,
        PASSWORD_EXPIRY = 8,
        SESSION_KEY = 9,
        PACKAGE_INFO = 10,
        USER_FLAGS = 11,
        NEGOTIATION_INFO = 12,
        NATIVE_NAMES = 13,
        FLAGS = 14,
        USE_VALIDATED = 15,
        CREDENTIAL_NAME = 16,
        TARGET_INFORMATION = 17,
        ACCESS_TOKEN = 18,
        TARGET = 19,
        AUTHENTICATION_ID = 20,
        LOGOFF_TIME = 21,
        NEGO_KEYS = 22,
        PROMPTING_NEEDED = 24,
        UNIQUE_BINDINGS = 25,
        ENDPOINT_BINDINGS = 26,
        CLIENT_SPECIFIED_TARGET = 27,
        LAST_CLIENT_TOKEN_STATUS = 30,
        NEGO_PKG_INFO = 31,
        NEGO_STATUS = 32,
        CONTEXT_DELETED = 33,
        DTLS_MTU = 34,
        SUBJECT_SECURITY_ATTRIBUTES = 128,
        APPLICATION_PROTOCOL = 35,
        NEGOTIATED_TLS_EXTENSIONS = 36,
        IS_LOOPBACK = 37,
    }
}
