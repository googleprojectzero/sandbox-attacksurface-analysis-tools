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

namespace NtApiDotNet.Net.Smb2
{
    internal enum Smb2Command : ushort
    {
        NEGOTIATE = 0x0000,
        SESSION_SETUP = 0x0001,
        LOGOFF = 0x0002,
        TREE_CONNECT = 0x0003,
        TREE_DISCONNECT = 0x0004,
        CREATE = 0x0005,
        CLOSE = 0x0006,
        FLUSH = 0x0007,
        READ = 0x0008,
        WRITE = 0x0009,
        LOCK = 0x000A,
        IOCTL = 0x000B,
        CANCEL = 0x000C,
        ECHO = 0x000D,
        QUERY_DIRECTORY = 0x000E,
        CHANGE_NOTIFY = 0x000F,
        QUERY_INFO = 0x0010,
        SET_INFO = 0x0011,
        OPLOCK_BREAK = 0x0012
    }
}
