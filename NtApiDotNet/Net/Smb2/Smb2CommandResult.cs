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
    internal class Smb2CommandResult<T> where T : Smb2ResponsePacket, new()
    {
        public byte[] Data { get; }
        public Smb2PacketHeader Header { get; }
        public T Response { get; }

        public Smb2CommandResult(byte[] data, Smb2PacketHeader header, T response)
        {
            Data = data;
            Header = header;
            Response = response;
        }
    }
}
