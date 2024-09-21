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

using System.IO;

namespace NtApiDotNet.Net.Smb2
{
    internal struct Smb2FileId
    {
        public ulong Persistent;
        public ulong Volatile;

        public void Write(BinaryWriter writer)
        {
            writer.Write(Persistent);
            writer.Write(Volatile);
        }

        public static Smb2FileId Read(BinaryReader reader)
        {
            return new Smb2FileId()
            {
                Persistent = reader.ReadUInt64(),
                Volatile = reader.ReadUInt64()
            };
        }
    }
}
