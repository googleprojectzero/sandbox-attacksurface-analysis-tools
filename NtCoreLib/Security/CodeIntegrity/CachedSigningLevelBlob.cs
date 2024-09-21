//  Copyright 2019 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Security.CodeIntegrity;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
public class CachedSigningLevelBlob
{
    public CachedSigningLevelBlobType BlobType { get; }
    public byte[] Data { get; }
    internal CachedSigningLevelBlob(CachedSigningLevelBlobType blob_type, byte[] data)
    {
        BlobType = blob_type;
        Data = data;
    }

    public override string ToString()
    {
        return $"Type {BlobType} - Length {Data.Length}";
    }

    internal static CachedSigningLevelBlob ReadBlob(BinaryReader reader)
    {
        int blob_size = reader.ReadByte();
        CachedSigningLevelBlobType type = (CachedSigningLevelBlobType)reader.ReadByte();
        byte[] data = reader.ReadAllBytes(blob_size - 2);
        return type switch
        {
            CachedSigningLevelBlobType.SignerHash or CachedSigningLevelBlobType.FileHash or CachedSigningLevelBlobType.DGPolicyHash or CachedSigningLevelBlobType.AntiCheatPolicyHash => new HashCachedSigningLevelBlob(type, data),
            _ => new CachedSigningLevelBlob(type, data),
        };
    }
}

#pragma warning restore 1591

