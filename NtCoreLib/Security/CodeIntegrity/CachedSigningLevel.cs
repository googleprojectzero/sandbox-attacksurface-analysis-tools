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

namespace NtCoreLib.Security.CodeIntegrity;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
public class CachedSigningLevel
{
    public CachedSigningLevelFlags Flags { get; }
    public SigningLevel SigningLevel { get; }
    public string Thumbprint { get; }
    public byte[] ThumbprintBytes { get; }
    public HashAlgorithm ThumbprintAlgorithm { get; }

    internal CachedSigningLevel(int flags, SigningLevel signing_level, byte[] thumbprint, HashAlgorithm thumbprint_algo)
    {
        Flags = (CachedSigningLevelFlags)flags;
        SigningLevel = signing_level;
        ThumbprintBytes = thumbprint;
        ThumbprintAlgorithm = thumbprint_algo;
        Thumbprint = thumbprint.ToHexString();
    }
}

#pragma warning restore 1591

