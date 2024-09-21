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

namespace NtApiDotNet.Utilities.ASN1.Parser
{
    /// <summary>
    /// The universal object tag.
    /// </summary>
    public enum ASN1UniversalTag
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        EOC = 0,
        Boolean = 1,
        Integer = 2,
        BitString = 3,
        OctetString = 4,
        Null = 5,
        ObjectIdentifier = 6,
        Enumerated = 10,
        UTF8String = 12,
        RelativeObjectIdentifier = 13,
        Sequence = 16,
        Set = 17,
        PrintableString = 19,
        T16String = 20,
        IA5String = 22,
        UTCTime = 23,
        GeneralizedTime = 24,
        GeneralString = 27,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
