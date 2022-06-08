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

namespace NtApiDotNet.Utilities.ASN1
{
    internal enum UniversalTag
    {
        EOC = 0,
        BOOLEAN = 1,
        INTEGER = 2,
        BIT_STRING = 3,
        OCTET_STRING = 4,
        NULL = 5,
        OBJECT_IDENTIFIER = 6,
        ENUMERATED = 10,
        UTF8String = 12,
        RELATIVE_OBJECT_IDENTIFIER = 13,
        SEQUENCE = 16,
        SET = 17,
        PrintableString = 19,
        T16String = 20,
        IA5String = 22,
        UTCTime = 23,
        GeneralizedTime = 24,
        GeneralString = 27,
    }
}
