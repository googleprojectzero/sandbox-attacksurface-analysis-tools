//  Copyright 2023 Google LLC. All Rights Reserved.
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

namespace NtCoreLib.Ndr.Ndr64;

/// <summary>
/// Base complex type.
/// </summary>
public abstract class Ndr64ComplexTypeReference : Ndr64BaseTypeReference
{
    /// <summary>
    /// The name of the type.
    /// </summary>
    public string Name { get; set; }
    /// <summary>
    /// The number of memebers.
    /// </summary>
    public abstract int MemberCount { get; }

    internal Ndr64ComplexTypeReference(string name, Ndr64FormatCharacter format) : base(format)
    {
        Name = name;
    }
}