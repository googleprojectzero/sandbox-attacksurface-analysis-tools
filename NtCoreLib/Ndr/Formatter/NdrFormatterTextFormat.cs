//  Copyright 2018 Google Inc. All Rights Reserved.
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


#nullable enable

namespace NtCoreLib.Ndr.Formatter;

/// <summary>
/// Enumeration for the text output format.
/// </summary>
public enum NdrFormatterTextFormat
{
    /// <summary>
    /// IDL style.
    /// </summary>
    Idl,
    /// <summary>
    /// C# style.
    /// </summary>
    CSharp,
    /// <summary>
    /// C++ style.
    /// </summary>
    Cpp,
}
