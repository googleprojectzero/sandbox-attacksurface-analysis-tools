//  Copyright 2016 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Utilities.Reflection;
#pragma warning disable 1591
/// <summary>
/// Supported windows verion
/// </summary>
public enum SupportedVersion
{
    Unknown,
    Windows7,
    Windows8,
    Windows81,
    Windows10,
    Windows10_TH2,
    Windows10_RS1,
    Windows10_RS2,
    Windows10_RS3,
    Windows10_RS4,
    Windows10_RS5,
    Windows10_19H1,
    Windows10_19H2,
    Windows10_20H1,
    Windows10_20H2,
    Windows10_21H1,
    Windows10_21H2,
    Windows10_22H2,
    Windows11,
    Windows11_22H2,
    /// <summary>
    /// This should always be at the end.
    /// </summary>
    Windows_Latest,
}
