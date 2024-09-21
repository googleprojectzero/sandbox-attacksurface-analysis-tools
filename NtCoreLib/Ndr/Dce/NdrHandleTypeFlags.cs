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

// NOTE: This file is a modified version of NdrParser.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this

using NtCoreLib.Utilities.Reflection;
using System;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
/// <summary>
/// Flags for the handle parameter.
/// </summary>
[Flags, Serializable]
public enum NdrHandleTypeFlags : byte
{
    [SDKName("HANDLE_PARAM_IS_VIA_PTR")]
    IsViaPtr = 0x80,
    [SDKName("HANDLE_PARAM_IS_IN")]
    IsIn = 0x40,
    [SDKName("HANDLE_PARAM_IS_OUT")]
    IsOut = 0x20,
    [SDKName("HANDLE_PARAM_IS_RETURN")]
    IsReturn = 0x10,
    /* flags for context handles */
    [SDKName("NDR_STRICT_CONTEXT_HANDLE")]
    Strict = 0x08,
    [SDKName("NDR_CONTEXT_HANDLE_NOSERIALIZE")]
    NoSerialize = 0x04,
    [SDKName("NDR_CONTEXT_HANDLE_SERIALIZE")]
    Serialize = 0x02,
    [SDKName("NDR_CONTEXT_HANDLE_CANNOT_BE_NULL")]
    CannotBeNull = 0x01,
}
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
