﻿//  Copyright 2020 Google Inc. All Rights Reserved.
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

using System;
using System.Runtime.InteropServices;
using NtCoreLib.Image.Security;
using NtCoreLib.Utilities.Memory;

namespace NtCoreLib.Image.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct IMAGE_POLICY_ENTRY : IConvertToNative<IMAGE_POLICY_ENTRY>
{
    public ImagePolicyEntryType Type;
    public ImagePolicyId PolicyId;
    public IMAGE_POLICY_ENTRY_UNION Value;

    readonly IMAGE_POLICY_ENTRY IConvertToNative<IMAGE_POLICY_ENTRY>.Read(IMemoryReader reader, IntPtr address, int index)
    {
        return reader.ReadStruct<IMAGE_POLICY_ENTRY32>(address, index).Convert();
    }
}
