//  Copyright 2024 Google LLC. All Rights Reserved.
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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Utilities.Collections;

namespace NtCoreLib.Kernel.Memory;

/// <summary>
/// Class to represent an address requirements extended memory parameter.
/// </summary>
public sealed class MemoryAddressRequirements : MemoryExtendedParameter
{
    /// <summary>
    /// Set the lowerst starting address.
    /// </summary>
    public long LowestStartingAddress { get; set; }

    /// <summary>
    /// Set the highest ending address.
    /// </summary>
    public long HighestEndingAddress { get; set; }

    /// <summary>
    /// Set the alignment.
    /// </summary>
    public long Alignment { get; set; }

    internal override MEM_EXTENDED_PARAMETER ToStruct(DisposableList list)
    {
        MEM_ADDRESS_REQUIREMENTS req = new()
        {
            LowestStartingAddress = new(LowestStartingAddress),
            HighestEndingAddress = new(HighestEndingAddress),
            Alignment = new(Alignment)
        };
        var buffer = list.AddResource(req.ToBuffer());
        return new()
        {
            Type = (long)MemExtendedParameterType.MemExtendedParameterAddressRequirements,
            Value = buffer.DangerousGetHandle().ToInt64()
        };
    }
}
