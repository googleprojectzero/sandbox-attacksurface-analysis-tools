//  Copyright 2025 Google LLC. All Rights Reserved.
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

using NtCoreLib.Utilities.Collections;
using System;

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// A builder to create a new firewall sub-layer.
/// </summary>
public sealed class FirewallSubLayerBuilder
{
    #region Public Properties
    /// <summary>
    /// The name of the sub-layer.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// The description of the sub-layer.
    /// </summary>
    public string Description { get; set; }

    /// <summary>
    /// The provider key. If empty will be automatically assigned.
    /// </summary>
    public Guid ProviderKey { get; set; }

    /// <summary>
    /// The sub-layer key. If empty will be automatically assigned.
    /// </summary>
    public Guid SubLayerKey { get; set; }

    /// <summary>
    /// Flags for the provider.
    /// </summary>
    public FirewallSubLayerFlags Flags { get; set;  }

    /// <summary>
    /// Provider data.
    /// </summary>
    public byte[] ProviderData { get; set; }

    /// <summary>
    /// Weight of the sub-layer.
    /// </summary>
    public ushort Weight { get; set; }
    #endregion

    #region Constructors
    /// <summary>
    /// Constructor.
    /// </summary>
    public FirewallSubLayerBuilder()
    {
        SubLayerKey = Guid.Empty;
        ProviderKey = Guid.Empty;

        Name = string.Empty;
        Description = string.Empty;
        Flags = FirewallSubLayerFlags.None;
    }
    #endregion

    #region Internal Members
    internal FWPM_SUBLAYER0 ToStruct(DisposableList list)
    {
        FWPM_SUBLAYER0 ret = new();
        ret.subLayerKey = SubLayerKey;
        ret.displayData.name = Name;
        ret.displayData.description = Description;
        ret.weight = Weight;
        ret.flags = Flags;

        if (ProviderKey != Guid.Empty)
        {
            ret.providerKey = list.AddStructureRef(ProviderKey).DangerousGetHandle();
        }

        if (ProviderData?.Length > 0)
        {
            FWP_BYTE_BLOB blob = new()
            {
                size = ProviderData.Length,
                data = list.AddBytes(ProviderData).DangerousGetHandle()
            };
            ret.providerData = blob;
        }

        return ret;
    }
    #endregion
}
