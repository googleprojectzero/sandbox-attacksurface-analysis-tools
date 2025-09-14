//  Copyright 2021 Google LLC. All Rights Reserved.
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
using System.Collections.Generic;
using System.Reflection;

namespace NtCoreLib.Net.Firewall;

internal class NamedGuidDictionary : Dictionary<Guid, string>
{
    public void DefineGuid(string name, uint a, ushort b, ushort c, byte d,
        byte e, byte f, byte g, byte h, byte i, byte j, byte k)
    {
        Add(new Guid(a, b, c, d, e, f, g, h, i, j, k), name);
    }

    public string GetName(Guid guid)
    {
        if (TryGetValue(guid, out string value))
        {
            return value;
        }
        return guid.ToString("B");
    }

    public static Lazy<NamedGuidDictionary> LayerGuids = new(GetLayerGuids);
    public static Lazy<NamedGuidDictionary> SubLayerGuids = new(GetSublayerGuids);
    public static Lazy<NamedGuidDictionary> ConditionGuids = new(GetConditionGuids);
    public static Lazy<NamedGuidDictionary> CalloutGuids = new(GetCalloutGuids);

    public NtResult<Guid> GuidFromName(string name, bool throw_on_error)
    {
        foreach (var pair in this)
        {
            if (pair.Value.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return pair.Key.CreateResult();
            }
        }
        return NtStatus.STATUS_NO_KEY.CreateResultFromError<Guid>(throw_on_error);
    }

    public Guid GuidFromName(string name)
    {
        return GuidFromName(name, true).Result;
    }

    private static NamedGuidDictionary GetCalloutGuids() => GetPublicGuidsFromType(typeof(FirewallCalloutGuids), "FWPM_CALLOUT_");

    private static NamedGuidDictionary GetLayerGuids() => GetPublicGuidsFromType(typeof(FirewallLayerGuids), "FWPM_LAYER_");

    private static NamedGuidDictionary GetSublayerGuids()
    {
        NamedGuidDictionary ret = GetPublicGuidsFromType(typeof(FirewallSubLayerGuids), "FWPM_SUBLAYER_");

        ret.DefineGuid(
            "MICROSOFT_DEFENDER_SUBLAYER_WSH",
            0xb3cdd441,
            0xaf90,
            0x41ba,
            0xa7, 0x45, 0x7c, 0x60, 0x08, 0xff, 0x23, 0x00);

        ret.DefineGuid(
            "MICROSOFT_DEFENDER_SUBLAYER_FIREWALL",
            0xb3cdd441,
            0xaf90,
            0x41ba,
            0xa7, 0x45, 0x7c, 0x60, 0x08, 0xff, 0x23, 0x01);

        ret.DefineGuid(
           "MICROSOFT_DEFENDER_SUBLAYER_QUARANTINE",
           0xb3cdd441,
           0xaf90,
           0x41ba,
           0xa7, 0x45, 0x7c, 0x60, 0x08, 0xff, 0x23, 0x02);

        return ret;
    }

    private static NamedGuidDictionary GetConditionGuids() => GetPublicGuidsFromType(typeof(FirewallConditionGuids), "FWPM_CONDITION_");

    private static NamedGuidDictionary GetPublicGuidsFromType(Type type, string field_prefix)
    {
        NamedGuidDictionary ret = new();

        FieldInfo[] fields = type.GetFields(BindingFlags.Public | BindingFlags.Static);
        foreach (FieldInfo field in fields)
        {
            if (field.FieldType == typeof(Guid) && field.Name.StartsWith(field_prefix))
            {
                ret.Add((Guid)field.GetValue(null), field.Name);
            }
        }

        return ret;
    }
}
