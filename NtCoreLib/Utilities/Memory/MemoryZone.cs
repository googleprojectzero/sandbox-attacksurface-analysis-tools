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


#nullable enable

using System.Collections.Generic;

namespace NtCoreLib.Utilities.Memory;

internal class MemoryZone
{
    public long StartAddress;
    public long EndAddress;

    public MemoryZone(long start_address, int size) 
        : this(start_address, start_address + size)
    {
    }

    public MemoryZone(long start_address, long end_address)
    {
        StartAddress = start_address;
        EndAddress = end_address;
    }

    internal virtual void Merge<T>(T zone) where T : MemoryZone
    {
        EndAddress = zone.EndAddress;
    }

    internal static List<T> MergeZones<T>(IEnumerable<T> zones) where T : MemoryZone
    {
        List<T> ret = new();
        T? curr = null;
        foreach (var zone in zones)
        {
            if (curr == null)
            {
                curr = zone;
            }
            else
            {
                if (zone.StartAddress == curr.EndAddress)
                {
                    curr.Merge(zone);
                }
                else
                {
                    ret.Add(curr);
                    curr = zone;
                }
            }
        }
        if (curr != null)
        {
            ret.Add(curr);
        }
        return ret;
    }

    internal static T? FindZone<T>(List<T> zones, long base_address) where T : MemoryZone
    {
        foreach (var zone in zones)
        {
            if (base_address >= zone.StartAddress && base_address < zone.EndAddress)
            {
                return zone;
            }
        }
        return null;
    }
}
