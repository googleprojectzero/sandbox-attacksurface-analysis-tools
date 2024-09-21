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

using System;

namespace NtApiDotNet.Utilities.Memory
{
    /// <summary>
    /// IMemoryReader implementation for a process.
    /// </summary>
    internal sealed class CrossBitnessProcessMemoryReader : ProcessMemoryReader
    {
        internal CrossBitnessProcessMemoryReader(NtProcess process) : base(process)
        {
        }

        public override IntPtr ReadIntPtr(IntPtr address)
        {
            return _process.ReadMemory<IntPtr32>(address.ToInt64()).Convert();
        }

        private static CrossBitnessTypeAttribute GetCrossBitnessAttribute<T>() where T : struct
        {
            object[] attrs = typeof(T).GetCustomAttributes(typeof(CrossBitnessTypeAttribute), false);
            if (attrs.Length > 0)
            {
                return (CrossBitnessTypeAttribute)attrs[0];
            }
            return null;
        }

        public override T ReadStruct<T>(IntPtr address)
        {
            var attr = GetCrossBitnessAttribute<T>();
            if (attr == null)
            {
                return base.ReadStruct<T>(address);
            }

            return attr.ReadType<T>(_process, address.ToInt64());
        }

        public override T[] ReadArray<T>(IntPtr address, int count)
        {
            var attr = GetCrossBitnessAttribute<T>();
            if (attr == null)
            {
                return base.ReadArray<T>(address, count);
            }

            T[] ret = new T[count];
            int size = attr.GetSize();
            for (int i = 0; i < count; ++i)
            {
                ret[i] = attr.ReadType<T>(_process, address.ToInt64() + i * size);
            }
            return ret;
        }
    }
}
