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
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Debugger
{
    internal class TypeInformationCache
    {
        private readonly Dictionary<Tuple<long, int>, TypeInformation> _cache;
        private readonly Dictionary<Tuple<long, int>, PointerTypeInformation> _pointer_fixup;

        public bool HasEntry(long module_base, int index)
        {
            return _cache.ContainsKey(Tuple.Create(module_base, index));
        }

        public TypeInformation GetEntry(long module_base, int index)
        {
            return _cache[Tuple.Create(module_base, index)];
        }

        public void AddEntry(long module_base, int index, TypeInformation entry)
        {
            if (!HasEntry(module_base, index))
                _cache.Add(Tuple.Create(module_base, index), entry);
        }

        public void AddFixedup(long module_base, int index, PointerTypeInformation pointer)
        {
            if (!_pointer_fixup.ContainsKey(Tuple.Create(module_base, index)))
            {
                _pointer_fixup.Add(Tuple.Create(module_base, index), pointer);
            }
        }

        public void FixupPointerTypes()
        {
            foreach (var pair in _pointer_fixup)
            {
                if (pair.Value.PointerType == null)
                {
                    Console.WriteLine("Ooops");
                }
                if (_cache.ContainsKey(pair.Key))
                {
                    pair.Value.PointerType = _cache[pair.Key];
                }
            }
        }

        internal TypeInformationCache()
        {
            _cache = new Dictionary<Tuple<long, int>, TypeInformation>();
            _pointer_fixup = new Dictionary<Tuple<long, int>, PointerTypeInformation>();
        }
    }
}
