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

using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading;

namespace NtApiDotNet
{
    internal class CachedEnumerable<T> : IEnumerable<T>
    {
        private IEnumerable<T> _base_enum;
        private IEnumerable<T> _cached_values;

        public CachedEnumerable(IEnumerable<T> base_enum)
        {
            _base_enum = base_enum;
        }

        private class CachedEnumerator : IEnumerator<T>
        {
            IEnumerator<T> _base_enum;
            CachedEnumerable<T> _parent;
            List<T> _cached_values;

            public CachedEnumerator(IEnumerator<T> base_enum, CachedEnumerable<T> parent)
            {
                _base_enum = base_enum;
                _cached_values = new List<T>();
                _parent = parent;
            }

            public T Current
            {
                get
                {
                    return _base_enum.Current;
                }
            }

            object IEnumerator.Current => Current;

            public void Dispose()
            {
                _base_enum.Dispose();
            }

            public bool MoveNext()
            {
                if (_base_enum.MoveNext())
                {
                    _cached_values.Add(_base_enum.Current);
                    return true;
                }
                Interlocked.CompareExchange(ref _parent._cached_values, _cached_values.AsReadOnly(), null);
                return false;
            }

            public void Reset()
            {
                // We don't support resetting the enumerator.
                throw new NotImplementedException();
            }
        }

        public IEnumerator<T> GetEnumerator()
        {
            if (_cached_values != null)
            {
                return _cached_values.GetEnumerator();
            }
            return new CachedEnumerator(_base_enum.GetEnumerator(), this);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
