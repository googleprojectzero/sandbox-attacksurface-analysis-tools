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

using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Ndr.Marshal
{
    /// <summary>
    /// Class to represent an output NDR pipe.
    /// </summary>
    /// <typeparam name="T">The base type of pipe blocks.</typeparam>
    public sealed class NdrOutPipe<T> : NdrPipe<T> where T : struct
    {
        private readonly List<T[]> _blocks;

        internal NdrOutPipe(IEnumerable<T[]> blocks)
        {
            _blocks = new List<T[]>(blocks);
        }

        /// <summary>
        /// The number of pipe blocks.
        /// </summary>
        public int Count => _blocks.Count;

        /// <summary>
        /// Index operator.
        /// </summary>
        /// <param name="index">The index.</param>
        /// <returns></returns>
        public T[] this[int index] => _blocks[index];

        /// <summary>
        /// Convert the pipe blocks to a flat array.
        /// </summary>
        /// <returns>The flat array.</returns>
        public T[] ToArray()
        {
            return _blocks.SelectMany(a => a).ToArray();
        }
    }
}
