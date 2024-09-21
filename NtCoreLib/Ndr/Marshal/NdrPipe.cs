//  Copyright 2019 Google Inc. All Rights Reserved.
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
    /// Type for a synchronous NDR pipe.
    /// </summary>
    /// <typeparam name="T">The base type of pipe blocks.</typeparam>
    public sealed class NdrPipe<T> where T : struct
    {
        /// <summary>
        /// The list of blocks for the pipe.
        /// </summary>
        public IEnumerable<T[]> Blocks { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="blocks">The list of blocks to return.</param>
        public NdrPipe(IEnumerable<T[]> blocks)
        {
            Blocks = blocks;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="block">A single block to return.</param>
        public NdrPipe(T[] block)
        {
            Blocks = new[] { block };
        }

        /// <summary>
        /// Convert the pipe blocks to a flat array.
        /// </summary>
        /// <returns>The flat array.</returns>
        public T[] ToArray()
        {
            return Blocks.SelectMany(a => a).ToArray();
        }
    }
}
