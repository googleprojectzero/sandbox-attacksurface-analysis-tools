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

namespace NtApiDotNet.Ndr.Marshal
{
    /// <summary>
    /// Class to represent an input NDR pipe.
    /// </summary>
    /// <typeparam name="T">The base type of pipe blocks.</typeparam>
    public sealed class NdrInPipe<T> : NdrPipe<T> where T : struct
    {
        internal IEnumerable<T[]> Blocks { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="blocks">The list of blocks to return.</param>
        public NdrInPipe(IEnumerable<T[]> blocks)
        {
            Blocks = blocks;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="block">A single block to return.</param>
        public NdrInPipe(T[] block)
        {
            Blocks = new[] { block };
        }
    }
}
