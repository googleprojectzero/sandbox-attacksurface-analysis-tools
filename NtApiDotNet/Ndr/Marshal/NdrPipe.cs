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

using System;

namespace NtApiDotNet.Ndr.Marshal
{
    /// <summary>
    /// Abstract type for a NDR pipe.
    /// </summary>
    /// <typeparam name="T">The base type of pipe blocks.</typeparam>
    public abstract class NdrPipe<T> where T : struct
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="can_pull">True to indicate supports pulling.</param>
        /// <param name="can_push">True to indicate supports pushing.</param>
        protected NdrPipe(bool can_pull, bool can_push)
        {
            CanPull = can_pull;
            CanPush = can_push;
        }

        /// <summary>
        /// Can the pipe pull elements.
        /// </summary>
        public bool CanPull { get; }

        /// <summary>
        /// Pull a block from a pipe.
        /// </summary>
        /// <param name="count">The maximum number of elements to pull.</param>
        /// <returns>The pulled block.</returns>
        public virtual T[] Pull(int count)
        {
            throw new NotImplementedException("Pipe support not implemented");
        }

        /// <summary>
        /// Can the pipe push elements.
        /// </summary>
        public bool CanPush { get; }

        /// <summary>
        /// Push a block to a pipe.
        /// </summary>
        /// <param name="data">The block to push.</param>
        public virtual void Push(T[] data)
        {
            throw new NotImplementedException("Pipe support not implemented");
        }
    }
}
