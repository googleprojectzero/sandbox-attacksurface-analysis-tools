//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Represents a list where the elements can be trivially disposed in one go.
    /// </summary>
    /// <typeparam name="T">An IDisposable implementing type</typeparam>
    public class DisposableList<T> : List<T>, IDisposable where T : IDisposable
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public DisposableList()
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">The initial capacity of the list</param>
        public DisposableList(int capacity) : base(capacity)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="collection">A collection to initialize the list</param>
        public DisposableList(IEnumerable<T> collection) : base(collection)
        {
        }

        #region IDisposable Support
        private bool disposedValue = false;

        /// <summary>
        /// Dispose method
        /// </summary>
        public void Dispose()
        {
            if (!disposedValue)
            {
                foreach (IDisposable entry in this)
                {
                    entry.Dispose();
                }

                disposedValue = true;
            }
        }
        #endregion

    }

    /// <summary>
    /// Disposable list of safe handles
    /// </summary>
    public sealed class SafeHandleList : DisposableList<SafeHandle>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public SafeHandleList()
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">The initial capacity of the list</param>
        public SafeHandleList(int capacity) : base(capacity)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="collection">A collection to initialize the list</param>
        public SafeHandleList(IEnumerable<SafeHandle> collection) : base(collection)
        {
        }

        /// <summary>
        /// Move the handle list to a new disposable list.
        /// </summary>
        /// <returns>The list of handles which have been moved.</returns>
        /// <remarks>After doing this the current list will be cleared.</remarks>
        [ReliabilityContract(Consistency.MayCorruptProcess, Cer.MayFail)]
        public SafeHandleList DangerousMove()
        {
            SafeHandle[] handles = this.ToArray();
            this.Clear();
            return new SafeHandleList(handles);
        }
    }
}
