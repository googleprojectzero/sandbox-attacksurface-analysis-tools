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

        /// <summary>
        /// Add a resource to the list and return a reference to it.
        /// </summary>
        /// <typeparam name="R">The type of resource to add.</typeparam>
        /// <param name="resource">The resource object.</param>
        /// <returns>The added resource.</returns>
        public R AddResource<R>(R resource) where R : T
        {
            Add(resource);
            return resource;
        }

        /// <summary>
        /// Add a resource to the list and return a reference to it.
        /// </summary>
        /// <typeparam name="R">The type of resource to add.</typeparam>
        /// <returns>The added resource.</returns>
        public R AddResource<R>() where R : T, new()
        {
            return AddResource(new R());
        }

        /// <summary>
        /// Convert this list to an array then clear it to the disposal no longer happens.
        /// </summary>
        /// <returns>The elements as an array.</returns>
        /// <remarks>After doing this the current list will be cleared.</remarks>
        [ReliabilityContract(Consistency.MayCorruptProcess, Cer.MayFail)]
        public T[] ToArrayAndClear()
        {
            T[] ret = ToArray();
            Clear();
            return ret;
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
                    if (entry != null)
                    {
                        entry.Dispose();
                    }
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
            return new SafeHandleList(ToArrayAndClear());
        }
    }
}
