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

using System;
using System.Threading;

namespace NtApiDotNet.Utilities.Misc
{
    /// <summary>
    /// A container which can detach an innner reference.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public sealed class DetachableContainer<T> : IDisposable where T : class, IDisposable
    {
        private T _obj;

        internal DetachableContainer(T obj)
        {
            _obj = obj;
        }

        /// <summary>
        /// Get the contained value.
        /// </summary>
        public T Value => _obj;

        /// <summary>
        /// Detach the object so the original isn't disposed.
        /// </summary>
        /// <returns>Detached object.</returns>
        public T Detach()
        {
            return Interlocked.Exchange(ref _obj, null);
        }

        void IDisposable.Dispose()
        {
            _obj?.Dispose();
        }
    }
}
