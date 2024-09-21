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

namespace NtApiDotNet.Utilities.Misc
{
    /// <summary>
    /// Miscellaneous utilities.
    /// </summary>
    public static class MiscUtils
    {
        /// <summary>
        /// Convert a disposable object to a detachable object.
        /// </summary>
        /// <typeparam name="T">The disposable object type.</typeparam>
        /// <param name="obj">The disposable object.</param>
        /// <returns>The disposable container.</returns>
        public static DetachableContainer<T> AsDetachable<T>(this T obj) where T : class, IDisposable
        {
            return new DetachableContainer<T>(obj);
        }
    }
}
