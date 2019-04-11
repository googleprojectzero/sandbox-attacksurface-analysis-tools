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

using NtApiDotNet.Ndr;

namespace NtApiDotNet.Win32.Rpc
{
    /// <summary>
    /// Some addition internal utilities for RPC code.
    /// </summary>
    public static class RpcUtils
    {
        /// <summary>
        /// Helper to dereference a type.
        /// </summary>
        /// <typeparam name="T">The type to dereference.</typeparam>
        /// <param name="t">The value to dereference.</param>
        /// <returns>The dereferenced result.</returns>
        public static T DeRef<T>(T t)
        {
            return t;
        }

        /// <summary>
        /// Helper to dereference a type.
        /// </summary>
        /// <typeparam name="T">The type to dereference.</typeparam>
        /// <param name="t">The value to dereference.</param>
        /// <returns>The dereferenced result.</returns>
        public static T DeRef<T>(T? t) where T : struct
        {
            return t.Value;
        }

        /// <summary>
        /// Helper to dereference a type.
        /// </summary>
        /// <typeparam name="T">The type to dereference.</typeparam>
        /// <param name="t">The value to dereference.</param>
        /// <returns>The dereferenced result.</returns>
        public static T DeRef<T>(NdrEmbeddedPointer<T> t) 
        {
            return t.GetValue();
        }
    }
}
