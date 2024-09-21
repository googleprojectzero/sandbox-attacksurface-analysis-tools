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

namespace NtApiDotNet
{
    /// <summary>
    /// LDR static methods.
    /// </summary>
    public static class NtLdr
    {
        /// <summary>
        /// Get address of a procedure in a mapped image.
        /// </summary>
        /// <param name="dll_handle">The handle to the mapped image.</param>
        /// <param name="name">The name of the procedure to find.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The procedure address.</returns>
        public static NtResult<IntPtr> GetProcedureAddress(IntPtr dll_handle, string name, bool throw_on_error)
        {
            return NtLdrNative.LdrGetProcedureAddress(dll_handle, 
                new AnsiString(name), 0, out IntPtr addr).CreateResult(throw_on_error, () => addr);
        }

        /// <summary>
        /// Get address of a procedure in a mapped image.
        /// </summary>
        /// <param name="dll_handle">The handle to the mapped image.</param>
        /// <param name="name">The name of the procedure to find.</param>
        /// <returns>The procedure address.</returns>
        public static IntPtr GetProcedureAddress(IntPtr dll_handle, string name)
        {
            return GetProcedureAddress(dll_handle, name, true).Result;
        }
    }
}
