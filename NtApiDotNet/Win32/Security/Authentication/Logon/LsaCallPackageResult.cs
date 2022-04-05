//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32.SafeHandles;
using System;

namespace NtApiDotNet.Win32.Security.Authentication.Logon
{
    /// <summary>
    /// Class to represent the result of a package call.
    /// </summary>
    public sealed class LsaCallPackageResult : IDisposable
    {
        /// <summary>
        /// The status result.
        /// </summary>
        public NtStatus Status { get; }

        /// <summary>
        /// The return buffer.
        /// </summary>
        public SafeBufferGeneric Buffer { get; }

        /// <summary>
        /// Dispose the response.
        /// </summary>
        public void Dispose()
        {
            ((IDisposable)Buffer)?.Dispose();
        }

        internal LsaCallPackageResult(LsaCallPackageResponse resp)
        {
            Status = resp.Status;
            Buffer = resp.Buffer;
        }
    }
}
