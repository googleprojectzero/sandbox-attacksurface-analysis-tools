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

using NtApiDotNet.Win32.Security.Native;
using System;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Impersonation context for a server authentication.
    /// </summary>
    public struct AuthenticationImpersonationContext : IDisposable
    {
        private readonly SecHandle _context;

        internal AuthenticationImpersonationContext(SecHandle context)
        {
            _context = context;
        }

        void IDisposable.Dispose()
        {
            SecurityNativeMethods.RevertSecurityContext(_context);
        }
    }
}
