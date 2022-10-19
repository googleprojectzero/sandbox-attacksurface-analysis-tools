//  Copyright 2022 Google LLC. All Rights Reserved.
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
using System.Security.Cryptography.X509Certificates;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Abstract class for a client authentication context delegate.
    /// </summary>
    public abstract class ClientAuthenticationContextDelegate : AuthenticationContextDelegate<IClientAuthenticationContext>, IClientAuthenticationContext
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        protected ClientAuthenticationContextDelegate(IClientAuthenticationContext context) : base(context)
        {
        }

        public virtual SecPkgLastClientTokenStatus LastTokenStatus => _context.LastTokenStatus;

        public InitializeContextReqFlags RequestAttributes => _context.RequestAttributes;

        public InitializeContextRetFlags ReturnAttributes => _context.ReturnAttributes;

        public X509Certificate2 LocalCertificate => _context.LocalCertificate;

        public X509Certificate2 RemoteCertificate => _context.RemoteCertificate;
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
