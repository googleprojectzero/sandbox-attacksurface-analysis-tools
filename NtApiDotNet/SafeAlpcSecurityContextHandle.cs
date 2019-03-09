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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Safe handle for an ALPC security context.
    /// </summary>
    public class SafeAlpcSecurityContextHandle : SafeHandle
    {
        private readonly NtAlpc _port;

        /// <summary>
        /// Attribute flags.
        /// </summary>
        public AlpcSecurityAttrFlags Flags { get; }

        /// <summary>
        /// Security quality of service.
        /// </summary>
        public SecurityQualityOfService SecurityQualityOfService { get; }

        internal SafeAlpcSecurityContextHandle(AlpcHandle handle, bool owns_handle, NtAlpc port, 
            AlpcSecurityAttrFlags flags, SecurityQualityOfService security_quality_of_service) 
            : base(IntPtr.Zero, owns_handle)
        {
            SetHandle(new IntPtr(handle.Value));
            _port = port;
            Flags = flags;
            SecurityQualityOfService = security_quality_of_service;
        }

        internal SafeAlpcSecurityContextHandle() : base(IntPtr.Zero, false)
        {
        }

        /// <summary>
        /// Get the security context as a message attribute.
        /// </summary>
        /// <returns>The message attribute.</returns>
        public AlpcSecurityMessageAttribute ToMessageAttribute()
        {
            return new AlpcSecurityMessageAttribute()
            {
                Flags = Flags,
                ContextHandle = handle.ToInt64(),
                SecurityQoS = SecurityQualityOfService
            };
        }

        /// <summary>
        /// Get whether handle is invalid.
        /// </summary>
        public override bool IsInvalid => handle.ToInt64() <= 0;

        /// <summary>
        /// Release handle.
        /// </summary>
        /// <returns>True if handle released successfully.</returns>
        protected override bool ReleaseHandle()
        {
            if (_port == null || _port.Handle.IsClosed)
            {
                return false;
            }
            return NtSystemCalls.NtAlpcDeleteSecurityContext(_port.Handle,
                AlpcDeleteSecurityContextFlags.None, handle.ToInt64()).IsSuccess();
        }

        /// <summary>
        /// Revoke the security context attribute.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Revoke(bool throw_on_error)
        {
            if (_port != null && !_port.Handle.IsClosed)
            {
                return NtSystemCalls.NtAlpcRevokeSecurityContext(_port.Handle, AlpcRevokeSecurityContextFlags.None, handle.ToInt64());
            }
            return NtStatus.STATUS_SUCCESS;
        }

        /// <summary>
        /// Revoke the security context attribute.
        /// </summary>
        public void Revoke()
        {
            Revoke(true);
        }
    }
}
