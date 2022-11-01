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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.SafeHandles
{
    internal class SafeSecWinntAuthIdentityBuffer : SafeBufferGeneric
    {
        #region Private Members
        private Type _auth_type;

        private Type GetAuthIdType()
        {
            if (Length < 4)
                InitializeLength(4);
            int version = Read<int>(0);
            switch (version)
            {
                case SEC_WINNT_AUTH_IDENTITY_EX2.SEC_WINNT_AUTH_IDENTITY_VERSION_2:
                    return typeof(SEC_WINNT_AUTH_IDENTITY_EX2);
                case SEC_WINNT_AUTH_IDENTITY_EX.SEC_WINNT_AUTH_IDENTITY_VERSION:
                    return typeof(SEC_WINNT_AUTH_IDENTITY_EX);
                default:
                    return typeof(SEC_WINNT_AUTH_IDENTITY);
            }
        }

        private void Initialize()
        {
            if (IsInvalid || _auth_type != null)
                return;
            _auth_type = GetAuthIdType();
            InitializeLength(Marshal.SizeOf(_auth_type));
        }

        private uint GetFlagsOffset()
        {
            Initialize();
            if (_auth_type == null)
                throw new ArgumentException("Invalid authentication ID buffer.");
            return (uint)Marshal.OffsetOf(_auth_type, "Flags").ToInt32();
        }
        #endregion

        protected override bool ReleaseHandle()
        {
            SecurityNativeMethods.SspiFreeAuthIdentity(handle);
            return true;
        }

        public SafeSecWinntAuthIdentityBuffer()
            : base(IntPtr.Zero, 0, true)
        {
        }

        public SecWinNtAuthIdentityFlags Flags
        {
            get => (SecWinNtAuthIdentityFlags)Read<int>(GetFlagsOffset());
            set => Write(GetFlagsOffset(), (int)value);
        }

        public Type AuthType
        {
            get
            {
                Initialize();
                return _auth_type;
            }
        }


        public override bool IsInvalid => handle == IntPtr.Zero;

        public static SafeSecWinntAuthIdentityBuffer Null => new SafeSecWinntAuthIdentityBuffer();
    }
}
