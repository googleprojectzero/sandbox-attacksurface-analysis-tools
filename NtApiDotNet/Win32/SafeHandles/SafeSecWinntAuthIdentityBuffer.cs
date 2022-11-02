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

using NtApiDotNet.Win32.Security.Credential;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.SafeHandles
{
    internal class SafeSecWinntAuthIdentityBuffer : SafeBufferGeneric
    {
        #region Private Members
        private Type _auth_type;
        private string _user;
        private string _domain;
        private string _password;
        private string _package_list;
        private PackedCredential _packed_credentials;

        private static string ReadString(IntPtr ptr, int length, SecWinNtAuthIdentityFlags flags)
        {
            if (ptr == IntPtr.Zero)
                return null;
            if (flags.HasFlagSet(SecWinNtAuthIdentityFlags.Ansi))
                return Marshal.PtrToStringAnsi(ptr, length);
            return Marshal.PtrToStringUni(ptr, length);
        }

        private string ReadString(uint offset, int length, SecWinNtAuthIdentityFlags flags)
        {
            if (offset == 0)
                return null;

            if (flags.HasFlagSet(SecWinNtAuthIdentityFlags.Ansi))
                return ReadAnsiString(offset, length);
            return ReadUnicodeString(offset, length / 2);
        }

        private void InitializeAuthId()
        {
            _auth_type = typeof(SEC_WINNT_AUTH_IDENTITY);
            InitializeLength(Marshal.SizeOf(_auth_type));
            var value = Read<SEC_WINNT_AUTH_IDENTITY_Struct>(0);
            _user = ReadString(value.User, value.UserLength, value.Flags);
            _domain = ReadString(value.Domain, value.DomainLength, value.Flags);
            _password = ReadString(value.Password, value.PasswordLength, value.Flags);
            _package_list = string.Empty;
        }

        private void InitializeAuthIdEx()
        {
            _auth_type = typeof(SEC_WINNT_AUTH_IDENTITY_EX);
            InitializeLength(Marshal.SizeOf(_auth_type));
            var value = Read<SEC_WINNT_AUTH_IDENTITY_EX_Struct>(0);
            _user = ReadString(value.User, value.UserLength, value.Flags);
            _domain = ReadString(value.Domain, value.DomainLength, value.Flags);
            _password = ReadString(value.Password, value.PasswordLength, value.Flags);
            _package_list = ReadString(value.PackageList, value.PackageListLength, value.Flags);
        }

        private void InitializeAuthIdEx2()
        {
            _auth_type = typeof(SEC_WINNT_AUTH_IDENTITY_EX2);
            InitializeLength(Marshal.SizeOf(_auth_type));
            var value = Read<SEC_WINNT_AUTH_IDENTITY_EX2>(0);
            InitializeLength(Math.Max(Length, value.cbStructureLength));
            _user = ReadString(value.UserOffset, value.UserLength, value.Flags);
            _domain = ReadString(value.DomainOffset, value.DomainLength, value.Flags);
            if (value.PackedCredentialsOffset != 0)
            {
                byte[] creds = ReadBytes(value.PackedCredentialsOffset, value.PackedCredentialsLength);
                PackedCredential.TryParse(creds, out _packed_credentials);
            }
            _package_list = ReadString(value.PackageListOffset, value.PackageListLength, value.Flags);
        }

        private void Initialize()
        {
            if (IsInvalid || _auth_type != null)
                return;


            if (Length < 4)
                InitializeLength(4);
            int version = Read<int>(0);
            switch (version)
            {
                case SEC_WINNT_AUTH_IDENTITY_EX2.SEC_WINNT_AUTH_IDENTITY_VERSION_2:
                    InitializeAuthIdEx2();
                    break;
                case SEC_WINNT_AUTH_IDENTITY_EX.SEC_WINNT_AUTH_IDENTITY_VERSION:
                    InitializeAuthIdEx();
                    break;
                default:
                    InitializeAuthId();
                    break;
            }
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

        public string User
        {
            get
            {
                Initialize();
                return _user;
            }
        }

        public string Domain
        {
            get
            {
                Initialize();
                return _domain;
            }
        }

        public string Password
        {
            get
            {
                Initialize();
                return _password;
            }
        }

        public string PackageList
        {
            get
            {
                Initialize();
                return _package_list;
            }
        }

        public PackedCredential PackedCredentials
        {
            get
            {
                Initialize();
                return _packed_credentials;
            }
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
