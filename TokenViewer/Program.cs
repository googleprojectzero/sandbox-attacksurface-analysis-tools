//  Copyright 2015 Google Inc. All Rights Reserved.
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

using NtApiDotNet;
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace TokenViewer
{
    static class Program
    {
        enum EOLE_AUTHENTICATION_CAPABILITIES
        {
            EOAC_NONE = 0,
            EOAC_MUTUAL_AUTH = 0x1,
            EOAC_STATIC_CLOAKING = 0x20,
            EOAC_DYNAMIC_CLOAKING = 0x40,
            EOAC_ANY_AUTHORITY = 0x80,
            EOAC_MAKE_FULLSIC = 0x100,
            EOAC_DEFAULT = 0x800,
            EOAC_SECURE_REFS = 0x2,
            EOAC_ACCESS_CONTROL = 0x4,
            EOAC_APPID = 0x8,
            EOAC_DYNAMIC = 0x10,
            EOAC_REQUIRE_FULLSIC = 0x200,
            EOAC_AUTO_IMPERSONATE = 0x400,
            EOAC_NO_CUSTOM_MARSHAL = 0x2000,
            EOAC_DISABLE_AAA = 0x1000
        }

        enum AuthnLevel
        {
            RPC_C_AUTHN_LEVEL_DEFAULT       = 0,
            RPC_C_AUTHN_LEVEL_NONE          = 1,
            RPC_C_AUTHN_LEVEL_CONNECT       = 2,
            RPC_C_AUTHN_LEVEL_CALL          = 3,
            RPC_C_AUTHN_LEVEL_PKT           = 4,
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY   = 6
        }

        enum ImpLevel
        {
            RPC_C_IMP_LEVEL_DEFAULT = 0,
            RPC_C_IMP_LEVEL_ANONYMOUS = 1,
            RPC_C_IMP_LEVEL_IDENTIFY = 2,
            RPC_C_IMP_LEVEL_IMPERSONATE = 3,
            RPC_C_IMP_LEVEL_DELEGATE = 4,
        }

        [DllImport("ole32.dll")]
        static extern void CoInitializeSecurity(
            IntPtr pSecDesc,
            int cAuthSvc,
            IntPtr asAuthSvc,
            IntPtr pReserved1,
            AuthnLevel dwAuthnLevel,
            ImpLevel dwImpLevel,
            IntPtr pAuthList,
            EOLE_AUTHENTICATION_CAPABILITIES dwCapabilities,
            IntPtr pReserved3
        );

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero, AuthnLevel.RPC_C_AUTHN_LEVEL_DEFAULT, 
                ImpLevel.RPC_C_IMP_LEVEL_IMPERSONATE, IntPtr.Zero, EOLE_AUTHENTICATION_CAPABILITIES.EOAC_DYNAMIC_CLOAKING, IntPtr.Zero);
            NtToken.EnableDebugPrivilege();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
