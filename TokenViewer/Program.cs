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

using NDesk.Options;
using NtApiDotNet;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
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

        static void ShowHelp(OptionSet p)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("Usage: ObjectList [options] path1 [path2..pathN]");
            builder.AppendLine();
            builder.AppendLine("Options:");
            StringWriter writer = new StringWriter();
            p.WriteOptionDescriptions(writer);
            builder.Append(writer.ToString());
            MessageBox.Show(builder.ToString(), "Options", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        static Form GetFormFromArgs(string[] args)
        {
            try
            {
                int pid = -1;
                int handle = -1;
                string text = String.Empty;
                bool show_help = false;

                OptionSet opts = new OptionSet() {
                        { "p|pid=", "Specify a process ID to view the token.",
                            v => pid = int.Parse(v) },
                        { "handle=", "Specify an inherited handle to view.",
                            v => handle = int.Parse(v) },
                        { "text=", "Specify a text string for the token window.",
                            v => text = v },
                        { "h|help",  "Show this message and exit",
                           v => show_help = v != null },
                    };

                opts.Parse(args);

                if (show_help || (handle <= 0 && pid <= 0))
                {
                    ShowHelp(opts);
                }
                else if (handle > 0)
                {
                    using (NtToken token = NtToken.FromHandle(new SafeKernelObjectHandle(new IntPtr(handle), true)))
                    {
                        if (token.NtType != NtType.GetTypeByType<NtToken>())
                        {
                            throw new ArgumentException("Passed handle is not a token");
                        }

                        return new TokenForm(token.Duplicate(), text);
                    }
                }
                else if (pid > 0)
                {
                    using (NtProcess process = NtProcess.Open(pid, ProcessAccessRights.QueryLimitedInformation))
                    {
                        return new TokenForm(process.OpenToken(), 
                            string.Format("{0}:{1}", process.Name, pid));
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            return null;
        }

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero, AuthnLevel.RPC_C_AUTHN_LEVEL_DEFAULT, 
                ImpLevel.RPC_C_IMP_LEVEL_IMPERSONATE, IntPtr.Zero, EOLE_AUTHENTICATION_CAPABILITIES.EOAC_DYNAMIC_CLOAKING, IntPtr.Zero);
            NtToken.EnableDebugPrivilege();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Form main_form;

            if (args.Length > 0)
            {
                main_form = GetFormFromArgs(args);
                if (main_form == null)
                {
                    Environment.Exit(1);
                }
            }
            else
            {
                main_form = new MainForm();
            }
            Application.Run(main_form);
        }
    }
}
