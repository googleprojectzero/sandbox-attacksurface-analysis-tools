//  Copyright 2017 Google Inc. All Rights Reserved.
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
using NtApiDotNet.Forms;
using System;
using System.Windows.Forms;

namespace ViewSecurityDescriptor
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            try
            {
                if (args.Length == 0)
                {
                    MessageBox.Show("Usage: ViewSecurityDescriptor.exe (handle [--readonly]|Name (SDDL|-B64) NtType [Container])", "Usage", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                }
                else
                {
                    if (args.Length < 3)
                    {
                        var handle = new SafeKernelObjectHandle(new IntPtr(int.Parse(args[0])), true);
                        bool read_only = args.Length > 1 && args[1].Equals("--readonly");
                        using (var obj = NtGeneric.FromHandle(handle))
                        {
                            Application.Run(new SecurityDescriptorViewerForm(obj.ToTypedObject(), read_only));
                        }
                    }
                    else
                    {
                        NtType type = new NtType(args[2]);
                        SecurityDescriptor sd;
                        if (args[1].StartsWith("-"))
                        {
                            sd = new SecurityDescriptor(Convert.FromBase64String(args[1].Substring(1)));
                        }
                        else
                        {
                            sd = new SecurityDescriptor(args[1]);
                        }

                        bool container = false;
                        if (args.Length > 3)
                        {
                            container = bool.Parse(args[3]);
                        }

                        Application.Run(new SecurityDescriptorViewerForm(args[0], sd, type, container));
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
