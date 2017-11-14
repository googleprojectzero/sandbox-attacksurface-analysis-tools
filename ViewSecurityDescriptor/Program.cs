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
using SandboxAnalysisUtils;
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
            if (args.Length != 1 && args.Length != 3)
            {
                MessageBox.Show("Usage: ViewSecurityDescriptor.exe (handle|Name SDDL NtType)", "Usage", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
            else
            {
                try
                {
                    if (args.Length == 1)
                    {
                        var handle = new SafeKernelObjectHandle(new IntPtr(int.Parse(args[0])), true);
                        using (var obj = NtGeneric.FromHandle(handle))
                        {
                            NativeBridge.EditSecurity(IntPtr.Zero, obj, obj.Name, true);
                        }
                    }
                    else
                    {
                        SecurityDescriptor sd = new SecurityDescriptor(args[1]);
                        NtType type = NtType.GetTypeByName(args[2], false);
                        if (type == null)
                        {
                            throw new ArgumentException(string.Format("Unknown NT type {0}", args[2]));
                        }
                        NativeBridge.EditSecurity(IntPtr.Zero, args[0], sd, type);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
    }
}
