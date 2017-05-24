//  Copyright 2016 Google Inc. All Rights Reserved.
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

using SandboxAnalysisUtils;
using NDesk.Options;
using NtApiDotNet;
using System;
using System.Collections.Generic;

namespace NewProcessFromToken
{
    class Program
    {
        static TokenIntegrityLevel ParseIL(string il)
        {
            il = il.Trim().ToLower();
            if (String.IsNullOrWhiteSpace(il))
            {
                throw new ArgumentException("IL name can't be empty");
            }

            switch (il[0])
            {
                case 'u':
                    return TokenIntegrityLevel.Untrusted;
                case 'l':
                    return TokenIntegrityLevel.Low;
                case 'm':
                    return TokenIntegrityLevel.Medium;
                case 'h':
                    return TokenIntegrityLevel.High;
                case 's':
                    return TokenIntegrityLevel.System;
            }

            int result;
            if (int.TryParse(il, out result))
            {
                return (TokenIntegrityLevel)result;
            }

            if (il.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return (TokenIntegrityLevel)int.Parse(il.Substring(2), System.Globalization.NumberStyles.HexNumber);
            }

            throw new ArgumentException("Invalid IL format");
        }

        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: NewProcessFromToken: [options] pid cmdline");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
            Console.WriteLine("* level:");
            Console.WriteLine("  u - Untrusted");
            Console.WriteLine("  l - Low");
            Console.WriteLine("  m - Medium");
            Console.WriteLine("  h - High");
            Console.WriteLine("  s - System");
            Console.WriteLine("  0xXXXX - Arbitrary IL");
            Environment.Exit(1);
        }

        static void Main(string[] args)
        {
            Win32Process new_process = null;
            try
            {
                CreateProcessFlags flags = CreateProcessFlags.None;
                bool parent_process = false;
                bool set_il = false;
                TokenIntegrityLevel il = 0;
                bool show_help = false;

                OptionSet opts = new OptionSet() {
                            { "p", "Use parent technique to create the new process",  v => parent_process = v != null },
                            { "j", "Try and break away from the current process job", v => flags |= v != null ? CreateProcessFlags.CREATE_BREAKAWAY_FROM_JOB : 0 },
                            { "c", "Create a new console for the process", v => flags |= v != null ? CreateProcessFlags.CREATE_NEW_CONSOLE : 0 },
                            { "s", "Create the process suspended", v => flags |= v != null ? CreateProcessFlags.CREATE_SUSPENDED : 0 },
                            { "i|il=", "Set the process IL level", v => {
                                il = ParseIL(v); set_il = true;
                            } },
                            { "h|help",  "show this message and exit", v => show_help = v != null },
                        };

                int pid;

                List<string> commands = opts.Parse(args);
                if (show_help || commands.Count < 2)
                {
                    ShowHelp(opts);
                }

                if (!int.TryParse(commands[0], out pid))
                {
                    throw new ArgumentException("Couldn't parse PID value");
                }

                if (!NtToken.EnableDebugPrivilege())
                {
                    Console.WriteLine("WARNING: Couldn't enable Debug privilege");
                }

                using (NtProcess process = NtProcess.Open(pid, ProcessAccessRights.MaximumAllowed))
                {
                    if (parent_process)
                    {
                        new_process = Win32Process.CreateProcess(process, null, commands[1], set_il ? flags | CreateProcessFlags.CREATE_SUSPENDED : flags, null);
                        if (set_il)
                        {
                            using (NtToken token = new_process.Process.OpenToken())
                            {
                                token.SetIntegrityLevel(il);
                            }
                            if ((flags & CreateProcessFlags.CREATE_SUSPENDED) == 0)
                            {
                                new_process.Thread.Resume();
                            }
                        }
                    }
                    else
                    {
                        using (NtToken token = process.OpenToken())
                        {
                            using (NtToken target_token = token.DuplicateToken(TokenType.Primary, SecurityImpersonationLevel.Anonymous, TokenAccessRights.MaximumAllowed))
                            {
                                if (set_il)
                                {
                                    target_token.SetIntegrityLevel(il);
                                }

                                new_process = Win32Process.CreateProcessAsUser(target_token, null, commands[1], flags, null);
                            }
                        }
                    }

                    using (new_process)
                    {
                        Console.WriteLine("Created Process: PID: {0}, SID {1}", new_process.Pid, new_process.Process.SessionId);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: {0}", ex.Message);
                if (new_process != null && new_process.Process != null)
                {
                    try
                    {
                        new_process.Process.Terminate(NtStatus.STATUS_WAIT_1);
                    }
                    catch
                    {
                    }
                }
            }
        }
    }
}
