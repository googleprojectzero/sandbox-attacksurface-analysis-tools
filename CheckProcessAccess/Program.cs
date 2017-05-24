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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace CheckProcessAccess
{
    class Program
    {     
        static int _pid;     
        static bool _identify_only;
        static bool _dump_threads;
        static bool _dump_token;
        static bool _print_sddl;
        static bool _named_process;
        static bool _all_threads;        

        class ThreadEntry
        {
            public ThreadEntry(NtThread handle)
            {
                Handle = handle;
                Tid = handle.ThreadId;
                try
                {
                    Token = handle.OpenToken();
                }
                catch
                {
                }
            }

            public NtThread Handle { get; private set; }
            public int Tid { get; private set; }
            public NtToken Token { get; private set; }
        }

        class ProcessEntry
        {
            public ProcessEntry(NtProcess handle) : this(handle, null)
            {
            }

            public ProcessEntry(NtProcess handle, NtThread[] threads)
            {
                Handle = handle;

                if (handle.IsAccessGranted(ProcessAccessRights.QueryInformation) || handle.IsAccessGranted(ProcessAccessRights.QueryLimitedInformation))
                {
                    Pid = handle.ProcessId;
                }

                if (threads == null)
                {
                    threads = handle.GetThreads(ThreadAccessRights.MaximumAllowed).ToArray();
                }

                Threads = threads.Select(h => new ThreadEntry(h)).ToArray();
                Array.Sort(Threads, (a, b) => a.Tid - b.Tid);
                ImagePath = String.Empty;
                Name = String.Empty;
                if (Pid == 0)
                {
                    Name = "Idle";
                }
                else if (Pid == 4)
                {
                    Name = "System";
                }
                else
                {
                    if (Handle.IsAccessGranted(ProcessAccessRights.QueryLimitedInformation))
                    {
                        try
                        {
                            ImagePath = Handle.GetImageFilePath(false);
                            Name = Path.GetFileNameWithoutExtension(ImagePath);
                        }
                        catch (NtException)
                        {
                        }
                    }
                }

                CommandLine = String.Empty;
                if (Handle.IsAccessGranted(ProcessAccessRights.QueryInformation) || Handle.IsAccessGranted(ProcessAccessRights.QueryLimitedInformation))
                {
                    try
                    {
                        Token = Handle.OpenToken();
                    }
                    catch (NtException)
                    {
                    }

                    try
                    {
                        CommandLine = Handle.CommandLine;
                    }
                    catch (NtException)
                    {
                    }
                }
            }

            // Dummy constructor, used when we can't open the process for the thread.
            public ProcessEntry(int pid, NtThread[] threads)
            {
                Pid = pid;
                Threads = threads.Select(h => new ThreadEntry(h)).ToArray();
                Array.Sort(Threads, (a, b) => a.Tid - b.Tid);

                CommandLine = String.Empty;
                ImagePath = "Unknown";
                if (Pid == 0)
                {
                    Name = "Idle";
                }
                else if (Pid == 4)
                {
                    Name = "System";
                }
                else
                {
                    ImagePath = "Unknown";
                    Name = Path.GetFileNameWithoutExtension(ImagePath);
                }
            }

            public string GetGrantedAccessString()
            {
                if (Handle != null)
                {
                    return Handle.GetGrantedAccessString();
                }
                else
                {
                    return String.Empty;
                }
            }

            public NtProcess Handle { get; private set; }
            public ThreadEntry[] Threads { get; private set; }
            public int Pid { get; private set; }
            public string Name { get; private set; }
            public string ImagePath { get; private set; }
            public NtToken Token { get; private set; }
            public string CommandLine { get; private set; }
        }
        
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckProcessAccess [options] [pid0 ... pinN]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static void Main(string[] args)
        {
            bool show_help = false;                        

            _pid = Process.GetCurrentProcess().Id;

            try
            {
                OptionSet opts = new OptionSet() {                        
                        { "p|pid=", "Specify a PID of a process to impersonate when checking", v => _pid = int.Parse(v.Trim()) },    
                        { "n", "Specifes the list of arguments represents names instead of pids", v => _named_process = v != null },        
                        { "i", "Use an indentify level token when impersonating", v => _identify_only = v != null },                        
                        { "t", "Dump accessible threads for process", v => _dump_threads = v != null },                        
                        { "k", "Dump tokens for accessible objects", v => _dump_token = v != null },
                        { "a", "Start with all accessible threads instead of processes", v => _dump_threads = _all_threads = v != null },
                        { "sddl", "Dump SDDL strings for objects", v => _print_sddl = v != null },
                        { "h|help",  "show this message and exit", 
                           v => show_help = v != null },
                    };

                List<string> pids = opts.Parse(args).Select(s => s.ToLower()).ToList();
                
                if (show_help)
                {
                    ShowHelp(opts);
                }
                else
                {
                    IEnumerable<ProcessEntry> processes = new ProcessEntry[0];

                    if (_all_threads)
                    {
                        NtThread[] all_threads = null;

                        using (var imp = NtToken.Impersonate(_pid,
                           _identify_only ? SecurityImpersonationLevel.Identification : SecurityImpersonationLevel.Impersonation))
                        {                            
                            if (pids.Count > 0)
                            {
                                List<NtThread> ths = new List<NtThread>();                              
                                foreach (string pid_name in pids)
                                {
                                    try
                                    {
                                        ths.Add(NtThread.Open(int.Parse(pid_name), ThreadAccessRights.MaximumAllowed));
                                    }
                                    catch (NtException ex)
                                    {
                                        Console.WriteLine("Error opening tid {0} - {1}", pid_name, ex.Message);
                                    }
                                }

                                all_threads = ths.ToArray();
                            }
                            else
                            {
                                all_threads = NtThread.GetThreads(ThreadAccessRights.MaximumAllowed).ToArray();
                            }

                            List<ProcessEntry> procs = new List<ProcessEntry>();

                            foreach (var group in all_threads.GroupBy(t => t.ProcessId))
                            {
                                ProcessEntry entry = null;
                                NtThread[] threads = group.ToArray();
                                try
                                {
                                    entry = new ProcessEntry(NtProcess.Open(group.Key, ProcessAccessRights.MaximumAllowed), threads);
                                }
                                catch (NtException)
                                {
                                    entry = new ProcessEntry(group.Key, threads);
                                }
                                procs.Add(entry);
                            }
                            processes = procs;
                        }
                    }
                    else
                    {
                        if (pids.Count > 0 && !_named_process)
                        {
                            List<ProcessEntry> procs = new List<ProcessEntry>();
                            using (var imp = NtToken.Impersonate(_pid,
                                _identify_only ? SecurityImpersonationLevel.Identification : SecurityImpersonationLevel.Impersonation))
                            {
                                foreach (string pid_name in pids)
                                {
                                    try
                                    {
                                        procs.Add(new ProcessEntry(NtProcess.Open(int.Parse(pid_name), ProcessAccessRights.MaximumAllowed)));
                                    }
                                    catch (NtException ex)
                                    {
                                        Console.WriteLine("Error opening pid {0} - {1}", pid_name, ex.Message);
                                    }
                                }
                            }

                            processes = procs;
                        }
                        else
                        {
                            try
                            {
                                HashSet<string> names = new HashSet<string>(pids, StringComparer.OrdinalIgnoreCase);
                                using (var imp = NtToken.Impersonate(_pid,
                                    _identify_only ? SecurityImpersonationLevel.Identification : SecurityImpersonationLevel.Impersonation))
                                {
                                    processes = NtProcess.GetProcesses(ProcessAccessRights.MaximumAllowed).Select(h => new ProcessEntry(h)).ToArray();
                                }

                                if (_named_process && names.Count > 0)
                                {
                                    processes = processes.Where(p => names.Contains(p.Name));
                                }
                            }
                            catch (NtException ex)
                            {
                                Console.WriteLine(ex);
                            }
                        }
                    }

                    List<ProcessEntry> ps = processes.ToList();

                    ps.Sort((a, b) => a.Pid - b.Pid);

                    processes = ps;

                    foreach (ProcessEntry process in processes)
                    {
                        Console.WriteLine("{0}: {1} {2}", process.Pid, process.Name, process.GetGrantedAccessString());
                        if (_print_sddl && process.Handle.IsAccessGranted(ProcessAccessRights.ReadControl))
                        {
                            Console.WriteLine("SDDL: {0}", process.Handle.GetSddl());
                        }

                        if (_dump_token && process.Token != null)
                        {
                            Console.WriteLine("User: {0}", process.Token.User);
                            if (_print_sddl && process.Token.IsAccessGranted(TokenAccessRights.ReadControl))
                            {
                                Console.WriteLine("Token SDDL: {0}", process.Token.GetSddl());
                            }
                            Console.WriteLine("Token Granted Access: {0}", process.Token.GrantedAccess);
                        }

                        if (_dump_threads)
                        {
                            foreach (ThreadEntry thread in process.Threads)
                            {
                                Console.WriteLine("-- Thread {0}: {1}", thread.Tid, thread.Handle.GetGrantedAccessString());
                                if (_print_sddl && thread.Handle.IsAccessGranted(ThreadAccessRights.ReadControl))
                                {
                                    Console.WriteLine("---- SDDL: {0}", thread.Handle.GetSddl());
                                }

                                if (_dump_token && thread.Token != null)
                                {                                    
                                    Console.WriteLine("---- Impersonating {0}", thread.Token.User);
                                    if (_print_sddl && thread.Token.IsAccessGranted(TokenAccessRights.ReadControl))
                                    {
                                        Console.WriteLine("---- Token SDDL: {0}", thread.Token.GetSddl());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
