//  Copyright 2015 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using HandleUtils;
using NDesk.Options;
using System;
using System.Collections.Generic;
using System.ComponentModel;
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

        class TokenEntry
        {
            public TokenEntry(NativeHandle handle)
            {
                Handle = handle;
                SecurityDescriptor = NativeBridge.GetSecurityDescriptorForHandle(handle);
                StringSecurityDescriptor = NativeBridge.GetStringSecurityDescriptor(SecurityDescriptor);
                UserName = NativeBridge.GetUserNameForToken(handle);
            }

            public string UserName { get; private set; }
            public NativeHandle Handle { get; private set; }
            public byte[] SecurityDescriptor { get; private set; }
            public string StringSecurityDescriptor { get; private set; }
        }

        class ThreadEntry
        {
            public ThreadEntry(NativeHandle handle)
            {
                Handle = handle;
                SecurityDescriptor = NativeBridge.GetSecurityDescriptorForHandle(handle);
                StringSecurityDescriptor = NativeBridge.GetStringSecurityDescriptor(SecurityDescriptor);
                Tid = NativeBridge.GetTidForThread(handle);
                NativeHandle token = NativeBridge.OpenThreadToken(handle);
                if (token != null)
                {
                    Token = new TokenEntry(token);
                }
            }

            public NativeHandle Handle { get; private set; }
            public int Tid { get; private set; }
            public byte[] SecurityDescriptor { get; private set; }
            public string StringSecurityDescriptor { get; private set; }
            public TokenEntry Token { get; private set; }

            public string GetGrantedAccess()
            {
                return NativeBridge.MapAccessToString(NativeBridge.GetGrantedAccess(Handle), typeof(ThreadAccessRights));
            }
        }

        class ProcessEntry
        {
            public ProcessEntry(NativeHandle handle) : this(handle, null)
            {
            }

            public ProcessEntry(NativeHandle handle, NativeHandle[] threads)
            {
                Handle = handle;
                Pid = NativeBridge.GetPidForProcess(handle);
                if (threads == null)
                {
                    threads = NativeBridge.GetThreadsForProcess(handle);
                }

                Threads = threads.Select(h => new ThreadEntry(h)).ToArray();
                Array.Sort(Threads, (a, b) => a.Tid - b.Tid);

                SecurityDescriptor = NativeBridge.GetSecurityDescriptorForHandle(handle);
                StringSecurityDescriptor = NativeBridge.GetStringSecurityDescriptor(SecurityDescriptor);

                ImagePath = String.Empty;
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
                    ImagePath = NativeBridge.GetProcessPath(handle);
                    Name = Path.GetFileNameWithoutExtension(ImagePath);
                }

                NativeHandle token = NativeBridge.OpenProcessToken(handle);
                if (token != null)
                {
                    Token = new TokenEntry(token);
                }
            }

            // Dummy constructor, used when we can't open the process for the thread.
            public ProcessEntry(int pid, NativeHandle[] threads)
            {
                Pid = pid;
                Threads = threads.Select(h => new ThreadEntry(h)).ToArray();
                Array.Sort(Threads, (a, b) => a.Tid - b.Tid);
                
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
                StringSecurityDescriptor = String.Empty;
                SecurityDescriptor = new byte[0];
            }

            public NativeHandle Handle { get; private set; }
            public ThreadEntry[] Threads { get; private set; }
            public int Pid { get; private set; }
            public byte[] SecurityDescriptor { get; private set; }
            public string StringSecurityDescriptor { get; private set; }
            public string Name { get; private set; }
            public string ImagePath { get; private set; }
            public TokenEntry Token { get; private set; }

            public string GetGrantedAccess()
            {
                if (Handle != null)
                {
                    return NativeBridge.MapAccessToString(NativeBridge.GetGrantedAccess(Handle), typeof(ProcessAccessRights));
                }
                return String.Empty;
            }
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
                        NativeHandle[] all_threads = null;

                        using (ImpersonateProcess imp = NativeBridge.Impersonate(_pid,
                           _identify_only ? TokenSecurityLevel.Identification : TokenSecurityLevel.Impersonate))
                        {                            
                            if (pids.Count > 0)
                            {
                                List<NativeHandle> ths = new List<NativeHandle>();                              
                                foreach (string pid_name in pids)
                                {
                                    try
                                    {
                                        ths.Add(NativeBridge.OpenThread(int.Parse(pid_name)));
                                    }
                                    catch (Win32Exception ex)
                                    {
                                        Console.WriteLine("Error opening tid {0} - {1}", pid_name, ex.Message);
                                    }
                                }

                                all_threads = ths.ToArray();
                            }
                            else
                            {
                                all_threads = NativeBridge.GetThreads();
                            }

                            List<ProcessEntry> procs = new List<ProcessEntry>();

                            foreach (var group in all_threads.GroupBy(t => NativeBridge.GetPidForThread(t)))
                            {
                                ProcessEntry entry = null;
                                NativeHandle[] threads = group.ToArray();
                                try
                                {
                                    entry = new ProcessEntry(NativeBridge.OpenProcess(group.Key), threads);
                                }
                                catch (Win32Exception)
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
                            using (ImpersonateProcess imp = NativeBridge.Impersonate(_pid,
                                _identify_only ? TokenSecurityLevel.Identification : TokenSecurityLevel.Impersonate))
                            {
                                foreach (string pid_name in pids)
                                {
                                    try
                                    {
                                        procs.Add(new ProcessEntry(NativeBridge.OpenProcess(int.Parse(pid_name))));
                                    }
                                    catch (Win32Exception ex)
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
                                using (ImpersonateProcess imp = NativeBridge.Impersonate(_pid,
                                    _identify_only ? TokenSecurityLevel.Identification : TokenSecurityLevel.Impersonate))
                                {
                                    processes = NativeBridge.GetProcesses().Select(h => new ProcessEntry(h));
                                }

                                if (_named_process && pids.Count > 0)
                                {
                                    processes = processes.Where(p => pids.Contains(p.Name.ToLower()));
                                }
                            }
                            catch (Win32Exception ex)
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
                        Console.WriteLine("{0}: {1} {2}", process.Pid, process.Name, process.GetGrantedAccess());
                        if (_print_sddl && process.StringSecurityDescriptor.Length > 0)
                        {
                            Console.WriteLine("SDDL: {0}", process.StringSecurityDescriptor);
                        }

                        if (_dump_token && process.Token != null)
                        {
                            Console.WriteLine("User: {0}", process.Token.UserName);
                            if (_print_sddl && process.Token.StringSecurityDescriptor.Length > 0)
                            {
                                Console.WriteLine("Token SDDL: {0}", process.Token.StringSecurityDescriptor);
                            }
                        }

                        if (_dump_threads)
                        {
                            foreach (ThreadEntry thread in process.Threads)
                            {
                                Console.WriteLine("-- Thread {0}: {1}", thread.Tid, thread.GetGrantedAccess());
                                if (_print_sddl && thread.StringSecurityDescriptor.Length > 0)
                                {
                                    Console.WriteLine("---- SDDL: {0}", thread.StringSecurityDescriptor);
                                }

                                if (_dump_token && thread.Token != null)
                                {                                    
                                    Console.WriteLine("---- Impersonating {0}", thread.Token.UserName);
                                    if (_print_sddl && thread.Token.StringSecurityDescriptor.Length > 0)
                                    {
                                        Console.WriteLine("---- Token SDDL: {0}", thread.Token.StringSecurityDescriptor);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

    }
}
