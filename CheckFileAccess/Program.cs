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

using NDesk.Options;
using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace CheckFileAccess
{
    class Program
    {
        static bool _recursive = false;
        static bool _print_sddl = false; 
        static bool _show_write_only = false;
        static HashSet<string> _walked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);        
        static NtType _type;
        static NtToken _token;
        static uint _file_filter;
        static uint _dir_filter;
        static bool _only_dirs;
        static bool _quiet;
        
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckFileAccess [options] path1 [path2..pathN]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static string AccessMaskToString(uint granted_access, bool directory)
        {
            if (_type.HasFullPermission(granted_access))
            {
                return "Full Permission";
            }
            
            if (directory)
            {
                FileDirectoryAccessRights rights = (FileDirectoryAccessRights)granted_access;
                return rights.ToString();
            }
            else
            {
                FileAccessRights rights = (FileAccessRights)granted_access;
                return rights.ToString();
            }
        }

        static void CheckAccess(FileSystemInfo entry)
        {
            try
            {
                SecurityDescriptor sd = NtSecurity.FromNamedResource(@"\??\" + entry.FullName, "file");
                if (sd != null)
                {
                    bool is_dir = entry is DirectoryInfo;
                    uint granted_access;
                    
                    if(is_dir && _dir_filter != 0)
                    {
                        granted_access = NtSecurity.GetAllowedAccess(_token.Handle, _type, _dir_filter, sd.ToByteArray());
                    }
                    else if (!is_dir && _file_filter != 0)
                    {
                        granted_access = NtSecurity.GetAllowedAccess(_token.Handle, _type, _file_filter, sd.ToByteArray());
                    }
                    else
                    {
                        granted_access = NtSecurity.GetMaximumAccess(_token.Handle, _type, sd.ToByteArray());
                    }

                    if (granted_access != 0)
                    {
                        // Now reget maximum access rights
                        if (_dir_filter != 0 || _file_filter != 0)
                        {
                            granted_access = NtSecurity.GetMaximumAccess(_token.Handle, _type, sd.ToByteArray());
                        }

                        if (!_show_write_only || _type.HasWritePermission(granted_access))
                        {                                                
                            Console.WriteLine("{0}{1} : {2:X08} {3}", entry.FullName, is_dir ? "\\" : "", granted_access, AccessMaskToString(granted_access, is_dir));
                            if (_print_sddl)
                            {
                                Console.WriteLine("{0}", sd.ToSddl());
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
            }
        }

        static void DumpFile(FileInfo file)
        {
            if (_walked.Contains(file.FullName))
            {
                return;
            }

            _walked.Add(file.FullName); 

            try
            {
                CheckAccess(file);
            }
            catch (Exception ex)
            {
                if (!_quiet)
                {
                    Console.Error.WriteLine("Error dumping file {0} {1}", file.FullName, ex.Message);
                }
            }
        }

        static void DumpDirectory(DirectoryInfo dir)
        {
            if (_walked.Contains(dir.FullName))
            {
                return;
            }
            
            _walked.Add(dir.FullName);

            try
            {
                CheckAccess(dir);

                if (!_only_dirs)
                {
                    foreach (FileInfo fi in dir.GetFiles())
                    {
                        DumpFile(fi);
                    }
                }

                if (_recursive)
                {
                    foreach (DirectoryInfo child in dir.GetDirectories())
                    {
                        DumpDirectory(child);
                    }
                }
            }
            catch (Exception ex)
            {
                if (!_quiet)
                {
                    Console.Error.WriteLine("Error dumping directory {0} {1}", dir.FullName, ex.Message);
                }
            }
        }

        static uint ParseRight(string name, Type enumtype)
        {
            return (uint)Enum.Parse(enumtype, name, true);
        }

        static void Main(string[] args)
        {
            bool show_help = false;

            int pid = Process.GetCurrentProcess().Id;

            try
            {
                OptionSet opts = new OptionSet() {
                            { "r", "Recursive tree directory listing",  
                                v => _recursive = v != null },                                  
                            { "sddl", "Print full SDDL security descriptors", v => _print_sddl = v != null },
                            { "p|pid=", "Specify a PID of a process to impersonate when checking", v => pid = int.Parse(v.Trim()) },
                            { "w", "Show only write permissions granted", v => _show_write_only = v != null },
                            { "f=", String.Format("Filter on a file right [{0}]", 
                                String.Join(",", Enum.GetNames(typeof(FileAccessRights)))), v => _file_filter |= ParseRight(v, typeof(FileAccessRights)) },  
                            { "d=", String.Format("Filter on a directory right [{0}]", 
                                String.Join(",", Enum.GetNames(typeof(FileDirectoryAccessRights)))), v => _dir_filter |= ParseRight(v, typeof(FileDirectoryAccessRights)) },
                            { "x=", "Specify a base path to exclude from recursive search", v => _walked.Add(v) },
                            { "q", "Don't print errors", v => _quiet = v != null },
                            { "onlydirs", "Only check the permissions of directories", v => _only_dirs = v != null },
                            { "h|help",  "show this message and exit", v => show_help = v != null },
                        };

                List<string> paths = opts.Parse(args);

                if (show_help || (paths.Count == 0))
                {
                    ShowHelp(opts);
                }
                else
                {
                    _type = NtType.GetTypeByName("file");
                    _token = NtToken.OpenProcessToken(pid);

                    foreach (string path in paths)
                    {
                        if ((File.GetAttributes(path) & System.IO.FileAttributes.Directory) == System.IO.FileAttributes.Directory)
                        {
                            DumpDirectory(new DirectoryInfo(path));
                        }
                        else
                        {
                            DumpFile(new FileInfo(path));
                        }
                    }
                }
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }    
}
