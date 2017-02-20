//  Copyright 2015, 2017 Google Inc. All Rights Reserved.
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

namespace CheckFileAccess
{
    class Program
    {
        static bool _print_sddl = false; 
        static bool _show_write_only = false;
        static HashSet<string> _walked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        static NtType _type;
        static NtToken _token;
        static uint _file_filter;
        static uint _dir_filter;
        static bool _quiet;
        
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckFileAccess [options] path1 [path2..pathN]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
            Console.WriteLine("File paths starting with @\\ will map to native NT paths");
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

        static void CheckAccess(string full_path, NtFile entry)
        {
            try
            {
                SecurityDescriptor sd = entry.GetSecurityDescriptor(SecurityInformation.AllBasic);
                if (sd != null)
                {
                    bool is_dir = entry.IsDirectory;
                    uint granted_access;

                    if (is_dir && _dir_filter != 0)
                    {
                        granted_access = NtSecurity.GetAllowedAccess(_token, _type, _dir_filter, sd.ToByteArray());
                    }
                    else if (!is_dir && _file_filter != 0)
                    {
                        granted_access = NtSecurity.GetAllowedAccess(_token, _type, _file_filter, sd.ToByteArray());
                    }
                    else
                    {
                        granted_access = NtSecurity.GetMaximumAccess(_token, _type, sd.ToByteArray());
                    }

                    if (granted_access != 0)
                    {
                        // Now reget maximum access rights
                        if (_dir_filter != 0 || _file_filter != 0)
                        {
                            granted_access = NtSecurity.GetMaximumAccess(_token, _type, sd.ToByteArray());
                        }

                        if (!_show_write_only || _type.HasWritePermission(granted_access))
                        {
                            Console.WriteLine("{0}{1} : {2:X08} {3}", full_path.TrimEnd('\\'),
                                is_dir ? "\\" : "", granted_access, AccessMaskToString(granted_access, is_dir));
                            if (_print_sddl)
                            {
                                Console.WriteLine("{0}", sd.ToSddl());
                            }
                        }
                    }
                }
            }
            catch { }
        }

        static void DumpFile(string full_path, NtFile root, int recusive_depth, bool no_files)
        {
            try
            {
                if (!_walked.Add(full_path))
                {
                    return;
                }

                using (NtFile file = OpenFile(full_path, root))
                {
                    CheckAccess(full_path, file);

                    if (file.IsDirectory && recusive_depth > 0)
                    {
                        IEnumerable<FileDirectoryEntry> dir_entries = file.QueryDirectoryInfo(null, FileTypeMask.All).OrderBy(d => d.FileName);

                        if (!no_files)
                        {
                            foreach (string file_name in dir_entries.Where(d => !d.IsDirectory).Select(d => d.FileName))
                            {
                                DumpFile(Path.Combine(full_path, file_name), file, recusive_depth - 1, no_files);
                            }
                        }

                        foreach (string file_name in dir_entries.Where(d => d.IsDirectory).Select(d => d.FileName))
                        {
                            DumpFile(Path.Combine(full_path, file_name), file, recusive_depth - 1, no_files);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (!_quiet)
                {
                    Console.Error.WriteLine("Error dumping file {0} {1}", full_path, ex.Message);
                }
            }
        }

        static NtFile OpenFile(string name, NtFile root)
        {
            bool is_pipe = root != null && root.DeviceType == FileDeviceType.NAMED_PIPE;
            name = is_pipe || root == null ? name : Path.GetFileName(name);

            return NtFile.Open(name, is_pipe ? null : root, FileAccessRights.GenericRead | FileAccessRights.Synchronize, FileShareMode.Read,
                                FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenReparsePoint);
        }
        
        static uint ParseRight(string name, Type enumtype)
        {
            return (uint)Enum.Parse(enumtype, name, true);
        }

        static string ConvertPath(string path)
        {
            if (path.StartsWith(@"@\"))
            {
                return path.Substring(1);
            }
            return NtFileUtils.DosFileNameToNt(path);
        }

        static void Main(string[] args)
        {
            bool show_help = false;

            int pid = Process.GetCurrentProcess().Id;
            int recursive_depth = 1;
            bool no_files = false;

            try
            {
                OptionSet opts = new OptionSet() {
                            { "r", "Recursive tree directory listing",  
                                v => recursive_depth = v != null ? int.MaxValue : 1 },                                  
                            { "sddl", "Print full SDDL security descriptors", v => _print_sddl = v != null },
                            { "p|pid=", "Specify a PID of a process to impersonate when checking", v => pid = int.Parse(v.Trim()) },
                            { "w", "Show only write permissions granted", v => _show_write_only = v != null },
                            { "f=", String.Format("Filter on a file right [{0}]", 
                                String.Join(",", Enum.GetNames(typeof(FileAccessRights)))), v => _file_filter |= ParseRight(v, typeof(FileAccessRights)) },  
                            { "d=", String.Format("Filter on a directory right [{0}]", 
                                String.Join(",", Enum.GetNames(typeof(FileDirectoryAccessRights)))), v => _dir_filter |= ParseRight(v, typeof(FileDirectoryAccessRights)) },
                            { "x=", "Specify a base path to exclude from recursive search", v => _walked.Add(ConvertPath(v)) },
                            { "q", "Don't print errors", v => _quiet = v != null },
                            { "nofiles", "Don't show permission of files.", v => no_files = v != null },
                            { "depth", "Specify a recursive depth", v => recursive_depth = int.Parse(v) },
                            { "h|help",  "show this message and exit", v => show_help = v != null },
                        };

                List<string> paths = opts.Parse(args).Select(p => ConvertPath(p)).ToList();

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
                        DumpFile(path, null, recursive_depth, no_files);
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
