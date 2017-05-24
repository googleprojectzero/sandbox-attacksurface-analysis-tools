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

using SandboxAnalysisUtils;
using NDesk.Options;
using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace CheckObjectManagerAccess
{
    class Program
    {
        static bool _recursive = false;
        static bool _print_sddl = false;
        static bool _show_write_only = false;
        static HashSet<string> _walked = new HashSet<string>();        
        static NtToken _token;
        static uint _dir_rights = 0;
        static HashSet<string> _type_filter = new HashSet<string>();
       
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckObjectManagerAccess [options] dir1 [dir2..dirN]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static Type GetTypeAccessRights(NtType type)
        {
            switch (type.Name.ToLower())
            {
                case "directory":
                    return typeof(DirectoryAccessRights);
                case "event":
                    return typeof(EventAccessRights);
                case "section":
                    return typeof(SectionAccessRights);
                case "mutant":
                    return typeof(MutantAccessRights);
                case "semaphore":
                    return typeof(SemaphoreAccessRights);
                case "job":
                    return typeof(JobAccessRights);
                case "symboliclink":
                    return typeof(SymbolicLinkAccessRights);
                default:
                    throw new ArgumentException("Can't get type for access rights");
            }
        }

        static string AccessMaskToString(NtType type, uint granted_access)
        {
            if (type.HasFullPermission(granted_access))
            {
                return "Full Permission";
            }

            return NtObject.AccessRightsToString(GetTypeAccessRights(type), type.MapGenericRights(granted_access));
        }

        static void CheckAccess(string path, byte[] sd, NtType type)
        {
            try
            {
                if (_type_filter.Count > 0)
                {
                    if (!_type_filter.Contains(type.Name.ToLower()))
                    {
                        return;
                    }
                }

                if (sd.Length > 0)
                {
                    uint granted_access = 0;

                    if (_dir_rights != 0)
                    {
                        granted_access = NtSecurity.GetAllowedAccess(_token, type, (uint)_dir_rights, sd);
                    }
                    else
                    {
                        granted_access = NtSecurity.GetMaximumAccess(_token, type, sd);
                    }

                    if (granted_access != 0)
                    {
                        // As we can get all the rights for the directory get maximum
                        if (_dir_rights != 0)
                        {
                            granted_access = NtSecurity.GetMaximumAccess(_token, type, sd);
                        }

                        if (!_show_write_only || type.HasWritePermission(granted_access))
                        {
                            Console.WriteLine("<{0}> {1} : {2:X08} {3}", type.Name, path, granted_access, AccessMaskToString(type, granted_access));
                            if (_print_sddl)
                            {
                                Console.WriteLine("{0}", NtSecurity.SecurityDescriptorToSddl(sd, SecurityInformation.AllBasic));
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
            }
        }

        static void DumpDirectory(ObjectDirectory dir)
        {
            if (_walked.Contains(dir.FullPath.ToLower()))
            {
                return;
            }

            _walked.Add(dir.FullPath.ToLower());

            try
            {
                CheckAccess(dir.FullPath, dir.SecurityDescriptor, NtType.GetTypeByName("Directory"));

                if (_recursive)
                {
                    foreach (ObjectDirectoryEntry entry in dir.Entries)
                    {
                        try
                        {                            
                            if (entry.IsDirectory)
                            {
                                using (ObjectDirectory newdir = ObjectNamespace.OpenDirectory(dir, entry.ObjectName))
                                {
                                    DumpDirectory(newdir);
                                }
                            }
                            else
                            {                                
                                CheckAccess(entry.FullPath, entry.SecurityDescriptor, NtType.GetTypeByName(entry.TypeName));
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine("Error opening {0} {1}", entry.FullPath, ex.Message);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error dumping directory {0} {1}", dir.FullPath, ex.Message);
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
                            { "k=", String.Format("Filter on a specific directory right [{0}]", 
                                String.Join(",", Enum.GetNames(typeof(DirectoryAccessRights)))), v => _dir_rights |= ParseRight(v, typeof(DirectoryAccessRights)) },  
                            { "x=", "Specify a base path to exclude from recursive search", v => _walked.Add(v.ToLower()) },
                            { "t=", "Specify a type of object to include", v => _type_filter.Add(v.ToLower()) },
                            { "h|help",  "show this message and exit", v => show_help = v != null },
                        };

                List<string> paths = opts.Parse(args);

                if (show_help || (paths.Count == 0))
                {
                    ShowHelp(opts);
                }
                else
                {
                    _token = NtToken.OpenProcessToken(pid);

                    foreach (string path in paths)
                    {
                        using (ObjectDirectory dir = ObjectNamespace.OpenDirectory(null, path))
                        {
                            DumpDirectory(dir);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }
}
