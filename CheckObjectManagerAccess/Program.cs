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

namespace CheckObjectManagerAccess
{
    class Program
    {
        static bool _print_sddl = false;
        static bool _show_write_only = false;
        static uint _dir_rights = 0;
        static HashSet<string> _type_filter = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        static bool _map_to_generic = false;
        static bool _show_errors = false;
       
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckObjectManagerAccess [options] dir1 [dir2..dirN]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static Type GetTypeAccessRights(NtType type)
        {
            return type.AccessRightsType;
        }

        static string AccessMaskToString(NtType type, AccessMask granted_access, bool map_to_generic)
        {
            return NtObjectUtils.GrantedAccessAsString(granted_access, type.GenericMapping, GetTypeAccessRights(type), map_to_generic);
        }

        static void CheckAccess(NtToken token, NtObject obj)
        {
            if (!obj.IsAccessMaskGranted(GenericAccessRights.ReadControl))
            {
                return;
            }

            try
            {
                SecurityDescriptor sd = obj.SecurityDescriptor;
                AccessMask granted_access;
                NtType type = obj.NtType;

                if (_dir_rights != 0)
                {
                    granted_access = NtSecurity.GetAllowedAccess(sd, token, 
                        _dir_rights, type.GenericMapping);
                }
                else
                {
                    granted_access = NtSecurity.GetMaximumAccess(sd, token, type.GenericMapping);
                }

                if (!granted_access.IsEmpty)
                {
                    // As we can get all the rights for the directory get maximum
                    if (_dir_rights != 0)
                    {
                        granted_access = NtSecurity.GetMaximumAccess(sd, token, type.GenericMapping);
                    }

                    if (!_show_write_only || type.HasWritePermission(granted_access))
                    {
                        Console.WriteLine("<{0}> {1} : {2:X08} {3}", type.Name, obj.FullPath, 
                            granted_access, type.AccessMaskToString(granted_access, _map_to_generic));
                        if (_print_sddl)
                        {
                            Console.WriteLine("{0}", sd.ToSddl());
                        }
                    }
                }
            }
            catch (NtException)
            {
            }
        }

        static void DumpDirectory(NtDirectory dir, NtToken token, bool recursive, HashSet<string> walked)
        {
            if (!walked.Add(dir.FullPath.ToLower()))
            {
                return;
            }
            
            CheckAccess(token, dir);

            if (recursive && dir.IsAccessGranted(DirectoryAccessRights.Query))
            {
                foreach (ObjectDirectoryInformation entry in dir.Query())
                {
                    try
                    {                            
                        if (entry.IsDirectory)
                        {
                            using (NtDirectory newdir = NtDirectory.Open(entry.Name, 
                                dir, DirectoryAccessRights.MaximumAllowed))
                            {
                                DumpDirectory(newdir, token, recursive, walked);
                            }
                        }
                        else if (entry.NtType.CanOpen)
                        {
                            if (_type_filter.Count == 0 || _type_filter.Contains(entry.NtTypeName))
                            {
                                using (NtObject obj = entry.Open(GenericAccessRights.ReadControl))
                                {
                                    CheckAccess(token, obj);
                                }
                            }
                        }
                    }
                    catch (NtException ex)
                    {
                        if (_show_errors && ex.Status != NtStatus.STATUS_ACCESS_DENIED)
                        {
                            Console.Error.WriteLine("Error opening {0} {1}", entry.FullPath, ex.Message);
                        }
                    }
                }
            }
        }

        static uint ParseRight(string name, Type enumtype)
        {
            return (uint)Enum.Parse(enumtype, name, true);
        }

        static NtDirectory OpenDirectory(string name)
        {
            if (name.StartsWith(@"\"))
            {
                return NtDirectory.Open(name);
            }
            else
            {
                return NtDirectory.OpenPrivateNamespace(BoundaryDescriptor.CreateFromString(name));
            }
        }
        static void PrintDeprecationWarning()
        {
            ConsoleColor color = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Error.WriteLine("This utility is deprecated. Please use the PowerShell Get-AccessibleObject cmdlet instead");
            Console.ForegroundColor = color;
        }

        static void Main(string[] args)
        {
            bool show_help = false;
            bool recursive = false;
            HashSet<string> exclude_dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            int pid = Process.GetCurrentProcess().Id;
            try
            {
                PrintDeprecationWarning();

                OptionSet opts = new OptionSet() {
                            { "r", "Recursive tree directory listing",  
                                v => recursive = v != null },                                  
                            { "sddl", "Print full SDDL security descriptors", v => _print_sddl = v != null },
                            { "p|pid=", "Specify a PID of a process to impersonate when checking", v => pid = int.Parse(v.Trim()) },
                            { "w", "Show only write permissions granted", v => _show_write_only = v != null },
                            { "k=", String.Format("Filter on a specific directory right [{0}]", 
                                String.Join(",", Enum.GetNames(typeof(DirectoryAccessRights)))), v => _dir_rights |= ParseRight(v, typeof(DirectoryAccessRights)) },  
                            { "x=", "Specify a base path to exclude from recursive search", v => exclude_dirs.Add(v) },
                            { "t=", "Specify a type of object to include", v => _type_filter.Add(v) },
                            { "g", "Map access mask to generic rights.", v => _map_to_generic = v != null },
                            { "e", "Display errors when opening objects, ignores access denied.", v => _show_errors = v != null },
                            { "h|help",  "show this message and exit", v => show_help = v != null },
                        };

                List<string> paths = opts.Parse(args);

                if (show_help || (paths.Count == 0))
                {
                    ShowHelp(opts);
                }
                else
                {
                    using (NtToken token = NtToken.OpenProcessToken(pid))
                    {
                        foreach (string path in paths)
                        {
                            try
                            {
                                using (NtDirectory dir = OpenDirectory(path))
                                {
                                    HashSet<string> walked = new HashSet<string>(exclude_dirs, StringComparer.OrdinalIgnoreCase);
                                    Console.WriteLine("Dumping Directory: {0}", path);
                                    DumpDirectory(dir, token, recursive, walked);
                                }
                            }
                            catch (NtException ex)
                            {
                                Console.WriteLine("Couldn't open {0} - {1}", path, ex.Message);
                            }
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
