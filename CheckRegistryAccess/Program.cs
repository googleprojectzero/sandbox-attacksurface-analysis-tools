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

namespace CheckRegistryAccess
{
    class Program
    {
        static bool _recursive = false;
        static bool _print_sddl = false;
        static bool _show_write_only = false;
        static HashSet<string> _walked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);        
        static NtType _type;
        static NtToken _token;
        static uint _key_rights = 0;

        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckRegistryAccess [options] key1 [key2..keyN]");            
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
            Console.WriteLine(@"Key names can be in win32 form (hkey_local_machine\blah) or native (\Registry\Machine\blah");
        }

        static string AccessMaskToString(uint granted_access)
        {
            if (_type.HasFullPermission(granted_access))
            {
                return "Full Permission";
            }

            return ((KeyAccessRights)granted_access).ToString();
        }

        static void CheckAccess(NtKey key)
        {
            if (!key.IsAccessGranted(KeyAccessRights.ReadControl))
            {
                return;
            }

            SecurityDescriptor sd = key.SecurityDescriptor;
            uint granted_access = 0;

            if (_key_rights != 0)
            {
                granted_access = NtSecurity.GetAllowedAccess(_token, _type, _key_rights, sd.ToByteArray());
            }
            else
            {
                granted_access = NtSecurity.GetMaximumAccess(_token, _type, sd.ToByteArray());
            }

            if (granted_access != 0)
            {
                // As we can get all the rights for the key get maximum
                if (_key_rights != 0)
                {
                    granted_access = NtSecurity.GetMaximumAccess(_token, _type, sd.ToByteArray());
                }

                if (!_show_write_only || _type.HasWritePermission(granted_access))
                {
                    Console.WriteLine("{0} : {1:X08} {2}", key.FullPath, granted_access, AccessMaskToString(granted_access));
                    if (_print_sddl)
                    {
                        Console.WriteLine("{0}", sd.ToSddl());
                    }
                }
            }
        }

        static void DumpKey(NtKey key)
        {
            string key_name = key.FullPath;
            if (_walked.Contains(key_name))
            {
                return;
            }

            _walked.Add(key_name);

            try
            {
                CheckAccess(key);

                if (_recursive && key.IsAccessGranted(KeyAccessRights.EnumerateSubKeys))
                {
                    using (var keys = key.QueryAccessibleKeys(KeyAccessRights.MaximumAllowed))
                    {
                        foreach (NtKey subkey in keys)
                        {
                            DumpKey(subkey);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error dumping key {0} {1}", key.FullPath, ex.Message);
            }
        }

        static string MapKeyName(string fullpath)
        {
            string mapped = "";
            string[] nameparts = fullpath.Split(new char[] { '\\' }, 2);

            if (nameparts.Length == 0)
            {
                throw new ArgumentException("Invalid key name");
            }

            switch (nameparts[0].ToLower())
            {
                case "hkey_local_machine":
                    mapped = @"\Registry\MACHINE";
                    break;
                case "hkey_current_user":
                    mapped = @"\Registry\User\" + NtToken.CurrentUser.Sid.ToString();
                    break;
                case "hkey_users":
                    mapped = @"\Registry\User";
                    break;
                case "hkey_classes_root":
                    mapped = @"\Registry\MACHINE\Software\Classes";
                    break;
                default:
                    throw new ArgumentException(String.Format("Invalid root keyname {0}", nameparts[0]));
            }

            if(nameparts.Length > 1)
            {
                return mapped + "\\" + nameparts[1];
            }
            else
            {
                return mapped + "\\";
            }
        }

        static NtKey OpenKey(string name)
        {
            if (!name.StartsWith(@"\"))
            {
                name = MapKeyName(name);
            }

            return NtKey.Open(name, null, KeyAccessRights.MaximumAllowed);
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
                        { "k=", String.Format("Filter on a specific right [{0}]", 
                            String.Join(",", Enum.GetNames(typeof(KeyAccessRights)))), v => _key_rights |= ParseRight(v, typeof(KeyAccessRights)) },  
                        { "x=", "Specify a base path to exclude from recursive search", v => _walked.Add(v.ToLower()) },
                        { "h|help",  "show this message and exit", v => show_help = v != null },
                    };

                List<string> paths = opts.Parse(args);

                if (show_help || (paths.Count == 0))
                {
                    ShowHelp(opts);
                }
                else
                {
                    _type = NtType.GetTypeByName("key");
                    _token = NtToken.OpenProcessToken(pid);

                    foreach (string path in paths)
                    {
                        try
                        {
                            using (NtKey key = OpenKey(path))
                            {
                                DumpKey(key);
                            }
                        }
                        catch (NtException ex)
                        {
                            Console.WriteLine("Error opening key: {0} - {1}", path, ex.Message);
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
