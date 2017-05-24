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
using System.Linq;
using System.Reflection;

namespace DumpTypeInfo
{
    class Program
    {
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: DumpTypeInfo [options] [type1 ... typeN]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static void DumpGenericTypeInfo(IEnumerable<NtType> types)
        {
            Console.WriteLine("{0,25}   READ     WRITE   EXECUTE   ALL     VALID ", "Name");
            Console.WriteLine("{0}", new String('-', 70));

            foreach (NtType type in types)
            {
                Console.WriteLine("{0,25} {1:X08} {2:X08} {3:X08} {4:X08} {5:X08}", type.Name, type.GenericMapping.GenericRead,
                    type.GenericMapping.GenericWrite, type.GenericMapping.GenericExecute, type.GenericMapping.GenericAll, type.ValidAccess);
            }
        }

        static void DumpVerboseTypeInfo(IEnumerable<NtType> types)
        {
            PropertyInfo[] props = typeof(NtType).GetProperties();

            foreach (NtType type in types)
            {
                string name = String.Format("{0}", type.Name);
                Console.WriteLine(name);
                Console.WriteLine(new String('-', name.Length));
                foreach (PropertyInfo pi in props)
                {
                    if (pi.Name != "Name")
                    {
                        if (pi.PropertyType == typeof(uint))
                        {
                            Console.WriteLine("{0,-32}: 0x{1:X08}/{1}", pi.Name, pi.GetValue(type));
                        }
                        else
                        {
                            Console.WriteLine("{0,-32}: {1}", pi.Name, pi.GetValue(type));
                        }
                        
                    }
                }
                Console.WriteLine();
            }
        }

        static void Main(string[] args)
        {
            bool require_security = false;
            bool verbose = false;
            bool show_help = false;
            bool name_only = false;
            bool sorted = false;

            OptionSet opts = new OptionSet() {                                                                                                                                            
                        { "v", "Display verbose information about type", v => verbose = v != null },
                        { "s", "Show types which do not require security", v => require_security = v != null },
                        { "n", "Display name only", v => name_only = v != null },
                        { "t", "Display sorted by type name", v => sorted = v != null },
                        { "h|help",  "show this message and exit", v => show_help = v != null },
                    };

            HashSet<string> typeFilter = new HashSet<string>(opts.Parse(args), StringComparer.OrdinalIgnoreCase);

            if (show_help)
            {
                ShowHelp(opts);
            }
            else
            {
                try
                {
                    IEnumerable<NtType> types = NtType.GetTypes();

                    if (typeFilter.Count > 0)
                    {
                        types = types.Where(t => typeFilter.Contains(t.Name));
                    }

                    if (require_security)
                    {
                        types = types.Where(t => !t.SecurityRequired);
                    }

                    if (sorted)
                    {
                        types = types.OrderBy(t => t.Name);
                    }

                    if (name_only)
                    {
                        foreach (NtType type in types)
                        {
                            Console.WriteLine("{0}", type.Name);
                        }
                    }
                    else
                    {
                        if (!verbose)
                        {
                            DumpGenericTypeInfo(types);
                        }
                        else
                        {
                            DumpVerboseTypeInfo(types);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }
    }
}
