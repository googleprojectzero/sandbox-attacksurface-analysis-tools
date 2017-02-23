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
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;

namespace DumpExeManifest
{
    class Program
    {
        private static bool _uiaccess_only;
        private static bool _autoelevate_only;
        private static bool _dump_manifest;        

        const string MANIFEST_ASMV1_NS = "urn:schemas-microsoft-com:asm.v1";
        const string MANIFEST_ASMV3_NS = "urn:schemas-microsoft-com:asm.v3";
        const string MANIFEST_WS_NS = "http://schemas.microsoft.com/SMI/2005/WindowsSettings";

        [System.Flags]
        enum LoadLibraryFlags : uint
        {
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
        }

        private delegate bool EnumResTypeProc(IntPtr hModule, IntPtr lpszType, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, CallingConvention=CallingConvention.StdCall)]
        static extern IntPtr LoadLibraryEx(string name, IntPtr reserved, LoadLibraryFlags flags);

        [DllImport("kernel32.dll", SetLastError=true, CallingConvention=CallingConvention.StdCall, CharSet=CharSet.Unicode)]
        static extern bool EnumResourceTypes(IntPtr hModule, EnumResTypeProc lpEnumFunc, IntPtr lParam);

        delegate bool EnumResNameProcDelegate(IntPtr hModule, IntPtr lpszType, IntPtr lpszName, IntPtr lParam);

        enum ResType
        {
            CURSOR = 1,
            BITMAP = 2,
            ICON = 3,
            MENU = 4,
            DIALOG = 5,
            STRING = 6,
            FONTDIR = 7,
            FONT = 8,
            ACCELERATOR = 9,
            RCDATA = 10,
            MESSAGETABLE = 11,
            GROUP_CURSOR = 12,
            GROUP_ICON = 14,
            VERSION = 16,
            DLGINCLUDE = 17,
            PLUGPLAY = 19,
            VXD = 20,
            ANICURSOR = 21,
            ANIICON = 22,
            HTML = 23,
            MANIFEST = 24
        }       

        [DllImport("kernel32.dll", SetLastError=true, CallingConvention=CallingConvention.StdCall, CharSet=CharSet.Unicode)]
        static extern bool EnumResourceNames(IntPtr hModule, IntPtr lpszType, EnumResNameProcDelegate lpEnumFunc, IntPtr lParam);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        static extern IntPtr LockResource(IntPtr hResData);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        static extern int SizeofResource(IntPtr hModule, IntPtr hResInfo);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        static extern IntPtr FindResource(IntPtr hModule, IntPtr lpName, IntPtr lpType);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        static extern void FreeLibrary(IntPtr p);        

        static string FormatTypeName(IntPtr p)
        {
            if (p.ToInt64() < 0x10000)
            {
                return p.ToString();
            }
            else
            {
                return Marshal.PtrToStringUni(p);
            }
        }

        static XmlNamespaceManager CreateNSMgr(XmlNameTable nt)
        {
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(nt);

            nsmgr.AddNamespace("asmv1", MANIFEST_ASMV1_NS);
            nsmgr.AddNamespace("asmv3", MANIFEST_ASMV3_NS);
            nsmgr.AddNamespace("ws", MANIFEST_WS_NS);

            return nsmgr;
        }

        static XmlNode GetNode(XmlDocument doc, string path)
        {
            return doc.SelectSingleNode(path, CreateNSMgr(doc.NameTable));
        }

        static bool GetUiAccess(XmlDocument doc)
        {                        
            XmlNode node = GetNode(doc, "/asmv1:assembly/asmv3:trustInfo/asmv3:security/asmv3:requestedPrivileges/asmv3:requestedExecutionLevel/@uiAccess");

            if (node != null)
            {
                bool ret;

                if (bool.TryParse(node.Value, out ret))
                {
                    return ret;
                }
            }            

            return false;
        }

        static string GetExecutionLevel(XmlDocument doc)
        {
            XmlNode node = GetNode(doc, "/asmv1:assembly/asmv3:trustInfo/asmv3:security/asmv3:requestedPrivileges/asmv3:requestedExecutionLevel/@level");

            if (node != null)
            {
                return node.Value;
            }

            return String.Empty;
        }

        static bool GetAutoElevate(XmlDocument doc)
        {
            bool ret = false;
            XmlNode node = GetNode(doc, "/asmv1:assembly/asmv3:application/asmv3:windowsSettings/ws:autoElevate");

            if(node != null)
            {
                if(!bool.TryParse(node.InnerText.Trim(), out ret))
                {
                    ret = false;
                }
            }
            return ret;
        }

        static XmlDocument LoadDocument(MemoryStream stm)
        {
            XmlDocument doc = new XmlDocument();
            XmlParserContext parse_context = 
                new XmlParserContext(null, CreateNSMgr(new NameTable()), null, XmlSpace.Default);
            XmlReader reader = XmlReader.Create(stm, null, parse_context);
            doc.Load(reader);
            return doc;
        }

        static void DumpManifest(string fileName, IntPtr hModule, IntPtr hName)
        {
            IntPtr hResHandle = FindResource(hModule, hName, new IntPtr((int)ResType.MANIFEST));

            if (hResHandle != IntPtr.Zero)
            {
                IntPtr hResource = LoadResource(hModule, hResHandle);

                IntPtr buf = LockResource(hResource);
                int size = SizeofResource(hModule, hResHandle);

                if (size > 0)
                {
                    byte[] manifest = new byte[size];

                    Marshal.Copy(buf, manifest, 0, size);
                    MemoryStream stm = new MemoryStream(manifest);
                    try
                    {
                        XmlDocument doc = LoadDocument(stm);

                        bool uiAccess = GetUiAccess(doc);                        

                        if (_uiaccess_only && !uiAccess)
                        {
                            return;
                        }

                        bool autoElevate = GetAutoElevate(doc);
                        if (_autoelevate_only && !autoElevate)
                        {
                            return;
                        }

                        Console.WriteLine("File: {0}", fileName);
                        Console.WriteLine("UIAccess: {0}", uiAccess);
                        Console.WriteLine("Execution Level: {0}", GetExecutionLevel(doc));
                        Console.WriteLine("Auto Elevate: {0}", autoElevate);

                        if (_dump_manifest)
                        {
                            XmlWriterSettings settings = new XmlWriterSettings();
                            settings.Indent = true;
                            settings.OmitXmlDeclaration = true;
                            settings.NewLineOnAttributes = true;
                            XmlWriter writer = XmlWriter.Create(Console.Out, settings);
                            doc.Save(writer);
                            Console.Out.WriteLine();
                        }
                        Console.Out.WriteLine();
                    }
                    catch (XmlException ex)
                    {
                        Console.WriteLine("Error {0} - {1}", fileName, ex.Message);
                        if (_dump_manifest)
                        {
                            Console.WriteLine(Encoding.UTF8.GetString(stm.ToArray()));
                        }
                    }
                }
            }
        }

        static IEnumerable<string> GetPaths(string search_path)
        {
            if (File.Exists(search_path))
            {
                return new string[] { search_path };
            }
            else
            {
                try
                {
                    string curr_dir = Path.GetDirectoryName(search_path);

                    if (curr_dir == null)
                    {
                        curr_dir = Environment.CurrentDirectory;
                    }

                    return Directory.GetFiles(curr_dir, Path.GetFileName(search_path), 
                        SearchOption.TopDirectoryOnly);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error accessing {0} - {1}", search_path, ex.Message);
                }                

                return new string[0];
            }
        }

        static void Main(string[] args)
        {
            bool show_help = false;

            OptionSet opts = new OptionSet() {                      
                        { "u|uiaccess", "Print only modules with UI access set", v => _uiaccess_only = v != null },
                        { "a|autoelevate", "Print only modules with Auto Elevate set", v => _autoelevate_only = v != null },
                        { "d|dump", "Dump the manifest for each file", v => _dump_manifest = v != null },
                        { "h|help",  "show this message and exit", v => show_help = v != null },
                    };

            List<string> paths = opts.Parse(args);

            if (show_help || paths.Count < 1)
            {
                Console.WriteLine("DumpExeManifest [options] file.exe|*.exe");
                opts.WriteOptionDescriptions(Console.Out);
            }
            else
            {
                foreach (string path in paths.SelectMany(p => GetPaths(p)))
                {
                    try
                    {
                        List<IntPtr> manifests = new List<IntPtr>();

                        IntPtr exeFile = LoadLibraryEx(path, IntPtr.Zero, LoadLibraryFlags.LOAD_LIBRARY_AS_IMAGE_RESOURCE);
                        if (exeFile == IntPtr.Zero)
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }

                        EnumResourceNames(exeFile, new IntPtr((int)ResType.MANIFEST), (a, b, c, d) =>
                        {
                            manifests.Add(c);                            
                            return true;
                        }, IntPtr.Zero);

                        foreach (IntPtr manifest in manifests)
                        {
                            DumpManifest(path, exeFile, manifest);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error: {0} - {1}", path, ex.Message);
                    }
                }
            }
        }
    }
}
