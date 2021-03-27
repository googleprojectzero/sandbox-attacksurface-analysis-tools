//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32.Image;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Contains information about a manifest file.
    /// </summary>
    public sealed class ExecutableManifest
    {
        const string MANIFEST_ASMV1_NS = "urn:schemas-microsoft-com:asm.v1";
        const string MANIFEST_ASMV3_NS = "urn:schemas-microsoft-com:asm.v3";
        const string MANIFEST_WS_NS = "http://schemas.microsoft.com/SMI/2005/WindowsSettings";
        const string MANIFEST_WS2_NS = "http://schemas.microsoft.com/SMI/2016/WindowsSettings";

        private static XmlNamespaceManager CreateNSMgr(XmlNameTable nt)
        {
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(nt);

            nsmgr.AddNamespace("asmv1", MANIFEST_ASMV1_NS);
            nsmgr.AddNamespace("asmv3", MANIFEST_ASMV3_NS);
            nsmgr.AddNamespace("ws", MANIFEST_WS_NS);
            nsmgr.AddNamespace("ws2", MANIFEST_WS2_NS);

            return nsmgr;
        }

        private static XmlNode GetNode(XmlDocument doc, string path)
        {
            return doc.SelectSingleNode(path, CreateNSMgr(doc.NameTable));
        }

        private static bool GetUiAccess(XmlDocument doc)
        {
            XmlNode node = GetNode(doc, "/asmv1:assembly/asmv3:trustInfo/asmv3:security/asmv3:requestedPrivileges/asmv3:requestedExecutionLevel/@uiAccess");

            if (node != null)
            {
                if (bool.TryParse(node.Value, out bool ret))
                {
                    return ret;
                }
            }

            return false;
        }

        private static string GetExecutionLevel(XmlDocument doc)
        {
            XmlNode node = GetNode(doc, "/asmv1:assembly/asmv3:trustInfo/asmv3:security/asmv3:requestedPrivileges/asmv3:requestedExecutionLevel/@level");

            if (node != null)
            {
                return node.Value;
            }

            return "asInvoker";
        }

        private static bool GetAutoElevate(XmlDocument doc)
        {
            bool ret = false;
            XmlNode node = GetNode(doc, "/asmv1:assembly/asmv3:application/asmv3:windowsSettings/ws:autoElevate");

            if (node != null)
            {
                if (!bool.TryParse(node.InnerText.Trim(), out ret))
                {
                    ret = false;
                }
            }
            return ret;
        }

        private static bool GetLongPathAware(XmlDocument doc)
        {
            bool ret = false;
            XmlNode node = GetNode(doc, "/asmv1:assembly/asmv3:application/asmv3:windowsSettings/ws2:longPathAware");

            if (node != null)
            {
                if (!bool.TryParse(node.InnerText.Trim(), out ret))
                {
                    ret = false;
                }
            }
            return ret;
        }

        private static XmlDocument LoadDocument(MemoryStream stm)
        {
            XmlDocument doc = new XmlDocument();
            XmlParserContext parse_context =
                new XmlParserContext(null, CreateNSMgr(new NameTable()), null, XmlSpace.Default);
            XmlReader reader = XmlReader.Create(stm, null, parse_context);
            doc.Load(reader);
            return doc;
        }
        
        internal ExecutableManifest(string fullpath, byte[] manifest)
        {
            FullPath = fullpath;

            if (manifest.Length <= 0)
            {
                throw new ArgumentException("Invalid manifest size");
            }

            MemoryStream stm = new MemoryStream(manifest);
            try
            {
                XmlDocument doc = LoadDocument(stm);

                UiAccess = GetUiAccess(doc);
                AutoElevate = GetAutoElevate(doc);
                ExecutionLevel = GetExecutionLevel(doc);
                LongPathAware = GetLongPathAware(doc);

                XmlWriterSettings settings = new XmlWriterSettings
                {
                    Indent = true,
                    OmitXmlDeclaration = true,
                    NewLineOnAttributes = true
                };
                StringWriter string_writer = new StringWriter();
                XmlWriter writer = XmlWriter.Create(string_writer, settings);
                doc.Save(writer);
                ManifestXml = string_writer.ToString();
            }
            catch (XmlException)
            {
                ParseError = true;
                ManifestXml = Encoding.UTF8.GetString(stm.ToArray());
            }
        }

        /// <summary>
        /// True if parsing the XML manifest failed.
        /// </summary>
        public bool ParseError { get; }

        /// <summary>
        /// Full path to the manifest location.
        /// </summary>
        public string FullPath { get; }

        /// <summary>
        /// The name of the manifest.
        /// </summary>
        public string Name => Path.GetFileName(FullPath);

        /// <summary>
        /// True if the manifest indicates UI access.
        /// </summary>
        public bool UiAccess { get; }

        /// <summary>
        /// The execution level from the manifest.
        /// </summary>
        public string ExecutionLevel { get; }

        /// <summary>
        /// True if the manifest indicates auto elevation.
        /// </summary>
        public bool AutoElevate { get; }

        /// <summary>
        /// The manifest XML.
        /// </summary>
        public string ManifestXml { get; }

        /// <summary>
        /// True if the manifest indicates long path awareness.
        /// </summary>
        public bool LongPathAware { get; }

        /// <summary>
        /// Get the manifests from a file.
        /// </summary>
        /// <param name="filename">The file to extract the manifests from.</param>
        /// <returns>The list of manifests.</returns>
        public static IEnumerable<ExecutableManifest> GetManifests(string filename)
        {
            string fullpath = Path.GetFullPath(filename);
            
            using (SafeLoadLibraryHandle library =
                SafeLoadLibraryHandle.LoadLibrary(fullpath, LoadLibraryFlags.LoadLibraryAsImageResource | LoadLibraryFlags.LoadLibraryAsDataFile))
            {
                return library.GetResources(WellKnownImageResourceType.Manifest).Where(m => m.Size > 0)
                    .Select(m => new ExecutableManifest(fullpath, m.ToArray())).ToArray();
            }
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The manifest as a string.</returns>
        public override string ToString()
        {
            return $"{Name} ExecutionLevel: {ExecutionLevel} AutoElevate: {AutoElevate} UiAccess: {UiAccess}";
        }
    }
}
