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

using NtCoreLib.Image;
using NtCoreLib.Win32.Loader;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;

namespace NtCoreLib.Win32.SideBySide;

/// <summary>
/// Contains information about a manifest file.
/// </summary>
public sealed class ManifestFile
{
    const string MANIFEST_ASMV1_NS = "urn:schemas-microsoft-com:asm.v1";
    const string MANIFEST_ASMV3_NS = "urn:schemas-microsoft-com:asm.v3";
    const string MANIFEST_WS_NS = "http://schemas.microsoft.com/SMI/2005/WindowsSettings";
    const string MANIFEST_WS2_NS = "http://schemas.microsoft.com/SMI/2016/WindowsSettings";

    private static XmlNamespaceManager CreateNSMgr(XmlNameTable nt)
    {
        XmlNamespaceManager nsmgr = new(nt);

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
        return GetNode(doc, "/asmv1:assembly/asmv3:trustInfo/asmv3:security/asmv3:requestedPrivileges/asmv3:requestedExecutionLevel/@level")?.Value ?? "asInvoker";
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

    private static string ConvertAssemblyIdentity(XmlNode node)
    {
        if (node.Name == "assemblyIdentity" && node is XmlElement el && el.HasAttribute("name"))
        {
            List<string> parts = new()
            {
                el.GetAttribute("name")
            };
            foreach (XmlAttribute attr in el.Attributes)
            {
                if (attr.Name != "name")
                {
                    parts.Add($"{attr.Name}={attr.Value}");
                }
            }
            return string.Join(", ", parts);
        }
        return string.Empty;
    }

    private static string GetIdentity(XmlDocument doc)
    {
        XmlNode node = GetNode(doc, "/asmv1:assembly/asmv1:assemblyIdentity");
        if (node != null)
        {
            return ConvertAssemblyIdentity(node);
        }
        return string.Empty;
    }

    private static IReadOnlyList<string> GetDependencies(XmlDocument doc)
    {
        List<string> names = new();
        foreach (XmlNode node in doc.SelectNodes("/asmv1:assembly/asmv1:dependency/asmv1:dependentAssembly/asmv1:assemblyIdentity", CreateNSMgr(doc.NameTable)))
        {
            string name = ConvertAssemblyIdentity(node);
            if (!string.IsNullOrEmpty(name))
            {
                names.Add(name);
            }
        }
        return names.AsReadOnly();
    }

    private static XmlDocument LoadDocument(Stream stm)
    {
        XmlDocument doc = new();
        XmlParserContext parse_context =
            new(null, CreateNSMgr(new NameTable()), null, XmlSpace.Default);
        XmlReader reader = XmlReader.Create(stm, null, parse_context);
        doc.Load(reader);
        return doc;
    }

    internal ManifestFile(string fullpath, int resource_id, byte[] manifest, bool ignore_xml_errors)
    {
        FullPath = fullpath;

        if (manifest.Length <= 0)
        {
            throw new ArgumentException("Invalid manifest size");
        }

        MemoryStream stm = new(manifest);
        try
        {
            XmlDocument doc = LoadDocument(stm);

            UiAccess = GetUiAccess(doc);
            AutoElevate = GetAutoElevate(doc);
            ExecutionLevel = GetExecutionLevel(doc);
            LongPathAware = GetLongPathAware(doc);
            Dependencies = GetDependencies(doc);
            Identity = GetIdentity(doc);

            XmlWriterSettings settings = new()
            {
                Indent = true,
                OmitXmlDeclaration = true,
                NewLineOnAttributes = true
            };
            StringWriter string_writer = new();
            doc.Save(XmlWriter.Create(string_writer, settings));
            ManifestXml = string_writer.ToString();

            if (resource_id > 0 && resource_id < 4)
            {
                ResourceType = (ManifestResourceType)resource_id;
            }
        }
        catch (XmlException)
        {
            if (!ignore_xml_errors)
            {
                throw;
            }
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
    /// Get the identity of the manifest assembly.
    /// </summary>
    public string Identity { get; }

    /// <summary>
    /// Get list of dependencies for this manifest.
    /// </summary>
    public IReadOnlyList<string> Dependencies { get; }

    /// <summary>
    /// Get the type of the manifest.
    /// </summary>
    public ManifestResourceType ResourceType { get; }

    /// <summary>
    /// Get the manifests from an executable file.
    /// </summary>
    /// <param name="filename">The file to extract the manifests from.</param>
    /// <returns>The list of manifests.</returns>
    /// <remarks>If the file is a PE file it'll be loaded and the resources parsed out, if it's an XML file then it'll be parsed directly.</remarks>
    public static IEnumerable<ManifestFile> FromExecutableFile(string filename)
    {
        using SafeLoadLibraryHandle library =
                SafeLoadLibraryHandle.LoadLibrary(filename, LoadLibraryFlags.AsImageResource | LoadLibraryFlags.AsDataFile);
        return library.GetResources(WellKnownImageResourceType.Manifest).Where(m => m.Size > 0)
                .Select(m => new ManifestFile(filename, m.Name.Id ?? 0, m.ToArray(), true)).ToArray();
    }

    /// <summary>
    /// Get a manifest from an XML file.
    /// </summary>
    /// <param name="filename">The XML file.</param>
    /// <returns></returns>
    public static ManifestFile FromXmlFile(string filename)
    {
        return new ManifestFile(filename, 0, File.ReadAllBytes(filename), false);
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
