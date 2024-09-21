//  Copyright 2019 Google Inc. All Rights Reserved.
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

using System;
using System.IO;
using System.Text;

namespace NtCoreLib.Kernel.IO;

/// <summary>
/// Reparse buffer for an execution alias.
/// </summary>
public class ExecutionAliasReparseBuffer : ReparseBuffer
{
    /// <summary>
    /// The execution alias version.
    /// </summary>
    public int Version { get; set; }
    /// <summary>
    /// The name of the application package.
    /// </summary>
    public string PackageName { get; set; }
    /// <summary>
    /// The entry point in the package.
    /// </summary>
    public string EntryPoint { get; set; }
    /// <summary>
    /// The target executable.
    /// </summary>
    public string Target { get; set; }
    /// <summary>
    /// Application type for the alias.
    /// </summary>
    public ExecutionAliasAppType AppType { get; set; }
    /// <summary>
    /// Flags, obsolete.
    /// </summary>
    [Obsolete("Use AppType instead")]
    public int Flags
    {
        get => ((int)AppType).ToString()[0];
        set => throw new NotImplementedException();
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="version">The execution alias version.</param>
    /// <param name="package_name">The name of the application package.</param>
    /// <param name="entry_point">The entry point in the package.</param>
    /// <param name="target">The target executable.</param>
    /// <param name="apptype">Apptype for the alias.</param>
    public ExecutionAliasReparseBuffer(int version, string package_name, string entry_point, string target, ExecutionAliasAppType apptype)
        : this()
    {
        Version = version;
        PackageName = package_name;
        EntryPoint = entry_point;
        Target = target;
        AppType = apptype;
    }

    internal ExecutionAliasReparseBuffer() : base(ReparseTag.APPEXECLINK)
    {
    }

    /// <summary>
    /// Get reparse buffer data as a byte array (not including header).
    /// </summary>
    /// <returns>The reparse buffer data.</returns>
    protected override byte[] GetBuffer()
    {
        MemoryStream stm = new();
        BinaryWriter writer = new(stm, Encoding.Unicode);
        writer.Write(Version);
        writer.WriteNulTerminated(PackageName);
        writer.WriteNulTerminated(EntryPoint);
        writer.WriteNulTerminated(Target);
        writer.WriteNulTerminated(((int)AppType).ToString());
        return stm.ToArray();
    }

    /// <summary>
    /// Function to initialize this class by parsing the reparse buffer data (not including header).
    /// </summary>
    /// <param name="data_length">The length of the data to read.</param>
    /// <param name="reader">The stream to read from.</param>
    protected override void ParseBuffer(int data_length, BinaryReader reader)
    {
        Version = reader.ReadInt32();
        PackageName = reader.ReadNulTerminated();
        EntryPoint = reader.ReadNulTerminated();
        Target = reader.ReadNulTerminated();
        AppType = (ExecutionAliasAppType)int.Parse(reader.ReadNulTerminated());
    }
}
