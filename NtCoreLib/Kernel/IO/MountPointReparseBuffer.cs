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
/// Reparse buffer for an NTFS mount point.
/// </summary>
public sealed class MountPointReparseBuffer : ReparseBuffer
{
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="substitution_name">Substitution name to reparse to when accessing mount point.</param>
    /// <param name="print_name">Printable name for the mount point.</param>
    public MountPointReparseBuffer(string substitution_name, string print_name) : base(ReparseTag.MOUNT_POINT)
    {
        if (string.IsNullOrEmpty(substitution_name))
        {
            throw new ArgumentException("substitution_name");
        }
        SubstitutionName = substitution_name;
        PrintName = print_name ?? string.Empty;
    }

    internal MountPointReparseBuffer() : base(ReparseTag.MOUNT_POINT)
    {
    }

    /// <summary>
    /// Substitution name to reparse to when accessing mount point.
    /// </summary>
    public string SubstitutionName { get; set; }
    /// <summary>
    /// Printable name for the mount point.
    /// </summary>
    public string PrintName { get; set; }

    /// <summary>
    /// Function to initialize this class by parsing the reparse buffer data (not including header).
    /// </summary>
    /// <param name="data_length">The length of the data to read.</param>
    /// <param name="reader">The stream to read from.</param>
    protected override void ParseBuffer(int data_length, BinaryReader reader)
    {
        int subname_ofs = reader.ReadUInt16();
        int subname_len = reader.ReadUInt16();
        int pname_ofs = reader.ReadUInt16();
        int pname_len = reader.ReadUInt16();

        byte[] path_buffer = reader.ReadAllBytes(data_length - 8);
        SubstitutionName = Encoding.Unicode.GetString(path_buffer, subname_ofs, subname_len);
        PrintName = Encoding.Unicode.GetString(path_buffer, pname_ofs, pname_len);
    }

    /// <summary>
    /// Get reparse buffer data as a byte array (not including header).
    /// </summary>
    /// <returns>The reparse buffer data.</returns>
    protected override byte[] GetBuffer()
    {
        MemoryStream stm = new();
        BinaryWriter writer = new(stm);
        byte[] subname = Encoding.Unicode.GetBytes(SubstitutionName);
        byte[] pname = Encoding.Unicode.GetBytes(PrintName);
        // SubstituteNameOffset
        writer.Write((ushort)0);
        // SubstituteNameLength
        writer.Write((ushort)subname.Length);
        // PrintNameOffset
        writer.Write((ushort)(subname.Length + 2));
        // PrintNameLength
        writer.Write((ushort)pname.Length);
        writer.Write(subname);
        writer.Write(new byte[2]);
        writer.Write(pname);
        writer.Write(new byte[2]);
        return stm.ToArray();
    }
}
