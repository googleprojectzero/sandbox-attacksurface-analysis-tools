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
/// Base class for a reparse buffer.
/// </summary>
public abstract class ReparseBuffer
{
    /// <summary>
    /// The reparse tag in the buffer.
    /// </summary>
    public ReparseTag Tag { get; set; }

    /// <summary>
    /// Function to initialize this class by parsing the reparse buffer data (not including header).
    /// </summary>
    /// <param name="data_length">The length of the data to read.</param>
    /// <param name="reader">The stream to read from.</param>
    protected abstract void ParseBuffer(int data_length, BinaryReader reader);
    /// <summary>
    /// Get reparse buffer data as a byte array (not including header).
    /// </summary>
    /// <returns>The reparse buffer data.</returns>
    protected abstract byte[] GetBuffer();

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="tag">The reparse tag to assign.</param>
    protected ReparseBuffer(ReparseTag tag)
    {
        Tag = tag;
    }

    /// <summary>
    /// Get a reparse buffer from a byte array.
    /// </summary>
    /// <param name="ba">The byte array to parse</param>
    /// <returns>The reparse buffer.</returns>
    public static ReparseBuffer FromByteArray(byte[] ba)
    {
        BinaryReader reader = new(new MemoryStream(ba), Encoding.Unicode);
        ReparseTag tag = (ReparseTag)reader.ReadUInt32();
        int data_length = reader.ReadUInt16();
        // Reserved
        reader.ReadUInt16();
        long remaining_length = reader.RemainingLength();
        long expected_length = data_length;
        if (!NtFileUtils.IsReparseTagMicrosoft(tag))
        {
            expected_length += 16;
        }

        if (remaining_length != expected_length)
        {
            // Corrupted buffer. Return an opaque buffer with all the data until the end.
            return new OpaqueReparseBuffer(tag, reader.ReadToEnd());
        }


        ReparseBuffer buffer;
        switch (tag)
        {
            case ReparseTag.MOUNT_POINT:
                buffer = new MountPointReparseBuffer();
                break;
            case ReparseTag.SYMLINK:
                buffer = new SymlinkReparseBuffer(false);
                break;
            case ReparseTag.GLOBAL_REPARSE:
                buffer = new SymlinkReparseBuffer(true);
                break;
            case ReparseTag.APPEXECLINK:
                buffer = new ExecutionAliasReparseBuffer();
                break;
            default:
                if (NtFileUtils.IsReparseTagMicrosoft(tag))
                {
                    buffer = new OpaqueReparseBuffer(tag);
                }
                else
                {
                    buffer = new GenericReparseBuffer(tag);
                }
                break;
        }

        buffer.ParseBuffer(data_length, reader);
        return buffer;
    }

    /// <summary>
    /// Convert reparse buffer to a byte array in REPARSE_DATA_BUFFER format.
    /// </summary>
    /// <returns>The reparse buffer as a byte array.</returns>
    public byte[] ToByteArray()
    {
        byte[] buffer = GetBuffer();
        MemoryStream stm = new();
        BinaryWriter writer = new(stm);
        writer.Write((uint)Tag);
        if (buffer.Length > ushort.MaxValue)
        {
            throw new ArgumentException("Reparse buffer too large");
        }
        writer.Write((ushort)buffer.Length);
        writer.Write((ushort)0);
        if (this is GenericReparseBuffer generic)
        {
            writer.Write(generic.Guid.ToByteArray());
        }
        writer.Write(buffer);
        return stm.ToArray();
    }

    /// <summary>
    /// Convert reparse buffer to a byte array in the REPARSE_DATA_BUFFER_EX format.
    /// </summary>
    /// <param name="flags">Flags for the buffer.</param>
    /// <param name="existing_guid">Existing GUID to match against.</param>
    /// <param name="existing_tag">Existing tag to matcha against.</param>
    /// <returns>The reparse buffer as a byte array.</returns>
    public byte[] ToByteArray(ReparseBufferExFlags flags, ReparseTag existing_tag, Guid existing_guid)
    {
        MemoryStream stm = new();
        BinaryWriter writer = new(stm);
        // Flags.
        writer.Write((int)flags);
        // Existing tag.
        writer.Write((uint)existing_tag);
        // Existing GUID for non-Microsoft tags.
        writer.Write(existing_guid.ToByteArray());
        // Reserved (64 bit)
        writer.Write(0L);
        // The original reparse buffer.
        writer.Write(ToByteArray());
        return stm.ToArray();
    }

    /// <summary>
    /// Get if a reparse tag is a Microsoft defined one.
    /// </summary>
    public bool IsMicrosoft => NtFileUtils.IsReparseTagMicrosoft(Tag);

    /// <summary>
    /// Get if a reparse tag is a name surrogate.
    /// </summary>
    /// <returns>True if it's a surrogate reparse tag.</returns>
    public bool IsNameSurrogate => NtFileUtils.IsReparseTagNameSurrogate(Tag);

    /// <summary>
    /// Get if a reparse tag is a directory.
    /// </summary>
    public bool IsTagDirectory => NtFileUtils.IsReparseTagDirectory(Tag);
}
