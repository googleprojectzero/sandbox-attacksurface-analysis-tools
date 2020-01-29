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

namespace NtApiDotNet
{
#pragma warning disable 1591
    /// <summary>
    /// Reparse Tag value.
    /// </summary>
    public enum ReparseTag : uint
    {
        MOUNT_POINT = 0xA0000003,
        HSM = 0xC0000004,
        DRIVE_EXTENDER = 0x80000005,
        HSM2 = 0x80000006,
        SIS = 0x80000007,
        WIM = 0x80000008,
        CSV = 0x80000009,
        DFS = 0x8000000A,
        FILTER_MANAGER = 0x8000000B,
        SYMLINK = 0xA000000C,
        IIS_CACHE = 0xA0000010,
        DFSR = 0x80000012,
        DEDUP = 0x80000013,
        APPXSTRM = 0xC0000014,
        NFS = 0x80000014,
        FILE_PLACEHOLDER = 0x80000015,
        DFM = 0x80000016,
        WOF = 0x80000017,
        WCI = 0x80000018,
        WCI_1 = 0x90001018,
        GLOBAL_REPARSE = 0xA0000019,
        CLOUD = 0x9000001A,
        CLOUD_1 = 0x9000101A,
        CLOUD_2 = 0x9000201A,
        CLOUD_3 = 0x9000301A,
        CLOUD_4 = 0x9000401A,
        CLOUD_5 = 0x9000501A,
        CLOUD_6 = 0x9000601A,
        CLOUD_7 = 0x9000701A,
        CLOUD_8 = 0x9000801A,
        CLOUD_9 = 0x9000901A,
        CLOUD_A = 0x9000A01A,
        CLOUD_B = 0x9000B01A,
        CLOUD_C = 0x9000C01A,
        CLOUD_D = 0x9000D01A,
        CLOUD_E = 0x9000E01A,
        CLOUD_F = 0x9000F01A,
        CLOUD_MASK = 0x0000F000,
        APPEXECLINK = 0x8000001B,
        PROJFS = 0x9000001C,
        LX_SYMLINK = 0xA000001D,
        STORAGE_SYNC = 0x8000001E,
        WCI_TOMBSTONE = 0xA000001F,
        UNHANDLED = 0x80000020,
        ONEDRIVE = 0x80000021,
        PROJFS_TOMBSTONE = 0xA0000022,
        AF_UNIX = 0x80000023,
        LX_FIFO = 0x80000024,
        LX_CHR = 0x80000025,
        LX_BLK = 0x80000026,
    }

    [Flags]
    public enum ReparseBufferExFlags
    {
        None = 0,
        GivenTagOrNone = 1,
    }

#pragma warning restore 1591

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
            BinaryReader reader = new BinaryReader(new MemoryStream(ba), Encoding.Unicode);
            ReparseTag tag = (ReparseTag)reader.ReadUInt32();
            int data_length = reader.ReadUInt16();
            // Reserved
            reader.ReadUInt16();

            ReparseBuffer buffer = null;

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
        /// Get a reparse buffer from a byte array.
        /// </summary>
        /// <param name="ba">The byte array to parse</param>
        /// <param name="opaque_buffer">True to return an opaque buffer if 
        /// the tag isn't known, otherwise try and parse as a generic buffer</param>
        /// <returns>The reparse buffer.</returns>
        [Obsolete("Opaque buffer now automatically determined, use FromByteArray without the parameter")]
        public static ReparseBuffer FromByteArray(byte[] ba, bool opaque_buffer)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(ba), Encoding.Unicode);
            ReparseTag tag = (ReparseTag)reader.ReadUInt32();
            int data_length = reader.ReadUInt16();
            // Reserved
            reader.ReadUInt16();

            ReparseBuffer buffer = null;

            if (data_length != reader.RemainingLength())
            {
                // Possibly corrupted. Return an opaque buffer with all the data until the end.
                return new OpaqueReparseBuffer(tag, reader.ReadToEnd());
            }

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
                case ReparseTag.AF_UNIX:
                    buffer = new OpaqueReparseBuffer(ReparseTag.AF_UNIX);
                    break;
                default:
                    if (opaque_buffer || reader.RemainingLength() < 16)
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
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write((uint)Tag);
            if (buffer.Length > ushort.MaxValue)
            {
                throw new ArgumentException("Reparse buffer too large");
            }
            writer.Write((ushort)buffer.Length);
            writer.Write((ushort)0);
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
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
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

    /// <summary>
    /// Generic GUID reparse buffer.
    /// </summary>
    public sealed class GenericReparseBuffer : ReparseBuffer
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="tag">The reparse tag.</param>
        /// <param name="guid">The reparse GUID</param>
        /// <param name="data">Additional reparse data.</param>
        public GenericReparseBuffer(ReparseTag tag, Guid guid, byte[] data) : base(tag)
        {
            Data = (byte[])data.Clone();
            Guid = guid;
        }

        internal GenericReparseBuffer(ReparseTag tag) : base(tag)
        {
        }

        /// <summary>
        /// The reparse GUID.
        /// </summary>
        public Guid Guid { get; set; }

        /// <summary>
        /// Additional reparse data.
        /// </summary>
        public byte[] Data { get; set; }

        /// <summary>
        /// Get reparse buffer data as a byte array (not including header).
        /// </summary>
        /// <returns>The reparse buffer data.</returns>
        protected override byte[] GetBuffer()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write(Guid.ToByteArray());
            writer.Write(Data);
            return stm.ToArray();
        }

        /// <summary>
        /// Function to initialize this class by parsing the reparse buffer data (not including header).
        /// </summary>
        /// <param name="data_length">The length of the data to read.</param>
        /// <param name="reader">The stream to read from.</param>
        protected override void ParseBuffer(int data_length, BinaryReader reader)
        {
            Guid = new Guid(reader.ReadAllBytes(16));
            Data = reader.ReadAllBytes(data_length);
        }
    }

    /// <summary>
    /// Reparse buffer with an opaque data blob.
    /// </summary>
    public sealed class OpaqueReparseBuffer : ReparseBuffer
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="tag">The reparse tag.</param>
        /// <param name="data">The opaque data blob.</param>
        public OpaqueReparseBuffer(ReparseTag tag, byte[] data) : base(tag)
        {
            Data = (byte[])data.Clone();
        }

        internal OpaqueReparseBuffer(ReparseTag tag) : base(tag)
        {
        }

        /// <summary>
        /// The opaque data blob.
        /// </summary>
        public byte[] Data { get; set; }

        /// <summary>
        /// Get reparse buffer data as a byte array (not including header).
        /// </summary>
        /// <returns>The reparse buffer data.</returns>
        protected override byte[] GetBuffer()
        {
            return Data;
        }

        /// <summary>
        /// Function to initialize this class by parsing the reparse buffer data (not including header).
        /// </summary>
        /// <param name="data_length">The length of the data to read.</param>
        /// <param name="reader">The stream to read from.</param>
        protected override void ParseBuffer(int data_length, BinaryReader reader)
        {
            Data = reader.ReadAllBytes(data_length);
        }
    }

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
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
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

    /// <summary>
    /// Symlink flags.
    /// </summary>
    public enum SymlinkReparseBufferFlags
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Substitution name is relative to the symlink.
        /// </summary>
        Relative = 1,
    }

    /// <summary>
    /// Reparse buffer for an NTFS symlink.
    /// </summary>
    public sealed class SymlinkReparseBuffer : ReparseBuffer
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="substitution_name">Substitution name to reparse to when accessing symlink.</param>
        /// <param name="print_name">Printable name for the symlink.</param>
        /// <param name="flags">Symlink flags.</param>
        public SymlinkReparseBuffer(string substitution_name,
            string print_name, SymlinkReparseBufferFlags flags)
            : this(substitution_name, print_name, flags, false)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="substitution_name">Substitution name to reparse to when accessing symlink.</param>
        /// <param name="print_name">Printable name for the symlink.</param>
        /// <param name="flags">Symlink flags.</param>
        /// <param name="global">Create a global symlink rather than a normal symlink.</param>
        public SymlinkReparseBuffer(string substitution_name,
            string print_name, SymlinkReparseBufferFlags flags,
            bool global)
            : this(global)
        {
            if (string.IsNullOrEmpty(substitution_name))
            {
                throw new ArgumentException("substitution_name");
            }

            if (string.IsNullOrEmpty(print_name))
            {
                throw new ArgumentException("print_name");
            }

            SubstitutionName = substitution_name;
            PrintName = print_name;
            Flags = flags;
        }

        internal SymlinkReparseBuffer(bool global)
            : base(global ? ReparseTag.GLOBAL_REPARSE : ReparseTag.SYMLINK)
        {
        }

        /// <summary>
        /// Substitution name to reparse to when accessing symlink.
        /// </summary>
        public string SubstitutionName { get; set; }
        /// <summary>
        /// Printable name for the symlink.
        /// </summary>
        public string PrintName { get; set; }
        /// <summary>
        /// Symlink flags.
        /// </summary>
        public SymlinkReparseBufferFlags Flags { get; set; }

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

            Flags = (SymlinkReparseBufferFlags)reader.ReadInt32();

            byte[] path_buffer = reader.ReadAllBytes(data_length - 12);
            SubstitutionName = Encoding.Unicode.GetString(path_buffer, subname_ofs, subname_len);
            PrintName = Encoding.Unicode.GetString(path_buffer, pname_ofs, pname_len);
        }

        /// <summary>
        /// Get reparse buffer data as a byte array (not including header).
        /// </summary>
        /// <returns>The reparse buffer data.</returns>
        protected override byte[] GetBuffer()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
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
            writer.Write((int)Flags);
            writer.Write(subname);
            writer.Write(new byte[2]);
            writer.Write(pname);
            writer.Write(new byte[2]);
            return stm.ToArray();
        }
    }

    /// <summary>
    /// Application type for execution alias.
    /// </summary>
    public enum ExecutionAliasAppType
    {
        /// <summary>
        /// Desktop bridge application.
        /// </summary>
        Desktop = 0,
        /// <summary>
        /// UWP type 1
        /// </summary>
        UWP1 = 1,
        /// <summary>
        /// UWP type 2
        /// </summary>
        UWP2 = 2,
        /// <summary>
        /// UWP type 3
        /// </summary>
        UWP3 = 3
    }

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

        private static string ReadNulTerminated(BinaryReader reader)
        {
            StringBuilder builder = new StringBuilder();

            while (true)
            {
                char c = reader.ReadChar();
                if (c == 0)
                {
                    break;
                }
                builder.Append(c);
            }
            return builder.ToString();
        }

        private static void WriteNulTerminated(BinaryWriter writer, string str)
        {
            writer.Write(Encoding.Unicode.GetBytes(str + "\0"));
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
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm, Encoding.Unicode);
            writer.Write(Version);
            WriteNulTerminated(writer, PackageName);
            WriteNulTerminated(writer, EntryPoint);
            WriteNulTerminated(writer, Target);
            WriteNulTerminated(writer, ((int)AppType).ToString());
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
            PackageName = ReadNulTerminated(reader);
            EntryPoint = ReadNulTerminated(reader);
            Target = ReadNulTerminated(reader);
            AppType = (ExecutionAliasAppType)int.Parse(ReadNulTerminated(reader));
        }
    }
}
