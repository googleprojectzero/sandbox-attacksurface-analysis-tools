//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    [Flags]
    public enum ProtectionType
    {
        None = 0,
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteWriteCopy = 0x80,
        Guard = 0x100,
        NoCache = 0x200,
        WriteCombine = 0x400,
    }

    [Flags]
    public enum SectionAttributes
    {
        None = 0,
        Based = 0x00200000,
        NoChange = 0x00400000,
        Image = 0x01000000,
        Reserve = 0x04000000,
        Commit = 0x08000000,
        NoCache = 0x10000000,
    }


    [Flags]
    public enum SectionAccessRights : uint
    {
        Query = 0x0001,
        MapWrite = 0x0002,
        MapRead = 0x0004,
        MapExecute = 0x0008,
        ExtendSize = 0x0010,
        MapExecuteExplicit = 0x0020,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
    }


    [Flags]
    public enum ImageCharacteristics : ushort
    {
        None = 0,
        RelocsStripped = 0x0001,
        ExecutableImage = 0x0002,
        LineNumsStripped = 0x0004,
        LocalSymsStripped = 0x0008,
        AggresiveWsTrim = 0x0010,
        LargeAddressAware = 0x0020,
        FileBytesReservedLo = 0x0080,
        Image32BitMachine = 0x0100,
        DebugStripped = 0x0200,
        RemovableRunFromSwap = 0x0400,
        NetRunFromSwap = 0x0800,
        System = 0x1000,
        Dll = 0x2000,
        UpSystemOnly = 0x4000,
        BytesReservedHi = 0x8000,
    }

    public enum SectionInherit
    {
        ViewShare = 1,
        ViewUnmap = 2
    }

    [Flags]
    public enum AllocationType
    {
        None = 0,
        Commit = 0x00001000,
        Reserve = 0x00002000,
        Reset = 0x00080000,
        ResetUndo = 0x1000000,
        LargePages = 0x20000000,
        Physical = 0x00400000,
        TopDown = 0x00100000,
        WriteWatch = 0x00200000,
    }
    public enum SectionInformationClass
    {
        SectionBasicInformation,
        SectionImageInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SectionBasicInformation
    {
        public IntPtr BaseAddress;
        public SectionAttributes Attributes;
        public LargeIntegerStruct Size;
    }    

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateSection(out SafeKernelObjectHandle SectionHandle, 
            SectionAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes, [In] LargeInteger SectionSize,
            ProtectionType Protect, SectionAttributes Attributes,
            SafeHandle FileHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenSection(out SafeKernelObjectHandle SectionHandle,
            SectionAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQuerySection(SafeKernelObjectHandle SectionHandle,
             SectionInformationClass SectionInformationClass,
             SafeBuffer SectionInformation,
             int SectionInformationLength,
             out int ResultLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtMapViewOfSection(
            SafeKernelObjectHandle SectionHandle,
            SafeKernelObjectHandle ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            [In, Out] LargeInteger SectionOffset,
            ref IntPtr ViewSize,
            SectionInherit InheritDisposition,
            AllocationType AllocationType,
            ProtectionType Win32Protect
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtUnmapViewOfSection(
            SafeKernelObjectHandle ProcessHandle,
            IntPtr BaseAddress
        );
    }

    public sealed class NtMappedSection : SafeBuffer
    {
        public NtProcess Process { get; private set; }

        public long Length { get; private set; }

        internal NtMappedSection(IntPtr pointer, long size, NtProcess process, bool writable) : base(true)
        {
            SetHandle(pointer); 
            Initialize((ulong)size);
            Length = size;
            if (process.Handle.IsInvalid)
            {
                // No point duplicating an invalid handle. 
                // Also covers case of pseudo current process handle.
                Process = process;
            }
            else
            {
                Process = process.Duplicate();
            }
            _writable = writable;
        }
        
        protected override bool ReleaseHandle()
        {
            if (NtObject.IsSuccess(NtSystemCalls.NtUnmapViewOfSection(Process.Handle, handle)))
            {
                handle = IntPtr.Zero;
                return true;
            }
            return false;
        }

        public UnmanagedMemoryStream GetStream()
        {
            return new UnmanagedMemoryStream(this, 0, (long)ByteLength, _writable ? FileAccess.ReadWrite : FileAccess.Read);
        }

        private bool _writable;
    }

    public sealed class NtSection : NtObjectWithDuplicate<NtSection, SectionAccessRights>
    {
        internal NtSection(SafeKernelObjectHandle handle, SectionAttributes attributes, ProtectionType protection, LargeInteger size) : base(handle)
        {
        }

        internal NtSection(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        public static NtSection CreateImageSection(NtFile file)
        {
            return Create(null, SectionAccessRights.MaximumAllowed, null, ProtectionType.Execute, SectionAttributes.Image, file);
        }

        public static NtSection Create(string name, SectionAccessRights access, LargeInteger size, ProtectionType protection, SectionAttributes attributes, NtFile file)
        {
            using (ObjectAttributes obj_attr = new ObjectAttributes(name))
            {
                SafeKernelObjectHandle section_handle;                
                StatusToNtException(NtSystemCalls.NtCreateSection(out section_handle, access, obj_attr,
                    size, protection, attributes, file == null ? SafeKernelObjectHandle.Null : file.Handle));
                return new NtSection(section_handle);
            }            
        }

        public static NtSection Create(long size)
        {
            return Create(null, SectionAccessRights.MaximumAllowed, new LargeInteger(size), 
                ProtectionType.ReadWrite, SectionAttributes.Commit, null);
        }

        public NtMappedSection MapReadWrite(NtProcess process)
        {
            return Map(process, ProtectionType.ReadWrite);
        }

        public NtMappedSection MapRead(NtProcess process)
        {
            return Map(process, ProtectionType.ReadOnly);
        }

        public NtMappedSection MapRead()
        {
            return Map(NtProcess.Current, ProtectionType.ReadOnly);
        }

        public NtMappedSection MapReadWrite()
        {
            return Map(NtProcess.Current, ProtectionType.ReadWrite);
        }

        public NtMappedSection Map(NtProcess process, ProtectionType type)
        {
            IntPtr base_address = IntPtr.Zero;
            IntPtr view_size = new IntPtr(0);
            StatusToNtException(NtSystemCalls.NtMapViewOfSection(Handle, process.Handle, ref base_address, IntPtr.Zero,
                new IntPtr(0), null, ref view_size, SectionInherit.ViewUnmap, AllocationType.None, type));
            return new NtMappedSection(base_address, view_size.ToInt64(), process, true);
        }

        public NtMappedSection Map(ProtectionType type)
        {
            return Map(NtProcess.Current, type);
        }

        public static NtSection Open(string path, NtObject root, SectionAccessRights access_rights)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtOpenSection(out handle, access_rights, obja));
                return new NtSection(handle);
            }
        }

        private T Query<T>(SectionInformationClass info_class) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                int return_length = 0;
                StatusToNtException(NtSystemCalls.NtQuerySection(Handle, info_class, buffer, buffer.Length, out return_length));
                return buffer.Result;
            }
        }

        public long GetSize()
        {
            SectionBasicInformation info = Query<SectionBasicInformation>(SectionInformationClass.SectionBasicInformation);
            return info.Size.QuadPart;
        }

        public SectionAttributes GetAttributes()
        {
            SectionBasicInformation info = Query<SectionBasicInformation>(SectionInformationClass.SectionBasicInformation);
            return info.Attributes;
        }
    }
}
