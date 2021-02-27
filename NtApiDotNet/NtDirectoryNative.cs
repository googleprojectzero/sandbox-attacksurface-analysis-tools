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

using NtApiDotNet.Utilities.Reflection;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_DIRECTORY_INFORMATION
    {
        public UnicodeStringOut Name;
        public UnicodeStringOut TypeName;
    }

    public sealed class ObjectDirectoryInformation
    {
        private readonly NtDirectory _root;
        private string _symlink_target;

        public string Name { get; }
        public string NtTypeName { get; }
        public NtType NtType
        {
            get
            {
                return NtType.GetTypeByName(NtTypeName, true);
            }
        }
        public string FullPath { get; }
        public string SymbolicLinkTarget
        {
            get
            {
                if (_symlink_target == null)
                {
                    _symlink_target = string.Empty;
                    if (IsSymbolicLink)
                    {
                        using (var symlink = NtSymbolicLink.Open(Name, _root, SymbolicLinkAccessRights.Query, false))
                        {
                            if (symlink.IsSuccess)
                            {
                                _symlink_target = symlink.Result.Target;
                            }
                        }
                    }
                }
                return _symlink_target;
            }
        }

        internal ObjectDirectoryInformation(NtDirectory root, string base_path, OBJECT_DIRECTORY_INFORMATION info)
            : this(root, base_path, info.Name.ToString(), info.TypeName.ToString())
        {
        }

        internal ObjectDirectoryInformation(NtDirectory root, string base_path, string name, string typename)
        {
            _root = root;
            Name = name;
            NtTypeName = typename;
            FullPath = $@"{base_path}\{Name}";
        }

        public NtObject Open(AccessMask access)
        {
            return NtObject.OpenWithType(NtTypeName, Name, _root, access);
        }

        public bool IsDirectory
        {
            get { return NtTypeName.Equals("directory", StringComparison.OrdinalIgnoreCase); }
        }

        public bool IsSymbolicLink
        {
            get { return NtTypeName.Equals("symboliclink", StringComparison.OrdinalIgnoreCase); }
        }
    }

    /// <summary>
    /// Directory access rights.
    /// </summary>
    [Flags]
    public enum DirectoryAccessRights : uint
    {
        [SDKName("DIRECTORY_QUERY")]
        Query = 1,
        [SDKName("DIRECTORY_TRAVERSE")]
        Traverse = 2,
        [SDKName("DIRECTORY_CREATE_OBJECT")]
        CreateObject = 4,
        [SDKName("DIRECTORY_CREATE_SUBDIRECTORY")]
        CreateSubDirectory = 8,
        [SDKName("GENERIC_READ")]
        GenericRead = GenericAccessRights.GenericRead,
        [SDKName("GENERIC_WRITE")]
        GenericWrite = GenericAccessRights.GenericWrite,
        [SDKName("GENERIC_EXECUTE")]
        GenericExecute = GenericAccessRights.GenericExecute,
        [SDKName("GENERIC_ALL")]
        GenericAll = GenericAccessRights.GenericAll,
        [SDKName("DELETE")]
        Delete = GenericAccessRights.Delete,
        [SDKName("READ_CONTROL")]
        ReadControl = GenericAccessRights.ReadControl,
        [SDKName("WRITE_DAC")]
        WriteDac = GenericAccessRights.WriteDac,
        [SDKName("WRITE_OWNER")]
        WriteOwner = GenericAccessRights.WriteOwner,
        [SDKName("SYNCHRONIZE")]
        Synchronize = GenericAccessRights.Synchronize,
        [SDKName("MAXIMUM_ALLOWED")]
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        [SDKName("ACCESS_SYSTEM_SECURITY")]
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    [Flags]
    public enum DirectoryCreateFlags
    {
        None = 0,
        AlwaysInheritSecurity = 1,
        // Only works in kernel mode.
        FakeObjectRoot = 2,
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateDirectoryObject(out SafeKernelObjectHandle Handle,
            DirectoryAccessRights DesiredAccess, ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateDirectoryObjectEx(out SafeKernelObjectHandle Handle,
            DirectoryAccessRights DesiredAccess, ObjectAttributes ObjectAttributes, SafeKernelObjectHandle ShadowDirectory, DirectoryCreateFlags Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenDirectoryObject(out SafeKernelObjectHandle Handle, DirectoryAccessRights DesiredAccess, [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryDirectoryObject(SafeKernelObjectHandle DirectoryHandle,
            SafeBuffer Buffer, int Length, bool ReturnSingleEntry, bool RestartScan, ref int Context, out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreatePrivateNamespace(
            out SafeKernelObjectHandle NamespaceHandle,
            DirectoryAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            IntPtr BoundaryDescriptor);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenPrivateNamespace(
            out SafeKernelObjectHandle NamespaceHandle,
            DirectoryAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            IntPtr BoundaryDescriptor);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDeletePrivateNamespace(
            [In] SafeKernelObjectHandle NamespaceHandle
        );
    }

    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlCreateBoundaryDescriptor([In] UnicodeString Name, BoundaryDescriptorFlags Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlAddSIDToBoundaryDescriptor(ref IntPtr BoundaryDescriptor, SafeSidBufferHandle RequiredSid);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlAddIntegrityLabelToBoundaryDescriptor(ref IntPtr BoundaryDescriptor, SafeSidBufferHandle RequiredSid);

        [DllImport("ntdll.dll")]
        public static extern bool RtlDeleteBoundaryDescriptor(IntPtr BoundaryDescriptor);
    }

#pragma warning restore 1591
}
