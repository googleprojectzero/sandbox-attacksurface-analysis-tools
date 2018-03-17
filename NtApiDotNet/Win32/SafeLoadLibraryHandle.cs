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

using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Flags for loading a library.
    /// </summary>
    [Flags]
    public enum LoadLibraryFlags
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Don't resolve DLL references
        /// </summary>
        DontResolveDllReferences = 0x00000001,
        /// <summary>
        /// Ignore code authz level.
        /// </summary>
        LoadIgnoreCodeAuthzLevel = 0x00000010,
        /// <summary>
        /// Load library as a data file.
        /// </summary>
        LoadLibraryAsDataFile = 0x00000002,
        /// <summary>
        /// Load library as a data file exclusively.
        /// </summary>
        LoadLibraryAsDataFileExclusive = 0x00000040,
        /// <summary>
        /// Load library as an image resource.
        /// </summary>
        LoadLibraryAsImageResource = 0x00000020,
        /// <summary>
        /// Load with an altered search path.
        /// </summary>
        LoadWithAlteredSearchPath = 0x00000008
    }

    /// <summary>
    /// Safe handle for a loaded library.
    /// </summary>
    public class SafeLoadLibraryHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeLoadLibraryHandle LoadLibraryEx(string name, IntPtr reserved, LoadLibraryFlags flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string name);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int GetModuleFileName(IntPtr hModule, [Out] StringBuilder lpFilename, int nSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, IntPtr name);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="handle">The handle to the library</param>
        /// <param name="owns_handle">True if the handle is owned by this object.</param>
        internal SafeLoadLibraryHandle(IntPtr handle, bool owns_handle) 
            : base(owns_handle)
        {
            SetHandle(handle);
        }

        internal SafeLoadLibraryHandle() : base(true)
        {
        }

        /// <summary>
        /// Release handle.
        /// </summary>
        /// <returns>True if handle released.</returns>
        protected override bool ReleaseHandle()
        {
            return FreeLibrary(handle);
        }

        /// <summary>
        /// Get the address of an exported function.
        /// </summary>
        /// <param name="name">The name of the exported function.</param>
        /// <returns>Pointer to the exported function, or IntPtr.Zero if it can't be found.</returns>
        public IntPtr GetProcAddress(string name)
        {
            return GetProcAddress(handle, name);
        }

        /// <summary>
        /// Get the address of an exported function from an ordinal.
        /// </summary>
        /// <param name="ordinal">The ordinal of the exported function.</param>
        /// <returns>Pointer to the exported function, or IntPtr.Zero if it can't be found.</returns>
        public IntPtr GetProcAddress(IntPtr ordinal)
        {
            return GetProcAddress(handle, ordinal);
        }

        /// <summary>
        /// Get a delegate which points to an unmanaged function.
        /// </summary>
        /// <typeparam name="TDelegate">The delegate type. The name of the delegate is used to lookup the name of the function.</typeparam>
        /// <returns>The delegate.</returns>
        public TDelegate GetFunctionPointer<TDelegate>() where TDelegate : class
        {
            if (!typeof(TDelegate).IsSubclassOf(typeof(Delegate)) ||
                typeof(TDelegate).GetCustomAttribute<UnmanagedFunctionPointerAttribute>() == null)
            {
                throw new ArgumentException("Invalid delegate type, must have an UnmanagedFunctionPointerAttribute annotation");
            }

            IntPtr proc = GetProcAddress(typeof(TDelegate).Name);
            if (proc == IntPtr.Zero)
            {
                throw new Win32Exception();
            }

            return (TDelegate)(object)Marshal.GetDelegateForFunctionPointer(proc, typeof(TDelegate));
        }

        /// <summary>
        /// Get path to loaded module.
        /// </summary>
        public string FullPath
        {
            get
            {
                StringBuilder builder = new StringBuilder(260);
                if (GetModuleFileName(handle, builder, builder.Capacity) == 0)
                {
                    throw new SafeWin32Exception();
                }
                return builder.ToString();
            }
        }

        /// <summary>
        /// Get the module name.
        /// </summary>
        public string Name
        {
            get
            {
                return Path.GetFileName(FullPath);
            }
        }

        /// <summary>
        /// Load a library into memory.
        /// </summary>
        /// <param name="name">The path to the library.</param>
        /// <param name="flags">Additonal flags to pass to LoadLibraryEx</param>
        /// <returns></returns>
        public static SafeLoadLibraryHandle LoadLibrary(string name, LoadLibraryFlags flags)
        {
            SafeLoadLibraryHandle ret = LoadLibraryEx(name, IntPtr.Zero, flags);
            if (ret.IsInvalid)
            {
                throw new SafeWin32Exception();
            }
            return ret;
        }

        /// <summary>
        /// Load a library into memory.
        /// </summary>
        /// <param name="name">The path to the library.</param>
        /// <returns></returns>
        public static SafeLoadLibraryHandle LoadLibrary(string name)
        {
            return LoadLibrary(name, LoadLibraryFlags.None);
        }

        const int GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x00000004;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetModuleHandleEx(int dwFlags, IntPtr lpModuleName, out SafeLoadLibraryHandle phModule);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetModuleHandleExW")]
        static extern bool GetModuleHandleEx(int dwFlags, string lpModuleName, out SafeLoadLibraryHandle phModule);

        /// <summary>
        /// Get the handle to an existing loading library by name.
        /// </summary>
        /// <param name="name">The name of the module.</param>
        /// <returns>The handle to the loaded library.</returns>
        /// <exception cref="SafeWin32Exception">Thrown if the module can't be found.</exception>
        public static SafeLoadLibraryHandle GetModuleHandle(string name)
        {
            if (GetModuleHandleEx(0, name, out SafeLoadLibraryHandle ret))
            {
                return ret;
            }
            throw new SafeWin32Exception();
        }

        /// <summary>
        /// Get the handle to an existing loading library by an address in the module.
        /// </summary>
        /// <param name="address">An address inside the module.</param>
        /// <returns>The handle to the loaded library, null if the address isn't inside a valid module.</returns>
        public static SafeLoadLibraryHandle GetModuleHandle(IntPtr address)
        {
            if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, address, out SafeLoadLibraryHandle ret))
            {
                return ret;
            }
            return null;
        }

        [DllImport("dbghelp.dll", SetLastError = true)]
        static extern IntPtr ImageDirectoryEntryToData(IntPtr Base, bool MappedAsImage, ushort DirectoryEntry, out int Size);

        const ushort IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;

        private IntPtr RvaToVA(long rva)
        {
            return new IntPtr(handle.ToInt64() + rva);
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_DELAY_IMPORT_DESCRIPTOR
        {
            public uint Characteristics;
            public int szName;
            public int phmod;
            public int pIAT;
            public int pINT;
            public int pBoundIAT;
            public int pUnloadIAT;
            public uint dwTimeStamp;
        }

        private void ParseDelayedImport(Dictionary<IntPtr, IntPtr> imports, IMAGE_DELAY_IMPORT_DESCRIPTOR desc)
        {
            if (desc.pIAT == 0 || desc.pINT == 0)
            {
                return;
            }

            string name = Marshal.PtrToStringAnsi(RvaToVA(desc.szName));
            IntPtr IAT = RvaToVA(desc.pIAT);
            IntPtr INT = RvaToVA(desc.pINT);

            try
            {
                using (SafeLoadLibraryHandle lib = SafeLoadLibraryHandle.LoadLibrary(name))
                {
                    IntPtr import_name_rva = Marshal.ReadIntPtr(INT);

                    while (import_name_rva != IntPtr.Zero)
                    {
                        IntPtr import;
                        // Ordinal
                        if (import_name_rva.ToInt64() < 0)
                        {
                            import = lib.GetProcAddress(new IntPtr(import_name_rva.ToInt64() & 0xFFFF));
                        }
                        else
                        {
                            IntPtr import_ofs = RvaToVA(import_name_rva.ToInt64() + 2);
                            string import_name = Marshal.PtrToStringAnsi(import_ofs);
                            import = lib.GetProcAddress(import_name);
                        }

                        if (import != IntPtr.Zero)
                        {
                            imports[IAT] = import;
                        }

                        INT += IntPtr.Size;
                        IAT += IntPtr.Size;
                        import_name_rva = Marshal.ReadIntPtr(INT);
                    }
                }
            }
            catch (Win32Exception)
            {
            }
        }

        private Dictionary<IntPtr, IntPtr> _delayed_imports;

        /// <summary>
        /// Parse a library's delayed import information.
        /// </summary>
        /// <returns>A dictionary containing the location of import information keyed against the IAT address.</returns>
        public IDictionary<IntPtr, IntPtr> ParseDelayedImports()
        {
            if (_delayed_imports != null)
            {
                return _delayed_imports;
            }
            _delayed_imports = new Dictionary<IntPtr, IntPtr>();
            IntPtr delayed_imports = ImageDirectoryEntryToData(handle, true, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, out int size);
            if (delayed_imports == null)
            {
                return new ReadOnlyDictionary<IntPtr, IntPtr>(_delayed_imports);
            }

            int i = 0;
            int desc_size = Marshal.SizeOf(typeof(IMAGE_DELAY_IMPORT_DESCRIPTOR));
            // Should really only do up to sizeof image delay import desc
            while (i <= (size - desc_size))
            {
                IMAGE_DELAY_IMPORT_DESCRIPTOR desc = (IMAGE_DELAY_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(delayed_imports, typeof(IMAGE_DELAY_IMPORT_DESCRIPTOR));
                if (desc.szName == 0)
                {
                    break;
                }

                ParseDelayedImport(_delayed_imports, desc);

                delayed_imports += desc_size;
                size -= desc_size;
            }

            return new ReadOnlyDictionary<IntPtr, IntPtr>(_delayed_imports);
        }
    }
}
