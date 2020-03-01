//  Copyright 2018 Google Inc. All Rights Reserved.
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

// NOTE: This file is a modified version of SymbolResolver.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32.Debugger
{
    internal sealed class DbgHelpSymbolResolver : ISymbolResolver, ISymbolTypeResolver, IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool SymInitializeW(
            SafeKernelObjectHandle hProcess,
            [MarshalAs(UnmanagedType.LPWStr)] string UserSearchPath,
            [MarshalAs(UnmanagedType.Bool)] bool fInvadeProcess
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool SymCleanup(
            SafeKernelObjectHandle hProcess
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool SymFromNameW(
              SafeKernelObjectHandle hProcess,
              string Name,
              SafeBuffer Symbol
            );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool EnumModules(
            string ModuleName,
            long BaseOfDll,
            IntPtr UserContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool SymEnumerateModulesW64(
              SafeKernelObjectHandle hProcess,
              EnumModules EnumModulesCallback,
              IntPtr UserContext
            );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool SymFromAddrW(
            SafeKernelObjectHandle hProcess,
            long Address,
            out long Displacement,
            SafeBuffer Symbol
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool SymGetModuleInfoW64(
              SafeKernelObjectHandle hProcess,
              long dwAddr,
              ref IMAGEHLP_MODULE64 ModuleInfo
            );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        delegate long SymLoadModule64(
              SafeKernelObjectHandle hProcess,
              IntPtr hFile,
              string ImageName,
              string ModuleName,
              long BaseOfDll,
              int SizeOfDll
            );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool SymRefreshModuleList(
            SafeKernelObjectHandle hProcess
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool PsymEnumeratesymbolsCallback(
          IntPtr pSymInfo,
          int SymbolSize,
          IntPtr UserContext
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool SymEnumTypesW(
          SafeKernelObjectHandle hProcess,
          long BaseOfDll,
          PsymEnumeratesymbolsCallback EnumSymbolsCallback,
          IntPtr UserContext
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate int SymSetOptions(
            SymOptions SymOptions
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool SymGetTypeFromNameW(
          SafeKernelObjectHandle hProcess,
          long BaseOfDll,
          string Name,
          SafeBuffer Symbol
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool SymEnumTypesByNameW(
            SafeKernelObjectHandle hProcess,
            long BaseOfDll,
            string mask,
            PsymEnumeratesymbolsCallback EnumSymbolsCallback,
            IntPtr UserContext
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool SymGetTypeInfo(
            SafeKernelObjectHandle hProcess,
            long BaseOfDll,
            int TypeId,
            IMAGEHLP_SYMBOL_TYPE_INFO GetType,
            SafeBuffer pInfo
        );

        private SafeLoadLibraryHandle _dbghelp_lib;
        private SymInitializeW _sym_init;
        private SymCleanup _sym_cleanup;
        private SymFromNameW _sym_from_name;
        private SymSetOptions _sym_set_options;
        private SymEnumerateModulesW64 _sym_enum_modules;
        private SymFromAddrW _sym_from_addr;
        private SymGetModuleInfoW64 _sym_get_module_info;
        private SymLoadModule64 _sym_load_module;
        private SymRefreshModuleList _sym_refresh_module_list;
        private SymEnumTypesW _sym_enum_types;
        private SymGetTypeFromNameW _sym_get_type_from_name;
        private SymEnumTypesByNameW _sym_enum_types_by_name;

        private void GetFunc<T>(ref T f) where T : Delegate
        {
            f = _dbghelp_lib.GetFunctionPointer<T>();
        }

        static SafeStructureInOutBuffer<SYMBOL_INFO> AllocateSymInfo()
        {
            return new SafeStructureInOutBuffer<SYMBOL_INFO>(new SYMBOL_INFO(SYMBOL_INFO.MAX_SYM_NAME), SYMBOL_INFO.MAX_SYM_NAME * 2, true);
        }

        static string GetNameFromSymbolInfo(SafeStructureInOutBuffer<SYMBOL_INFO> buffer)
        {
            return buffer.Data.ReadNulTerminatedUnicodeString();
        }

        internal DbgHelpSymbolResolver(NtProcess process, string dbghelp_path, string symbol_path)
        {
            Process = process.Duplicate();
            _dbghelp_lib = SafeLoadLibraryHandle.LoadLibrary(dbghelp_path);
            GetFunc(ref _sym_init);
            GetFunc(ref _sym_cleanup);
            GetFunc(ref _sym_from_name);
            GetFunc(ref _sym_set_options);
            GetFunc(ref _sym_enum_modules);
            GetFunc(ref _sym_from_addr);
            GetFunc(ref _sym_get_module_info);
            GetFunc(ref _sym_load_module);
            GetFunc(ref _sym_refresh_module_list);
            GetFunc(ref _sym_enum_types);
            GetFunc(ref _sym_get_type_from_name);
            GetFunc(ref _sym_enum_types_by_name);

            _sym_set_options(SymOptions.INCLUDE_32BIT_MODULES | SymOptions.UNDNAME | SymOptions.DEFERRED_LOADS);

            if (!_sym_init(Handle, symbol_path, true))
            {
                // If SymInitialize failed then we'll have to bootstrap modules manually.
                if (!_sym_init(Handle, symbol_path, false))
                {
                    throw new Win32Exception();
                }
                
                IntPtr[] modules = new IntPtr[1024];
                if (Win32NativeMethods.EnumProcessModulesEx(Handle, modules, modules.Length * IntPtr.Size, out int return_length,
                    process.Is64Bit ? EnumProcessModulesFilter.LIST_MODULES_64BIT : EnumProcessModulesFilter.LIST_MODULES_32BIT))
                {
                    foreach (IntPtr module in modules.Take(return_length / IntPtr.Size))
                    {
                        StringBuilder dllpath = new StringBuilder(260);
                        if (Win32NativeMethods.GetModuleFileNameEx(Handle, module, dllpath, dllpath.Capacity) > 0)
                        {
                            if (_sym_load_module(Handle, IntPtr.Zero, dllpath.ToString(),
                                Path.GetFileNameWithoutExtension(dllpath.ToString()), module.ToInt64(), GetImageSize(module)) == 0)
                            {
                                System.Diagnostics.Debug.WriteLine($"Couldn't load {dllpath}");
                            }
                        }
                    }
                }
            }
        }

        private int GetImageSize(IntPtr base_address)
        {
            if (!Win32NativeMethods.GetModuleInformation(Handle, base_address, 
                out MODULEINFO mod_info, Marshal.SizeOf(typeof(MODULEINFO))))
            {
                throw new SafeWin32Exception();
            }

            return mod_info.SizeOfImage;
        }

        private IMAGEHLP_MODULE64 GetModuleInfo(long base_address)
        {
            IMAGEHLP_MODULE64 module = new IMAGEHLP_MODULE64();
            module.SizeOfStruct = Marshal.SizeOf(module);
            if (_sym_get_module_info(Handle, base_address, ref module))
            {
                return module;
            }
            return new IMAGEHLP_MODULE64();
        }

        private IEnumerable<SymbolLoadedModule> GetLoadedModulesInternal()
        {
            List<SymbolLoadedModule> modules = new List<SymbolLoadedModule>();

            if (!_sym_enum_modules(Handle, (s, m, p) =>
            {
                modules.Add(new SymbolLoadedModule(s, new IntPtr(m), GetModuleInfo(m).ImageSize, this));
                return true;
            }, IntPtr.Zero))
            {
                throw new Win32Exception();
            }
            return modules.AsReadOnly();
        }

        private IEnumerable<SymbolLoadedModule> _loaded_modules;

        public IEnumerable<SymbolLoadedModule> GetLoadedModules()
        {
            return GetLoadedModules(false);
        }

        public IEnumerable<SymbolLoadedModule> GetLoadedModules(bool refresh)
        {
            if (_loaded_modules == null || refresh)
            {
                _loaded_modules = GetLoadedModulesInternal().OrderBy(s => s.BaseAddress.ToInt64());
            }
            return _loaded_modules;
        }

        public SymbolLoadedModule GetModuleForAddress(IntPtr address, bool refresh)
        {
            long check_addr = address.ToInt64();

            foreach (SymbolLoadedModule module in GetLoadedModules(refresh))
            {
                long base_address = module.BaseAddress.ToInt64();
                if (check_addr >= base_address && check_addr < base_address + module.ImageSize)
                {
                    return module;
                }
            }

            return null;
        }

        public SymbolLoadedModule GetModuleForAddress(IntPtr address)
        {
            return GetModuleForAddress(address, false);
        }

        public string GetModuleRelativeAddress(IntPtr address)
        {
            return GetModuleRelativeAddress(address, false);
        }

        public string GetModuleRelativeAddress(IntPtr address, bool refresh)
        {
            SymbolLoadedModule module = GetModuleForAddress(address, refresh);
            if (module == null)
            {
                return $"0x{address.ToInt64():X}";
            }

            return $"{module.Name}+0x{address.ToInt64() - module.BaseAddress.ToInt64():X}";
        }

        public IntPtr GetAddressOfSymbol(string name)
        {
            using (var sym_info = AllocateSymInfo())
            {
                if (!_sym_from_name(Handle, name, sym_info))
                {
                    return IntPtr.Zero;
                }
                return new IntPtr(sym_info.Result.Address);
            }
        }

        public string GetSymbolForAddress(IntPtr address)
        {
            return GetSymbolForAddress(address, true);
        }

        private static string GetSymbolName(string symbol)
        {
            int last_index = symbol.LastIndexOf("::");
            if (last_index >= 0)
            {
                symbol = symbol.Substring(last_index + 2);
            }

            last_index = symbol.LastIndexOf("`");
            if (last_index >= 0)
            {
                symbol = symbol.Substring(last_index + 1);
            }
            return symbol;
        }

        public string GetSymbolForAddress(IntPtr address, bool generate_fake_symbol, bool return_name_only)
        {
            using (var sym_info = AllocateSymInfo())
            {
                if (_sym_from_addr(Handle, address.ToInt64(), out long displacement, sym_info))
                {
                    string name = GetNameFromSymbolInfo(sym_info);
                    if (return_name_only)
                    {
                        return GetSymbolName(name);
                    }
                    string disp_str = string.Empty;
                    if (displacement < 0)
                    {
                        disp_str = $"-0x{Math.Abs(displacement):X}";
                    }
                    else if (displacement > 0)
                    {
                        disp_str = $"+0x{displacement:X}";
                    }

                    return $"{name}{disp_str}";
                }
                // Perhaps should return module+X?
                if (generate_fake_symbol && !return_name_only)
                {
                    return $"0x{address.ToInt64():X}";
                }
                return null;
            }
        }

        public string GetSymbolForAddress(IntPtr address, bool generate_fake_symbol)
        {
            return GetSymbolForAddress(address, generate_fake_symbol, false);
        }

        public void ReloadModuleList()
        {
            if (!_sym_refresh_module_list(Handle))
            {
                throw new SafeWin32Exception();
            }
        }

        public void LoadModule(string module_path, IntPtr base_address)
        {
            if (_sym_load_module(Handle, IntPtr.Zero, module_path,
                                Path.GetFileNameWithoutExtension(module_path), base_address.ToInt64(), GetImageSize(base_address)) == 0)
            {
                int error = Marshal.GetLastWin32Error();
                if (error != 0)
                {
                    throw new SafeWin32Exception(error);
                }
            }
        }

        private static SafeStructureInOutBuffer<SYMBOL_INFO> MapSymbolInfo(IntPtr symbol_info)
        {
            int base_size = Marshal.SizeOf(typeof(SYMBOL_INFO));
            SafeStructureInOutBuffer<SYMBOL_INFO> ret = new SafeStructureInOutBuffer<SYMBOL_INFO>(symbol_info, base_size, false);
            var result = ret.Result;
            int total_size = (result.MaxNameLen * 2) + result.SizeOfStruct - 2;
            return new SafeStructureInOutBuffer<SYMBOL_INFO>(symbol_info, total_size, false);
        }

        private EnumTypeInformation CreateEnumType(SYMBOL_INFO symbol_info, SymbolLoadedModule module, string name)
        {
            return new EnumTypeInformation(symbol_info, module, name);
        }

        private TypeInformation CreateType(SYMBOL_INFO symbol_info, SymbolLoadedModule module, string name)
        {
            switch (symbol_info.Tag)
            {
                case SymTagEnum.SymTagUDT:
                    return new UserDefinedTypeInformation(symbol_info, module, name);
                case SymTagEnum.SymTagEnum:
                    return CreateEnumType(symbol_info, module, name);
                default:
                    return new TypeInformation(symbol_info, module, name);
            }
        }

        private bool EnumTypes(Dictionary<long, SymbolLoadedModule> modules, 
            List<TypeInformation> symbols, IntPtr symbol_info, int symbol_size, IntPtr context)
        {
            var sym_info = MapSymbolInfo(symbol_info);
            SymbolLoadedModule loaded_module;
            var result = sym_info.Result;
            if (modules.ContainsKey(result.ModBase))
            {
                loaded_module = modules[result.ModBase];
            }
            else
            {
                loaded_module = new SymbolLoadedModule(string.Empty, new IntPtr(result.ModBase), 0, this);
                modules.Add(result.ModBase, loaded_module);
            }

            symbols.Add(CreateType(sym_info.Result, loaded_module, GetNameFromSymbolInfo(sym_info)));
            return true;
        }

        public IEnumerable<string> QueryTypeNames(IntPtr base_address)
        {
            return QueryTypes(base_address).Select(t => t.Name);
        }

        public IEnumerable<TypeInformation> QueryTypes(IntPtr base_address)
        {
            Dictionary<long, SymbolLoadedModule> modules = GetLoadedModules().ToDictionary(m => m.BaseAddress.ToInt64());
            List<TypeInformation> symbols = new List<TypeInformation>();
            _sym_enum_types(Handle, base_address.ToInt64(), (s, z, c) => EnumTypes(modules, symbols, s, z, c), IntPtr.Zero);
            return symbols;
        }

        public TypeInformation GetTypeByName(IntPtr base_address, string name)
        {
            Dictionary<long, SymbolLoadedModule> modules = GetLoadedModules().ToDictionary(m => m.BaseAddress.ToInt64());
            using (var sym_info = AllocateSymInfo())
            {
                if (_sym_get_type_from_name(Handle, base_address.ToInt64(), name, sym_info))
                {
                    var result = sym_info.Result;
                    SymbolLoadedModule loaded_module;
                    if (modules.ContainsKey(base_address.ToInt64()))
                    {
                        loaded_module = modules[base_address.ToInt64()];
                    }
                    else
                    {
                        loaded_module = new SymbolLoadedModule(string.Empty, new IntPtr(result.ModBase), 0, this);
                    }
                    return CreateType(result, loaded_module, GetNameFromSymbolInfo(sym_info));
                }
                else
                {
                    throw new ArgumentException("Invalid type");
                }
            }
        }

        public IEnumerable<TypeInformation> QueryTypesByName(IntPtr base_address, string mask)
        {
            Dictionary<long, SymbolLoadedModule> modules = GetLoadedModules().ToDictionary(m => m.BaseAddress.ToInt64());
            List<TypeInformation> symbols = new List<TypeInformation>();
            _sym_enum_types_by_name(Handle, base_address.ToInt64(), mask, (s, z, c) => EnumTypes(modules, symbols, s, z, c), IntPtr.Zero);
            return symbols;
        }

        internal NtProcess Process { get; }
        internal SafeKernelObjectHandle Handle { get { return Process.Handle; } }

        #region IDisposable Support
        private bool disposedValue = false; 

        void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                disposedValue = true;
                _sym_cleanup?.Invoke(Handle);
                _dbghelp_lib?.Close();
                Process?.Dispose();
            }
        }

        ~DbgHelpSymbolResolver()
        {
            Dispose(false);
        }

        void IDisposable.Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
