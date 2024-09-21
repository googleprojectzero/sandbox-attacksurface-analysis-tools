//  Copyright 2021 Google Inc. All Rights Reserved.
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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Debugger
{
    internal class DbgHelpDebugCallbackHandler
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool PsymbolRegisteredCallback64(
            IntPtr hProcess,
            DbgHelpCallbackActionCode ActionCode,
            long CallbackData,
            long UserContext
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool SymRegisterCallbackW64(
          SafeKernelObjectHandle hProcess,
          [MarshalAs(UnmanagedType.FunctionPtr)]
          PsymbolRegisteredCallback64 CallbackFunction,
          long UserContext
        );

        private readonly SafeLoadLibraryHandle _dbghelp_lib;
        private readonly Dictionary<IntPtr, Func<IntPtr, DbgHelpCallbackActionCode, IntPtr, bool>> _callbacks;
        private readonly SymRegisterCallbackW64 _sym_register_callback;
        private readonly PsymbolRegisteredCallback64 _sym_debug_callback;

        private readonly static ConcurrentDictionary<IntPtr, DbgHelpDebugCallbackHandler> _callback_handlers 
            = new ConcurrentDictionary<IntPtr, DbgHelpDebugCallbackHandler>();

        private bool SymDebugCallback(
            IntPtr hProcess,
            DbgHelpCallbackActionCode ActionCode,
            long CallbackData,
            long UserContext
        )
        {
            if (_callbacks.ContainsKey(hProcess))
            {
                return _callbacks[hProcess](hProcess, ActionCode, new IntPtr(CallbackData));
            }
            return false;
        }

        private DbgHelpDebugCallbackHandler(SafeLoadLibraryHandle dbghelp_lib)
        {
            _dbghelp_lib = dbghelp_lib;
            _dbghelp_lib.PinModule();
            _callbacks = new Dictionary<IntPtr, Func<IntPtr, DbgHelpCallbackActionCode, IntPtr, bool>>();
            _sym_register_callback = _dbghelp_lib.GetFunctionPointer<SymRegisterCallbackW64>();
            _sym_debug_callback = SymDebugCallback;
        }

        public static DbgHelpDebugCallbackHandler GetInstance(SafeLoadLibraryHandle dbghelp_lib)
        {
            return _callback_handlers.GetOrAdd(dbghelp_lib.DangerousGetHandle(), 
                _ => new DbgHelpDebugCallbackHandler(dbghelp_lib));
        }

        public void RegisterHandler(SafeKernelObjectHandle process_handle, Func<IntPtr, DbgHelpCallbackActionCode, IntPtr, bool> handler)
        {
            lock (_callbacks)
            {
                _callbacks.Add(process_handle.DangerousGetHandle(), handler);
                if (!_sym_register_callback(process_handle, _sym_debug_callback, 0))
                {
                    throw new Win32Exception();
                }
            }
        }

        public void RemoveHandler(SafeKernelObjectHandle process_handle)
        {
            lock (_callbacks)
            {
                _callbacks.Remove(process_handle.DangerousGetHandle());
            }
        }
    }
}
