//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Security;
using NtApiDotNet.Win32;
using NtApiDotNet.Win32.Rpc.Transport;
using NtApiDotNet.Win32.Security.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent the firewall engine.
    /// </summary>
    public sealed class FirewallEngine : IDisposable, INtObjectSecurity
    {
        #region Private Members

        private readonly SafeFwpmEngineHandle _handle;

        private delegate Win32Error GetSecurityInfoByKey(SafeFwpmEngineHandle engineHandle,
            in Guid key,
            SecurityInformation securityInfo,
            IntPtr sidOwner,
            IntPtr sidGroup,
            IntPtr dacl,
            IntPtr sacl,
            out SafeFwpmMemoryBuffer securityDescriptor);

        private delegate Win32Error GetSecurityInfo(SafeFwpmEngineHandle engineHandle,
            SecurityInformation securityInfo,
            IntPtr sidOwner,
            IntPtr sidGroup,
            IntPtr dacl,
            IntPtr sacl,
            out SafeFwpmMemoryBuffer securityDescriptor);

        private delegate Win32Error CreateEnumHandleFunc(
            SafeFwpmEngineHandle engineHandle,
            SafeBuffer enumTemplate,
            out IntPtr enumHandle
        );

        private delegate Win32Error EnumObjectFunc(
            SafeFwpmEngineHandle engineHandle,
            IntPtr enumHandle,
            int numEntriesRequested,
            out SafeFwpmMemoryBuffer entries,
            out int numEntriesReturned
        );

        private delegate Win32Error DestroyEnumHandleFunc(
           SafeFwpmEngineHandle engineHandle,
           IntPtr enumHandle
        );

        private NtResult<SecurityDescriptor> GetSecurity(SecurityInformation security_information, GetSecurityInfo func, bool throw_on_error)
        {
            security_information &= SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl | SecurityInformation.Sacl;

            var error = func(_handle, security_information,
                                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out SafeFwpmMemoryBuffer security_descriptor);
            if (error != Win32Error.SUCCESS)
            {
                return error.CreateResultFromDosError<SecurityDescriptor>(throw_on_error);
            }

            using (security_descriptor)
            {
                return SecurityDescriptor.Parse(security_descriptor, 
                   FirewallUtils.FirewallType, throw_on_error);
            }
        }

        private static NtResult<SecurityDescriptor> GetSecurityForKey(SafeFwpmEngineHandle engine_handle, SecurityInformation security_information, 
            Guid key, GetSecurityInfoByKey func, bool throw_on_error)
        {
            security_information &= SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl | SecurityInformation.Sacl;

            var error = func(engine_handle, key, SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl,
                                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out SafeFwpmMemoryBuffer security_descriptor);
            if (error != Win32Error.SUCCESS)
            {
                return error.CreateResultFromDosError<SecurityDescriptor>(throw_on_error);
            }

            using (security_descriptor)
            {
                return SecurityDescriptor.Parse(security_descriptor, FirewallUtils.FirewallType, throw_on_error);
            }
        }

        static FirewallFilter ProcessFilter(SafeFwpmEngineHandle engine_handle, FWPM_FILTER0 filter)
        {
            return new FirewallFilter(filter, (i, t) => GetSecurityForKey(engine_handle, i, filter.filterKey, 
                FirewallNativeMethods.FwpmFilterGetSecurityInfoByKey0, t));
        }

        static FirewallLayer ProcessLayer(SafeFwpmEngineHandle engine_handle, FWPM_LAYER0 layer)
        {
            return new FirewallLayer(layer, (i, t) => GetSecurityForKey(engine_handle, i, layer.layerKey,
                FirewallNativeMethods.FwpmLayerGetSecurityInfoByKey0, t));
        }

        static FirewallSubLayer ProcessSubLayer(SafeFwpmEngineHandle engine_handle, FWPM_SUBLAYER0 sublayer)
        {
            return new FirewallSubLayer(sublayer, (i, t) => GetSecurityForKey(engine_handle, i, sublayer.subLayerKey,
                FirewallNativeMethods.FwpmSubLayerGetSecurityInfoByKey0, t));
        }

        static FirewallCallout ProcessCallout(SafeFwpmEngineHandle engine_handle, FWPM_CALLOUT0 callout)
        {
            return new FirewallCallout(callout, (i, t) => GetSecurityForKey(engine_handle, i, callout.calloutKey,
                FirewallNativeMethods.FwpmCalloutGetSecurityInfoByKey0, t));
        }

        static IReadOnlyList<T> EnumerateFwObjects<T, U>(SafeFwpmEngineHandle engine_handle, SafeBuffer template,
            Func<SafeFwpmEngineHandle, U, T> map_func, CreateEnumHandleFunc create_func,
            EnumObjectFunc enum_func, DestroyEnumHandleFunc destroy_func)
        {
            return EnumerateFwObjects(engine_handle, template, map_func, create_func, enum_func, destroy_func, true).Result;
        }

        static NtResult<List<T>> EnumerateFwObjects<T, U>(SafeFwpmEngineHandle engine_handle, SafeBuffer template, 
            Func<SafeFwpmEngineHandle, U, T> map_func, CreateEnumHandleFunc create_func, 
            EnumObjectFunc enum_func, DestroyEnumHandleFunc destroy_func, bool throw_on_error)
        {
            const int MAX_ENTRY = 1000;
            IntPtr enum_handle = IntPtr.Zero;
            List<T> ret = new List<T>();
            try
            {
                NtStatus status = create_func(engine_handle, template ?? SafeHGlobalBuffer.Null, out enum_handle).MapDosErrorToStatus();
                if (!status.IsSuccess())
                {
                    return status.CreateResultFromError<List<T>>(throw_on_error);
                }
                while (true)
                {
                    status = enum_func(engine_handle, enum_handle, MAX_ENTRY, out SafeFwpmMemoryBuffer entries, out int entry_count).MapDosErrorToStatus();
                    if (!status.IsSuccess())
                    {
                        return status.CreateResultFromError<List<T>>(throw_on_error);
                    }

                    using (entries)
                    {
                        if (entry_count > 0)
                        {
                            entries.Initialize<IntPtr>((uint)entry_count);
                            IntPtr[] ptrs = entries.ReadArray<IntPtr>(0, entry_count);
                            ret.AddRange(ptrs.Select(ptr => map_func(engine_handle, (U)Marshal.PtrToStructure(ptr, typeof(U)))));
                        }

                        if (entry_count < MAX_ENTRY)
                        {
                            break;
                        }
                    }
                }
            }
            finally
            {
                if (enum_handle != IntPtr.Zero)
                {
                    destroy_func(engine_handle, enum_handle);
                }
            }
            return ret.CreateResult();
        }

        #endregion

        #region Constructors
        private FirewallEngine(SafeFwpmEngineHandle handle)
        {
            _handle = handle;
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Open an instance of the engine.
        /// </summary>
        /// <param name="server_name">The server name for the firewall service.</param>
        /// <param name="authn_service">RPC authentication service. Use default or WinNT.</param>
        /// <param name="auth_identity">Optional authentication credentials.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened firewall engine.</returns>
        public static NtResult<FirewallEngine> Open(string server_name, RpcAuthenticationType authn_service, UserCredentials auth_identity, bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var auth = auth_identity?.ToAuthIdentity(list);
                return FirewallNativeMethods.FwpmEngineOpen0(server_name, authn_service, auth, null,
                    out SafeFwpmEngineHandle handle).CreateWin32Result(throw_on_error, () => new FirewallEngine(handle));
            }
        }

        /// <summary>
        /// Open an instance of the engine.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened firewall engine.</returns>
        public static NtResult<FirewallEngine> Open(bool throw_on_error)
        {
            return Open(null, RpcAuthenticationType.WinNT, null, throw_on_error);
        }

        /// <summary>
        /// Open an instance of the engine.
        /// </summary>
        /// <returns>The opened firewall engine.</returns>
        public static FirewallEngine Open()
        {
            return Open(true).Result;
        }
        #endregion

        #region Public Methods

        /// <summary>
        /// Enumerate all layers.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of layers.</returns>
        public NtResult<IEnumerable<FirewallLayer>> EnumerateLayers(bool throw_on_error)
        {
            Func<SafeFwpmEngineHandle, FWPM_LAYER0, FirewallLayer> f = ProcessLayer;
            return EnumerateFwObjects(_handle, null, f, FirewallNativeMethods.FwpmLayerCreateEnumHandle0,
                FirewallNativeMethods.FwpmLayerEnum0, FirewallNativeMethods.FwpmLayerDestroyEnumHandle0,
                throw_on_error).Map<IEnumerable<FirewallLayer>>(l => l.AsReadOnly());
        }

        /// <summary>
        /// Enumerate all layers.
        /// </summary>
        /// <returns>The list of layers.</returns>
        public IEnumerable<FirewallLayer> EnumerateLayers()
        {
            return EnumerateLayers(true).Result;
        }

        /// <summary>
        /// Enumerate all sub-layers.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of sub-layers.</returns>
        public NtResult<IEnumerable<FirewallSubLayer>> EnumerateSubLayers(bool throw_on_error)
        {
            Func<SafeFwpmEngineHandle, FWPM_SUBLAYER0, FirewallSubLayer> f = ProcessSubLayer;

            return EnumerateFwObjects(_handle, null, f, FirewallNativeMethods.FwpmSubLayerCreateEnumHandle0,
                FirewallNativeMethods.FwpmSubLayerEnum0, FirewallNativeMethods.FwpmSubLayerDestroyEnumHandle0, 
                throw_on_error).Map<IEnumerable<FirewallSubLayer>>(l => l.AsReadOnly());
        }

        /// <summary>
        /// Enumerate all sub-layers.
        /// </summary>
        /// <returns>The list of sub-layers.</returns>
        public IEnumerable<FirewallSubLayer> EnumerateSubLayers()
        {
            return EnumerateSubLayers(true).Result;
        }

        /// <summary>
        /// Enumerate all callouts
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of callouts.</returns>
        public NtResult<IEnumerable<FirewallCallout>> EnumerateCallouts(bool throw_on_error)
        {
            Func<SafeFwpmEngineHandle, FWPM_CALLOUT0, FirewallCallout> f = ProcessCallout;

            return EnumerateFwObjects(_handle, null, f, FirewallNativeMethods.FwpmCalloutCreateEnumHandle0,
                FirewallNativeMethods.FwpmCalloutEnum0, FirewallNativeMethods.FwpmCalloutDestroyEnumHandle0, 
                throw_on_error).Map<IEnumerable<FirewallCallout>>(l => l.AsReadOnly());
        }

        /// <summary>
        /// Enumerate all callouts.
        /// </summary>
        /// <returns>The list of callouts.</returns>
        public IEnumerable<FirewallCallout> EnumerateCallouts()
        {
            return EnumerateCallouts(true).Result;
        }

        /// <summary>
        /// Enumerate all filters
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of filters.</returns>
        public NtResult<IEnumerable<FirewallFilter>> EnumerateFilters(bool throw_on_error)
        {
            Func<SafeFwpmEngineHandle, FWPM_FILTER0, FirewallFilter> f = ProcessFilter;
            return EnumerateFwObjects(_handle, null, f, FirewallNativeMethods.FwpmFilterCreateEnumHandle0,
                FirewallNativeMethods.FwpmFilterEnum0, FirewallNativeMethods.FwpmFilterDestroyEnumHandle0, 
                throw_on_error).Map<IEnumerable<FirewallFilter>>(l => l.AsReadOnly());
        }

        /// <summary>
        /// Enumerate all filters.
        /// </summary>
        /// <returns>The list of filters.</returns>
        public IEnumerable<FirewallFilter> EnumerateFilters()
        {
            return EnumerateFilters(true).Result;
        }

        /// <summary>
        /// Dispose the engine.
        /// </summary>
        public void Dispose()
        {
            _handle?.Dispose();
        }
        #endregion

        #region INtObjectSecurity Implementation
        string INtObjectSecurity.ObjectName => "FwEngine";

        NtType INtObjectSecurity.NtType => FirewallUtils.FirewallType;

        SecurityDescriptor INtObjectSecurity.SecurityDescriptor => ((INtObjectSecurity)this).GetSecurityDescriptor(SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl);

        bool INtObjectSecurity.IsAccessMaskGranted(AccessMask access)
        {
            return true;
        }

        void INtObjectSecurity.SetSecurityDescriptor(SecurityDescriptor security_descriptor, SecurityInformation security_information)
        {
            throw new NotImplementedException();
        }

        NtStatus INtObjectSecurity.SetSecurityDescriptor(SecurityDescriptor security_descriptor, SecurityInformation security_information, bool throw_on_error)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <returns>The security descriptor</returns>
        public SecurityDescriptor GetSecurityDescriptor(SecurityInformation security_information)
        {
            return ((INtObjectSecurity)this).GetSecurityDescriptor(security_information, true).Result;
        }

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor</returns>
        public NtResult<SecurityDescriptor> GetSecurityDescriptor(SecurityInformation security_information, bool throw_on_error)
        {
            return GetSecurity(security_information, FirewallNativeMethods.FwpmEngineGetSecurityInfo0, throw_on_error);
        }
        #endregion
    }
}
