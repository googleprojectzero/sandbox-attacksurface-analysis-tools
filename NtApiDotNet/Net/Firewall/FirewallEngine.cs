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

        private delegate Win32Error GetSecurityInfoByKey(
            SafeFwpmEngineHandle engineHandle,
            in Guid key,
            SecurityInformation securityInfo,
            IntPtr sidOwner,
            IntPtr sidGroup,
            IntPtr dacl,
            IntPtr sacl,
            out SafeFwpmMemoryBuffer securityDescriptor);

        private delegate Win32Error GetSecurityInfo(
            SafeFwpmEngineHandle engineHandle,
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

        private delegate Win32Error GetFirewallObjectByKey(
            SafeFwpmEngineHandle engineHandle,
            in Guid key,
            out SafeFwpmMemoryBuffer buffer);

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
            var error = func(engine_handle, key, security_information,
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

        private FirewallFilter ProcessFilter(FWPM_FILTER0 filter)
        {
            return new FirewallFilter(filter, this, (i, t) => GetSecurityForKey(_handle, i, filter.filterKey, 
                FirewallNativeMethods.FwpmFilterGetSecurityInfoByKey0, t));
        }

        private FirewallLayer ProcessLayer(FWPM_LAYER0 layer)
        {
            return new FirewallLayer(layer, this, (i, t) => GetSecurityForKey(_handle, i, layer.layerKey,
                FirewallNativeMethods.FwpmLayerGetSecurityInfoByKey0, t));
        }

        private FirewallSubLayer ProcessSubLayer(FWPM_SUBLAYER0 sublayer)
        {
            return new FirewallSubLayer(sublayer, this, (i, t) => GetSecurityForKey(_handle, i, sublayer.subLayerKey,
                FirewallNativeMethods.FwpmSubLayerGetSecurityInfoByKey0, t));
        }

        private FirewallCallout ProcessCallout(FWPM_CALLOUT0 callout)
        {
            return new FirewallCallout(callout, this, (i, t) => GetSecurityForKey(_handle, i, callout.calloutKey,
                FirewallNativeMethods.FwpmCalloutGetSecurityInfoByKey0, t));
        }

        private FirewallProvider ProcessProvider(FWPM_PROVIDER0 provider)
        {
            return new FirewallProvider(provider, this, (i, t) => GetSecurityForKey(_handle, i, provider.providerKey,
                FirewallNativeMethods.FwpmProviderGetSecurityInfoByKey0, t));
        }

        private FirewallAleEndpoint ProcessAleEndpoint(FWPS_ALE_ENDPOINT_PROPERTIES0 endpoint)
        {
            return new FirewallAleEndpoint(endpoint);
        }

        private NtResult<List<T>> EnumerateFwObjects<T, U>(IFirewallEnumTemplate template, 
            Func<U, T> map_func, CreateEnumHandleFunc create_func, 
            EnumObjectFunc enum_func, DestroyEnumHandleFunc destroy_func, bool throw_on_error)
        {
            const int MAX_ENTRY = 1000;
            List<T> ret = new List<T>();
            using (var list = new DisposableList())
            {
                NtStatus status = create_func(_handle, template?.ToTemplateBuffer(list) ?? SafeHGlobalBuffer.Null, out IntPtr enum_handle).MapDosErrorToStatus();
                if (!status.IsSuccess())
                {
                    return status.CreateResultFromError<List<T>>(throw_on_error);
                }
                list.CallOnDispose(() => destroy_func(_handle, enum_handle));
                while (true)
                {
                    status = enum_func(_handle, enum_handle, MAX_ENTRY, out SafeFwpmMemoryBuffer entries, out int entry_count).MapDosErrorToStatus();
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
                            ret.AddRange(ptrs.Select(ptr => map_func((U)Marshal.PtrToStructure(ptr, typeof(U)))));
                        }

                        if (entry_count < MAX_ENTRY)
                        {
                            break;
                        }
                    }
                }
            }
            return ret.CreateResult();
        }

        private NtResult<T> GetFwObjectByKey<T, U>(Guid key, Func<U, T> map_func, GetFirewallObjectByKey get_func, bool throw_on_error)
        {
            return get_func(_handle, key, out SafeFwpmMemoryBuffer buffer).CreateWin32Result(throw_on_error, () =>
            {
                using (buffer)
                {
                    return map_func((U)Marshal.PtrToStructure(buffer.DangerousGetHandle(), typeof(U)));
                }
            });
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
        /// <param name="session">Optional session information.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened firewall engine.</returns>
        public static NtResult<FirewallEngine> Open(string server_name, RpcAuthenticationType authn_service, UserCredentials auth_identity, FirewallSession session, bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var auth = auth_identity?.ToAuthIdentity(list);
                var sess = session?.ToStruct(list);
                return FirewallNativeMethods.FwpmEngineOpen0(string.IsNullOrEmpty(server_name) ? null : server_name, authn_service, auth, sess,
                    out SafeFwpmEngineHandle handle).CreateWin32Result(throw_on_error, () => new FirewallEngine(handle));
            }
        }

        /// <summary>
        /// Open an instance of the engine.
        /// </summary>
        /// <param name="server_name">The server name for the firewall service.</param>
        /// <param name="authn_service">RPC authentication service. Use default or WinNT.</param>
        /// <param name="auth_identity">Optional authentication credentials.</param>
        /// <param name="session">Optional session information.</param>
        /// <returns>The opened firewall engine.</returns>
        public static FirewallEngine Open(string server_name, RpcAuthenticationType authn_service, UserCredentials auth_identity, FirewallSession session)
        {
            return Open(server_name, authn_service, auth_identity, session, true).Result;
        }

        /// <summary>
        /// Open an instance of the engine.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened firewall engine.</returns>
        public static NtResult<FirewallEngine> Open(bool throw_on_error)
        {
            return Open(null, RpcAuthenticationType.WinNT, null, null, throw_on_error);
        }

        /// <summary>
        /// Open an instance of the engine.
        /// </summary>
        /// <returns>The opened firewall engine.</returns>
        public static FirewallEngine Open()
        {
            return Open(true).Result;
        }

        /// <summary>
        /// Open a dynamic instance of the engine.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened firewall engine.</returns>
        public static NtResult<FirewallEngine> OpenDynamic(bool throw_on_error)
        {
            return Open(null, RpcAuthenticationType.WinNT, null, 
                new FirewallSession(FirewallSessionFlags.Dynamic), throw_on_error);
        }

        /// <summary>
        /// Open a dynamic instance of the engine.
        /// </summary>
        /// <returns>The opened firewall engine.</returns>
        public static FirewallEngine OpenDynamic()
        {
            return OpenDynamic(true).Result;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Get a layer by its key.
        /// </summary>
        /// <param name="key">The key of the layer.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall layer.</returns>
        public NtResult<FirewallLayer> GetLayer(Guid key, bool throw_on_error)
        {
            Func<FWPM_LAYER0, FirewallLayer> f = ProcessLayer;
            return GetFwObjectByKey(key, f, FirewallNativeMethods.FwpmLayerGetByKey0, throw_on_error);
        }

        /// <summary>
        /// Get a layer by its key.
        /// </summary>
        /// <param name="key">The key of the layer.</param>
        /// <returns>The firewall layer.</returns>
        public FirewallLayer GetLayer(Guid key)
        {
            return GetLayer(key, true).Result;
        }

        /// <summary>
        /// Get a layer by its ID.
        /// </summary>
        /// <param name="id">The ID of the layer.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall layer.</returns>
        public NtResult<FirewallLayer> GetLayer(int id, bool throw_on_error)
        {
            return FirewallNativeMethods.FwpmLayerGetById0(_handle, (ushort)id, out SafeFwpmMemoryBuffer buffer)
                .CreateWin32Result(throw_on_error, () =>
                {
                    using (buffer)
                    {
                        return ProcessLayer((FWPM_LAYER0)Marshal.PtrToStructure(buffer.DangerousGetHandle(), typeof(FWPM_LAYER0)));
                    }
                });
        }

        /// <summary>
        /// Get a layer by its ID.
        /// </summary>
        /// <param name="id">The ID of the layer.</param>
        /// <returns>The firewall layer.</returns>
        public FirewallLayer GetLayer(int id)
        {
            return GetLayer(id, true).Result;
        }

        /// <summary>
        /// Get a layer by its well-known key name.
        /// </summary>
        /// <param name="name">The well-known key name of the layer.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall layer.</returns>
        public NtResult<FirewallLayer> GetLayer(string name, bool throw_on_error)
        {
            var key = NamedGuidDictionary.LayerGuids.Value.GuidFromName(name, throw_on_error);
            if (!key.IsSuccess)
                return key.Cast<FirewallLayer>();

            return GetLayer(key.Result, throw_on_error);
        }

        /// <summary>
        /// Get a layer by its well-known key name.
        /// </summary>
        /// <param name="name">The well-known key name of the layer.</param>
        /// <returns>The firewall layer.</returns>
        public FirewallLayer GetLayer(string name)
        {
            return GetLayer(name, true).Result;
        }

        /// <summary>
        /// Get a layer by an ALE layer type.
        /// </summary>
        /// <param name="ale_layer">The ALE layer type.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall layer.</returns>
        public NtResult<FirewallLayer> GetLayer(FirewallAleLayer ale_layer, bool throw_on_error)
        {
            return GetLayer(FirewallUtils.GetLayerGuidForAleLayer(ale_layer), throw_on_error);
        }

        /// <summary>
        /// Get a layer by an ALE layer type.
        /// </summary>
        /// <param name="ale_layer">The ALE layer type.</param>
        /// <returns>The firewall layer.</returns>
        public FirewallLayer GetLayer(FirewallAleLayer ale_layer)
        {
            return GetLayer(ale_layer, true).Result;
        }

        /// <summary>
        /// Enumerate all layers.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of layers.</returns>
        public NtResult<IEnumerable<FirewallLayer>> EnumerateLayers(bool throw_on_error)
        {
            Func<FWPM_LAYER0, FirewallLayer> f = ProcessLayer;
            return EnumerateFwObjects(null, f, FirewallNativeMethods.FwpmLayerCreateEnumHandle0,
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
        /// Get a sub-layer by its key.
        /// </summary>
        /// <param name="key">The key of the sub-layer.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall sub-layer.</returns>
        public NtResult<FirewallSubLayer> GetSubLayer(Guid key, bool throw_on_error)
        {
            Func<FWPM_SUBLAYER0, FirewallSubLayer> f = ProcessSubLayer;
            return GetFwObjectByKey(key, f, FirewallNativeMethods.FwpmSubLayerGetByKey0, throw_on_error);
        }

        /// <summary>
        /// Get a sub-layer by its key.
        /// </summary>
        /// <param name="key">The key of the sub-layer.</param>
        /// <returns>The firewall sub-layer.</returns>
        public FirewallSubLayer GetSubLayer(Guid key)
        {
            return GetSubLayer(key, true).Result;
        }

        /// <summary>
        /// Get a sub-layer by its well-known key name.
        /// </summary>
        /// <param name="name">The well-known key name of the sub-layer.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall sub-layer.</returns>
        public NtResult<FirewallSubLayer> GetSubLayer(string name, bool throw_on_error)
        {
            var key = NamedGuidDictionary.SubLayerGuids.Value.GuidFromName(name, throw_on_error);
            if (!key.IsSuccess)
                return key.Cast<FirewallSubLayer>();
            return GetSubLayer(key.Result, throw_on_error);
        }

        /// <summary>
        /// Get a sub-layer by its well-known key name.
        /// </summary>
        /// <param name="name">The well-known key name of the sub-layer.</param>
        /// <returns>The firewall sub-layer.</returns>
        public FirewallSubLayer GetSubLayer(string name)
        {
            return GetSubLayer(name, true).Result;
        }

        /// <summary>
        /// Enumerate all sub-layers.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of sub-layers.</returns>
        public NtResult<IEnumerable<FirewallSubLayer>> EnumerateSubLayers(bool throw_on_error)
        {
            Func<FWPM_SUBLAYER0, FirewallSubLayer> f = ProcessSubLayer;

            return EnumerateFwObjects(null, f, FirewallNativeMethods.FwpmSubLayerCreateEnumHandle0,
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
        /// Get a callout by its key.
        /// </summary>
        /// <param name="key">The key of the callout.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall callout.</returns>
        public NtResult<FirewallCallout> GetCallout(Guid key, bool throw_on_error)
        {
            Func<FWPM_CALLOUT0, FirewallCallout> f = ProcessCallout;
            return GetFwObjectByKey(key, f, FirewallNativeMethods.FwpmCalloutGetByKey0, throw_on_error);
        }

        /// <summary>
        /// Get a callout by its key.
        /// </summary>
        /// <param name="key">The key of the callout.</param>
        /// <returns>The firewall callout.</returns>
        public FirewallCallout GetCallout(Guid key)
        {
            return GetCallout(key, true).Result;
        }

        /// <summary>
        /// Enumerate all callouts
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of callouts.</returns>
        public NtResult<IEnumerable<FirewallCallout>> EnumerateCallouts(bool throw_on_error)
        {
            Func<FWPM_CALLOUT0, FirewallCallout> f = ProcessCallout;

            return EnumerateFwObjects(null, f, FirewallNativeMethods.FwpmCalloutCreateEnumHandle0,
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
        /// Get a filter by its key.
        /// </summary>
        /// <param name="key">The key of the filter.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall filter.</returns>
        public NtResult<FirewallFilter> GetFilter(Guid key, bool throw_on_error)
        {
            Func<FWPM_FILTER0, FirewallFilter> f = ProcessFilter;
            return GetFwObjectByKey(key, f, FirewallNativeMethods.FwpmFilterGetByKey0, throw_on_error);
        }

        /// <summary>
        /// Get a filter by its key.
        /// </summary>
        /// <param name="key">The key of the filter.</param>
        /// <returns>The firewall filter.</returns>
        public FirewallFilter GetFilter(Guid key)
        {
            return GetFilter(key, true).Result;
        }

        /// <summary>
        /// Get a filter by its id.
        /// </summary>
        /// <param name="id">The ID of the filter.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall filter.</returns>
        public NtResult<FirewallFilter> GetFilter(ulong id, bool throw_on_error)
        {
            return FirewallNativeMethods.FwpmFilterGetById0(_handle, id, out SafeFwpmMemoryBuffer buffer)
                .CreateWin32Result(throw_on_error, () =>
            {
                using (buffer)
                {
                    return ProcessFilter((FWPM_FILTER0)Marshal.PtrToStructure(buffer.DangerousGetHandle(), typeof(FWPM_FILTER0)));
                }
            });
        }

        /// <summary>
        /// Get a filter by its id.
        /// </summary>
        /// <param name="id">The ID of the filter.</param>
        /// <returns>The firewall filter.</returns>
        public FirewallFilter GetFilter(ulong id)
        {
            return GetFilter(id, true).Result;
        }

        /// <summary>
        /// Enumerate filters
        /// </summary>
        /// <param name="template">Specify a template for enumerating the filters.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of filters.</returns>
        public NtResult<IEnumerable<FirewallFilter>> EnumerateFilters(FirewallFilterEnumTemplate template, bool throw_on_error)
        {
            Func<FWPM_FILTER0, FirewallFilter> f = ProcessFilter;
            return EnumerateFwObjects(template, f, FirewallNativeMethods.FwpmFilterCreateEnumHandle0,
                FirewallNativeMethods.FwpmFilterEnum0, FirewallNativeMethods.FwpmFilterDestroyEnumHandle0,
                throw_on_error).Map<IEnumerable<FirewallFilter>>(l => l.AsReadOnly());
        }

        /// <summary>
        /// Enumerate filters
        /// </summary>
        /// <param name="template">Specify a template for enumerating the filters.</param>
        /// <returns>The list of filters.</returns>
        public IEnumerable<FirewallFilter> EnumerateFilters(FirewallFilterEnumTemplate template)
        {
            return EnumerateFilters(template, true).Result;
        }

        /// <summary>
        /// Enumerate all filters
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of filters.</returns>
        public NtResult<IEnumerable<FirewallFilter>> EnumerateFilters(bool throw_on_error)
        {
            return EnumerateFilters(null, throw_on_error);
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
        /// Add a filter.
        /// </summary>
        /// <param name="builder">The builder used to create the filter.</param>
        /// <param name="security_descriptor">Optional security descriptor.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The added filter ID.</returns>
        public NtResult<ulong> AddFilter(FirewallFilterBuilder builder, SecurityDescriptor security_descriptor, bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var sd_buffer = security_descriptor != null ? list.AddResource(security_descriptor.ToSafeBuffer()) : SafeHGlobalBuffer.Null;
                return FirewallNativeMethods.FwpmFilterAdd0(_handle, builder.ToStruct(list), 
                    sd_buffer, out ulong id).CreateWin32Result(throw_on_error, () => id);
            }
        }

        /// <summary>
        /// Add a filter.
        /// </summary>
        /// <param name="builder">The builder used to create the filter.</param>
        /// <param name="security_descriptor">Optional security descriptor.</param>
        /// <returns>The added filter ID.</returns>
        public ulong AddFilter(FirewallFilterBuilder builder, SecurityDescriptor security_descriptor)
        {
            return AddFilter(builder, security_descriptor, true).Result;
        }

        /// <summary>
        /// Add a filter.
        /// </summary>
        /// <param name="builder">The builder used to create the filter.</param>
        /// <returns>The added filter ID.</returns>
        public ulong AddFilter(FirewallFilterBuilder builder)
        {
            return AddFilter(builder, null);
        }

        /// <summary>
        /// Delete a filter.
        /// </summary>
        /// <param name="key">The filter key.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status.</returns>
        public NtStatus DeleteFilter(Guid key, bool throw_on_error)
        {
            return FirewallNativeMethods.FwpmFilterDeleteByKey0(_handle, key).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Delete a filter.
        /// </summary>
        /// <param name="key">The filter key.</param>
        public void DeleteFilter(Guid key)
        {
            DeleteFilter(key, true);
        }

        /// <summary>
        /// Delete a filter.
        /// </summary>
        /// <param name="id">The filter ID.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status.</returns>
        public NtStatus DeleteFilter(ulong id, bool throw_on_error)
        {
            return FirewallNativeMethods.FwpmFilterDeleteById0(_handle, id).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Delete a filter.
        /// </summary>
        /// <param name="id">The filter ID.</param>
        public void DeleteFilter(ulong id)
        {
            DeleteFilter(id, true);
        }

        /// <summary>
        /// Get a provider by its key.
        /// </summary>
        /// <param name="key">The key of the provider.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall provider.</returns>
        public NtResult<FirewallProvider> GetProvider(Guid key, bool throw_on_error)
        {
            Func<FWPM_PROVIDER0, FirewallProvider> f = ProcessProvider;
            return GetFwObjectByKey(key, f, FirewallNativeMethods.FwpmProviderGetByKey0, throw_on_error);
        }

        /// <summary>
        /// Get a provider by its key.
        /// </summary>
        /// <param name="key">The key of the provider.</param>
        /// <returns>The firewall provider.</returns>
        public FirewallProvider GetProvider(Guid key)
        {
            return GetProvider(key, true).Result;
        }

        /// <summary>
        /// Enumerate all providers.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of providers.</returns>
        public NtResult<IEnumerable<FirewallProvider>> EnumerateProviders(bool throw_on_error)
        {
            Func<FWPM_PROVIDER0, FirewallProvider> f = ProcessProvider;
            return EnumerateFwObjects(null, f, FirewallNativeMethods.FwpmProviderCreateEnumHandle0,
                FirewallNativeMethods.FwpmProviderEnum0, FirewallNativeMethods.FwpmProviderDestroyEnumHandle0,
                throw_on_error).Map<IEnumerable<FirewallProvider>>(l => l.AsReadOnly());
        }

        /// <summary>
        /// Enumerate all providers.
        /// </summary>
        /// <returns>The list of providers.</returns>
        public IEnumerable<FirewallProvider> EnumerateProviders()
        {
            return EnumerateProviders(true).Result;
        }

        /// <summary>
        /// Get the security descriptor for the IKE SA database.
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor</returns>
        public NtResult<SecurityDescriptor> GetIkeSaDbSecurityDescriptor(SecurityInformation security_information, bool throw_on_error)
        {
            return GetSecurity(security_information, FirewallNativeMethods.IkeextSaDbGetSecurityInfo0, throw_on_error);
        }

        /// <summary>
        /// Get the security descriptor for the IKE SA database.
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <returns>The security descriptor</returns>
        public SecurityDescriptor GetIkeSaDbSecurityDescriptor(SecurityInformation security_information)
        {
            return GetIkeSaDbSecurityDescriptor(security_information, true).Result;
        }

        /// <summary>
        /// Get the security descriptor for the IKE SA database.
        /// </summary>
        /// <returns>The security descriptor</returns>
        public SecurityDescriptor GetIkeSaDbSecurityDescriptor()
        {
            return GetIkeSaDbSecurityDescriptor(SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl);
        }

        /// <summary>
        /// Classify a layer.
        /// </summary>
        /// <param name="layer_id">The ID of the layer.</param>
        /// <param name="incoming_values">A list of incoming values.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The classify result.</returns>
        public NtResult<FirewallClassifyResult> Classify(int layer_id, IEnumerable<FirewallValue> incoming_values, bool throw_on_error)
        {
            if (incoming_values is null)
            {
                throw new ArgumentNullException(nameof(incoming_values));
            }

            using (var list = new DisposableList())
            {
                var values = incoming_values.Select(v => v.ToStruct(list)).ToArray();
                var buffer = list.AddResource(values.ToBuffer());
                return FirewallNativeMethods.FwpsClassifyUser0(_handle, (ushort)layer_id, new FWPS_INCOMING_VALUES0()
                {
                    layerId = (ushort)layer_id,
                    valueCount = values.Length,
                    incomingValue = buffer.DangerousGetHandle()
                }, IntPtr.Zero, IntPtr.Zero, out FWPS_CLASSIFY_OUT0 result).CreateWin32Result(throw_on_error, 
                () => new FirewallClassifyResult(result));
            }
        }

        /// <summary>
        /// Classify a layer.
        /// </summary>
        /// <param name="layer_id">The ID of the layer.</param>
        /// <param name="incoming_values">A list of incoming values.</param>
        /// <returns>The classify result.</returns>
        public FirewallClassifyResult Classify(int layer_id, IEnumerable<FirewallValue> incoming_values)
        {
            return Classify(layer_id, incoming_values, true).Result;
        }

        /// <summary>
        /// Enumerate IPSEC key managers.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of registered key managers.</returns>
        public NtResult<IEnumerable<IPsecKeyManager>> EnumerateKeyManagers(bool throw_on_error)
        {
            NtStatus status = FirewallNativeMethods.IPsecKeyManagersGet0(_handle,
                out SafeFwpmMemoryBuffer entries, out int entry_count).MapDosErrorToStatus();
            if (!status.IsSuccess())
            {
                return status.CreateResultFromError<IEnumerable<IPsecKeyManager>>(throw_on_error);
            }

            using (entries)
            {
                List<IPsecKeyManager> ret = new List<IPsecKeyManager>();
                if (entry_count > 0)
                {
                    entries.Initialize<IntPtr>((uint)entry_count);
                    IntPtr[] ptrs = entries.ReadArray<IntPtr>(0, entry_count);
                    ret.AddRange(ptrs.Select(ptr => new IPsecKeyManager((IPSEC_KEY_MANAGER0)Marshal.PtrToStructure(ptr, typeof(IPSEC_KEY_MANAGER0)))));
                }
                return ret.AsReadOnly().CreateResult<IEnumerable<IPsecKeyManager>>();
            }
        }

        /// <summary>
        /// Enumerate IPSEC key managers.
        /// </summary>
        /// <returns>The list of registered key managers.</returns>
        public IEnumerable<IPsecKeyManager> EnumerateKeyManagers()
        {
            return EnumerateKeyManagers(true).Result;
        }

        /// <summary>
        /// Get key manager component security descriptor.
        /// </summary>
        /// <param name="security_information">The security information to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor.</returns>
        public NtResult<SecurityDescriptor> GetKeyManagerSecurityDescriptor(SecurityInformation security_information, bool throw_on_error)
        {
            return GetSecurityForKey(_handle, security_information, Guid.Empty, FirewallNativeMethods.IPsecKeyManagerGetSecurityInfoByKey0, throw_on_error);
        }

        /// <summary>
        /// Get key manager component security descriptor.
        /// </summary>
        /// <param name="security_information">The security information to query.</param>
        /// <returns>The security descriptor.</returns>
        public SecurityDescriptor GetKeyManagerSecurityDescriptor(SecurityInformation security_information)
        {
            return GetKeyManagerSecurityDescriptor(security_information, true).Result;
        }

        /// <summary>
        /// Open token from its modified ID.
        /// </summary>
        /// <param name="modified_id">The token's modified ID.</param>
        /// <param name="desired_access">The desired token access.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened token.</returns>
        public NtResult<NtToken> OpenToken(Luid modified_id, TokenAccessRights desired_access, bool throw_on_error)
        {
            return FirewallNativeMethods.FwpsOpenToken0(_handle, modified_id, desired_access, 
                out SafeKernelObjectHandle handle).CreateWin32Result(throw_on_error, () => new NtToken(handle));
        }

        /// <summary>
        /// Open token from its modified ID.
        /// </summary>
        /// <param name="modified_id">The token's modified ID.</param>
        /// <param name="desired_access">The desired token access.</param>
        /// <returns>The opened token.</returns>
        public NtToken OpenToken(Luid modified_id, TokenAccessRights desired_access)
        {
            return OpenToken(modified_id, desired_access, true).Result;
        }

        /// <summary>
        /// Enumerate all ALE endpoints.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of ALE endpoints.</returns>
        public NtResult<IEnumerable<FirewallAleEndpoint>> EnumerateAleEndpoints(bool throw_on_error)
        {
            Func<FWPS_ALE_ENDPOINT_PROPERTIES0, FirewallAleEndpoint> f = ProcessAleEndpoint;
            return EnumerateFwObjects(null, f, FirewallNativeMethods.FwpsAleEndpointCreateEnumHandle0,
                FirewallNativeMethods.FwpsAleEndpointEnum0, FirewallNativeMethods.FwpsAleEndpointDestroyEnumHandle0,
                throw_on_error).Map<IEnumerable<FirewallAleEndpoint>>(l => l.AsReadOnly());
        }

        /// <summary>
        /// Enumerate all ALE endpoints.
        /// </summary>
        /// <returns>The list of ALE endpoints.</returns>
        public IEnumerable<FirewallAleEndpoint> EnumerateAleEndpoints()
        {
            return EnumerateAleEndpoints(true).Result;
        }

        /// <summary>
        /// Get an ALE endpoint by its ID.
        /// </summary>
        /// <param name="id">The ID of the ALE endpoint.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The ALE endpoint.</returns>
        public NtResult<FirewallAleEndpoint> GetAleEndpoint(ulong id, bool throw_on_error)
        {
            return FirewallNativeMethods.FwpsAleEndpointGetById0(_handle, id, out SafeFwpmMemoryBuffer buffer)
                .CreateWin32Result(throw_on_error, () =>
                {
                    using (buffer)
                    {
                        return ProcessAleEndpoint((FWPS_ALE_ENDPOINT_PROPERTIES0)Marshal.PtrToStructure(
                            buffer.DangerousGetHandle(), typeof(FWPS_ALE_ENDPOINT_PROPERTIES0)));
                    }
                });
        }

        /// <summary>
        /// Get an ALE endpoint by its ID.
        /// </summary>
        /// <param name="id">The ID of the ALE endpoint.</param>
        /// <returns>The ALE endpoint.</returns>
        public FirewallAleEndpoint GetAleEndpoint(ulong id)
        {
            return GetAleEndpoint(id, true).Result;
        }

        /// <summary>
        /// Get the ALE endpoint security.
        /// </summary>
        /// <param name="security_information">The security information to query for.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor.</returns>
        public NtResult<SecurityDescriptor> GetAleEndpointSecurityDescriptor(SecurityInformation security_information, bool throw_on_error)
        {
            return GetSecurity(security_information, FirewallNativeMethods.FwpsAleEndpointGetSecurityInfo0, throw_on_error);
        }

        /// <summary>
        /// Get the ALE endpoint security.
        /// </summary>
        /// <param name="security_information">The security information to query for.</param>
        /// <returns>The security descriptor.</returns>
        public SecurityDescriptor GetAleEndpointSecurityDescriptor(SecurityInformation security_information)
        {
            return GetAleEndpointSecurityDescriptor(security_information, true).Result;
        }

        /// <summary>
        /// Begin a firewall transaction.
        /// </summary>
        /// <param name="flags">Flags for the transaction.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall transaction.</returns>
        /// <remarks>Disposing the transaction will cause it to abort. You should call Commit to use it.</remarks>
        public NtResult<FirewallTransaction> BeginTransaction(FirewallTransactionFlags flags, bool throw_on_error)
        {
            return FirewallNativeMethods.FwpmTransactionBegin0(_handle, flags).CreateWin32Result(throw_on_error, () => new FirewallTransaction(_handle));
        }

        /// <summary>
        /// Begin a firewall transaction.
        /// </summary>
        /// <param name="flags">Flags for the transaction.</param>
        /// <returns>The firewall transaction.</returns>
        /// <remarks>Disposing the transaction will cause it to abort. You should call Commit to use it.</remarks>
        public FirewallTransaction BeginTransaction(FirewallTransactionFlags flags)
        {
            return BeginTransaction(flags, true).Result;
        }

        /// <summary>
        /// Begin a read/write firewall transaction.
        /// </summary>
        /// <returns>The firewall transaction.</returns>
        /// <remarks>Disposing the transaction will cause it to abort. You should call Commit to use it.</remarks>
        public FirewallTransaction BeginTransaction()
        {
            return BeginTransaction(FirewallTransactionFlags.None);
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

        bool INtObjectSecurity.IsContainer => true;

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
