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

using NtApiDotNet.Win32.AppModel;
using NtApiDotNet.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// A class which represents an AppContainer profile.
    /// </summary>
    public sealed class AppContainerProfile : IDisposable
    {
        #region Constructors
        private AppContainerProfile(string name, Sid sid, IEnumerable<Sid> capabilities, 
            string display_name, string description)
        {
            Name = name;
            Sid = sid;
            _key_path = new Lazy<string>(GetKeyPath);
            Capabilities = (capabilities?.ToList() ?? new List<Sid>()).AsReadOnly();
            DisplayName = display_name ?? string.Empty;
            Description = description ?? string.Empty;
        }

        private AppContainerProfile(string name)
            : this(name, TokenUtils.DerivePackageSidFromName(name), null, null, null)
        {
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Create a new AppContainerProfile.
        /// </summary>
        /// <param name="appcontainer_name">The name of the AppContainer.</param>
        /// <param name="display_name">A display name.</param>
        /// <param name="description">An optional description.</param>
        /// <param name="capabilities">An optional list of capability SIDs.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created AppContainer profile.</returns>
        /// <remarks>If the profile already exists then it'll be opened instead.</remarks>
        public static NtResult<AppContainerProfile> Create(
                string appcontainer_name,
                string display_name,
                string description,
                IEnumerable<Sid> capabilities,
                bool throw_on_error)
        {
            using (var resources = new DisposableList())
            {
                var caps = resources.CreateSidAndAttributes(capabilities);
                NtStatus status = Win32NativeMethods.CreateAppContainerProfile(appcontainer_name, display_name, description,
                    caps.Length > 0 ? caps : null, caps.Length, out SafeSidBufferHandle sid);
                if (status == NtObjectUtils.MapDosErrorToStatus(Win32Error.ERROR_ALREADY_EXISTS))
                {
                    return new AppContainerProfile(appcontainer_name).CreateResult();
                }
                resources.AddResource(sid);
                return status.CreateResult(throw_on_error, () =>
                    {
                        using (sid)
                        {
                            return new AppContainerProfile(appcontainer_name, sid.ToSid(), 
                                capabilities, display_name, description);
                        }
                    });
            }
        }

        /// <summary>
        /// Create a new AppContainerProfile.
        /// </summary>
        /// <param name="appcontainer_name">The name of the AppContainer.</param>
        /// <param name="display_name">A display name.</param>
        /// <param name="description">An optional description.</param>
        /// <param name="capabilities">An optional list of capability SIDs.</param>
        /// <returns>The created AppContainer profile.</returns>
        /// <remarks>If the profile already exists then it'll be opened instead.</remarks>
        public static AppContainerProfile Create(
                string appcontainer_name,
                string display_name = "DisplayName",
                string description = "Description",
                IEnumerable<Sid> capabilities = null)
        {
            return Create(appcontainer_name, display_name, description, capabilities, true).Result;
        }

        /// <summary>
        /// Create a temporary AppContainer profile.
        /// </summary>
        /// <param name="capabilities">List of capabilities for the AppContainer profile.</param>
        /// <returns>The created AppContainer profile.</returns>
        /// <remarks>The profile will be marked to DeleteOnClose. In order to not leak the profile you
        /// should wait till the process has exited and dispose this profile.</remarks>
        public static AppContainerProfile CreateTemporary(IEnumerable<Sid> capabilities)
        {
            string name = "tmp_" + Guid.NewGuid().ToString("N");
            var profile = Create(name, capabilities: capabilities);
            profile.DeleteOnClose = true;
            return profile;
        }

        /// <summary>
        /// Create a temporary AppContainer profile.
        /// </summary>
        /// <returns>The created AppContainer profile.</returns>
        /// <remarks>The profile will be marked to DeleteOnClose. In order to not leak the profile you
        /// should wait till the process has exited and dispose this profile.</remarks>
        public static AppContainerProfile CreateTemporary()
        {
            return CreateTemporary(null);
        }

        /// <summary>
        /// Opens an AppContainerProfile.
        /// </summary>
        /// <param name="appcontainer_name">The name of the AppContainer.</param>
        /// <param name="throw_on_error">True to throw no error.</param>
        /// <returns>The opened AppContainer profile.</returns>
        /// <remarks>This method doesn't check the profile exists.</remarks>
        public static NtResult<AppContainerProfile> Open(
                string appcontainer_name, bool throw_on_error)
        {
            var sid = TokenUtils.DerivePackageSidFromName(appcontainer_name, throw_on_error);
            if (!sid.IsSuccess)
            {
                return sid.Cast<AppContainerProfile>();
            }
            return new AppContainerProfile(appcontainer_name, sid.Result, null, null, null).CreateResult();
        }

        /// <summary>
        /// Opens an AppContainerProfile.
        /// </summary>
        /// <param name="appcontainer_name">The name of the AppContainer.</param>
        /// <returns>The opened AppContainer profile.</returns>
        /// <remarks>This method doesn't check the profile exists.</remarks>
        public static AppContainerProfile Open(
                string appcontainer_name)
        {
            return new AppContainerProfile(appcontainer_name);
        }

        /// <summary>
        /// Opens an AppContainerProfile and checks it exists.
        /// </summary>
        /// <param name="appcontainer_name">The name of the AppContainer.</param>
        /// <param name="throw_on_error">True to throw no error.</param>
        /// <returns>The opened AppContainer profile.</returns>
        /// <remarks>This checks for the existence of the profile and also populates the additional information.</remarks>
        public static NtResult<AppContainerProfile> OpenExisting(
                string appcontainer_name, bool throw_on_error)
        {
            var sid = TokenUtils.DerivePackageSidFromName(appcontainer_name, throw_on_error);
            if (!sid.IsSuccess)
                return sid.Cast<AppContainerProfile>();

            var ret = GetAppContainerProfiles(throw_on_error);
            if (!ret.IsSuccess)
                return ret.Cast<AppContainerProfile>();

            var profile = ret.Result.FirstOrDefault(p => p.Sid == sid.Result);
            if (profile == null)
                return NtStatus.STATUS_NOT_FOUND.CreateResultFromError<AppContainerProfile>(throw_on_error);
            return profile.CreateResult();
        }

        /// <summary>
        /// Opens an AppContainerProfile and checks it exists.
        /// </summary>
        /// <param name="appcontainer_name">The name of the AppContainer.</param>
        /// <returns>The opened AppContainer profile.</returns>
        /// <remarks>This checks for the existence of the profile and also populates the additional information.</remarks>
        public static AppContainerProfile OpenExisting(string appcontainer_name)
        {
            return OpenExisting(appcontainer_name, true).Result;
        }

        /// <summary>
        /// Delete an existing profile.
        /// </summary>
        /// <param name="appcontainer_name">The AppContainer name.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The HRESULT from the delete operation.</returns>
        public static NtStatus Delete(string appcontainer_name, bool throw_on_error)
        {
            return Win32NativeMethods.DeleteAppContainerProfile(appcontainer_name).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Delete an existing profile.
        /// </summary>
        /// <param name="appcontainer_name">The AppContainer name.</param>
        public static void Delete(string appcontainer_name)
        {
            Delete(appcontainer_name, true);
        }

        /// <summary>
        /// Enumerate all AppContainer profiles.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of appcontainer profiles.</returns>
        public static NtResult<IEnumerable<AppContainerProfile>> GetAppContainerProfiles(bool throw_on_error)
        {
            var error = AppModelNativeMethods.NetworkIsolationEnumAppContainers(NETISO_FLAG.NONE, out int count, out IntPtr acs);
            if (error != Win32Error.SUCCESS)
            {
                return error.CreateResultFromDosError<IEnumerable<AppContainerProfile>>(throw_on_error);
            }
            try
            {
                var profiles = new Dictionary<Sid, AppContainerProfile>();
                var array = NtProcess.Current.ReadMemoryArray<INET_FIREWALL_APP_CONTAINER>(acs.ToInt64(), count);
                foreach (var a in array)
                {
                    Sid package_sid = new Sid(a.appContainerSid);
                    if (profiles.ContainsKey(package_sid))
                        continue;
                    profiles.Add(package_sid, new AppContainerProfile(a.appContainerName, package_sid, 
                        GetCapabilities(package_sid, a.capabilities), a.displayName, a.description));
                }
                return profiles.Values.CreateResult().Cast<IEnumerable<AppContainerProfile>>();
            }
            finally
            {
                if (acs != IntPtr.Zero)
                    AppModelNativeMethods.NetworkIsolationFreeAppContainers(acs);
            }
        }

        /// <summary>
        /// Enumerate all AppContainer profiles.
        /// </summary>
        /// <returns>The list of appcontainer profiles.</returns>
        public static IEnumerable<AppContainerProfile> GetAppContainerProfiles()
        {
            return GetAppContainerProfiles(true).Result;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Delete an existing profile.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The HRESULT from the delete operation.</returns>
        public NtStatus Delete(bool throw_on_error)
        {
            return Delete(Name, throw_on_error);
        }

        /// <summary>
        /// Delete an existing profile.
        /// </summary>
        public void Delete()
        {
            Delete(false);
        }

        /// <summary>
        /// Dispose of the AppContainer profile. If DeleteOnClose is set then the profile will be deleted.
        /// </summary>
        public void Dispose()
        {
            if (DeleteOnClose)
            {
                Delete(Name, false);
            }
        }

        /// <summary>
        /// Close an AppContainer profile. If DeleteOnClose is set then the profile will be deleted.
        /// </summary>
        public void Close()
        {
            Dispose();
        }

        /// <summary>
        /// Open the AppContainer key.
        /// </summary>
        /// <param name="desired_access">The desired access for the key.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened key.</returns>
        public NtResult<NtKey> OpenKey(KeyAccessRights desired_access, bool throw_on_error)
        {
            using (var result = TokenUtils.CreateAppContainerToken(null, Sid, new Sid[0], throw_on_error))
            {
                if (!result.IsSuccess)
                    return result.Cast<NtKey>();
                using (var imp = result.Result.Impersonate(SecurityImpersonationLevel.Impersonation))
                {
                    return Win32NativeMethods.GetAppContainerRegistryLocation(desired_access, out SafeKernelObjectHandle key)
                        .CreateResult(throw_on_error, () => new NtKey(key, KeyDisposition.OpenedExistingKey, false));
                }
            }
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// The AppContainer name.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The package SID 
        /// </summary>
        public Sid Sid { get; }

        /// <summary>
        /// Path to the AppContainer profile directory.
        /// </summary>
        public string Path
        {
            get
            {
                if (Win32NativeMethods.GetAppContainerFolderPath(Sid.ToString(), out SafeCoTaskMemBuffer path).IsSuccess())
                {
                    using (path)
                    {
                        return path.ReadNulTerminatedUnicodeStringUnsafe();
                    }
                }
                return string.Empty;
            }
        }

        /// <summary>
        /// Path to the AppContainer key.
        /// </summary>
        public string KeyPath => _key_path.Value;

        /// <summary>
        /// Set to true to delete the profile when closed.
        /// </summary>
        public bool DeleteOnClose { get; set; }

        /// <summary>
        /// Get list of capabilities assigned to this AppContainer profile.
        /// </summary>
        public IReadOnlyList<Sid> Capabilities { get; }

        /// <summary>
        /// The display name for the AppContainer profile.
        /// </summary>
        public string DisplayName { get; }

        /// <summary>
        /// The description for the AppContainer profile.
        /// </summary>
        public string Description { get; }

        #endregion

        #region Private Members
        private readonly Lazy<string> _key_path;

        private string GetKeyPath()
        {
            using (var key = OpenKey(KeyAccessRights.MaximumAllowed, false))
            {
                if (!key.IsSuccess)
                    return string.Empty;
                return key.Result.Win32Path;
            }
        }

        private static Sid[] GetCapabilities(Sid package_sid, INET_FIREWALL_AC_CAPABILITIES caps)
        {
            Sid package_cap = new Sid(SecurityAuthority.Package, 3).CreateRelative(package_sid.SubAuthorities.Skip(1).ToArray());

            if (caps.count == 0)
                return new Sid[0];

            return NtProcess.Current.ReadMemoryArray<SidAndAttributes>(caps.capabilities.ToInt64(), 
                caps.count).Select(s => new Sid(s.Sid)).Where(s => s != package_cap).ToArray();
        }

        #endregion
    }
}
