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

using NtApiDotNet.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// A class which represents an AppContainer profile.
    /// </summary>
    public sealed class AppContainerProfile : IDisposable
    {
        #region Constructors
        private AppContainerProfile(string name, Sid sid)
        {
            Name = name;
            Sid = sid;
        }

        private AppContainerProfile(string name)
            : this(name, TokenUtils.DerivePackageSidFromName(name))
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
                            return new AppContainerProfile(appcontainer_name, sid.ToSid());
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
        /// <returns>The created AppContainer profile.</returns>
        /// <remarks>The profile will be marked to DeleteOnClose. In order to not leak the profile you
        /// should wait till the process has exited and dispose this profile.</remarks>
        public static AppContainerProfile CreateTemporary()
        {
            string name = "tmp_" + Guid.NewGuid().ToString("N");
            var profile = Create(name);
            profile.DeleteOnClose = true;
            return profile;
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
            return new AppContainerProfile(appcontainer_name, sid.Result).CreateResult();
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
        /// Path to the AppContainer profile.
        /// </summary>
        public string Path
        {
            get
            {
                if (Win32NativeMethods.GetAppContainerFolderPath(Sid.ToString(), out SafeCoTaskMemHandle path).IsSuccess())
                {
                    using (path)
                    {
                        return Marshal.PtrToStringUni(path.DangerousGetHandle());
                    }
                }
                return string.Empty;
            }
        }

        /// <summary>
        /// Set to true to delete the profile when closed.
        /// </summary>
        public bool DeleteOnClose { get; set; }

        #endregion
    }
}
