//  Copyright 2016 Google Inc. All Rights Reserved.
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

using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent an NT Key object
    /// </summary>
    [NtType("Key")]
    public class NtKey : NtObjectWithDuplicateAndInfo<NtKey, KeyAccessRights, KeyInformationClass, KeySetInformationClass>
    {
        #region Constructors
        internal NtKey(SafeKernelObjectHandle handle, KeyDisposition disposition, bool predefined_handle) : base(handle)
        {
            Disposition = disposition;
            PredefinedHandle = predefined_handle;
        }

        internal NtKey(SafeKernelObjectHandle handle) : this(handle, KeyDisposition.OpenedExistingKey, false)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtKey> OpenInternal(ObjectAttributes obj_attributes,
                KeyAccessRights desired_access, bool throw_on_error)
            {
                return NtKey.Open(obj_attributes, desired_access, 0, throw_on_error);
            }
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Load a new hive
        /// </summary>
        /// <param name="destination">The destination path</param>
        /// <param name="filename">The path to the hive</param>
        /// <param name="flags">Load flags</param>
        /// <returns>The opened root key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey LoadKey(string destination, string filename, LoadKeyFlags flags)
        {
            using (ObjectAttributes dest = new ObjectAttributes(destination, AttributeFlags.CaseInsensitive))
            {
                using (ObjectAttributes name = new ObjectAttributes(filename, AttributeFlags.CaseInsensitive))
                {
                    return LoadKey(dest, name, flags, KeyAccessRights.MaximumAllowed);
                }
            }
        }

        /// <summary>
        /// Load a new hive
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="file_obj_attr">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <returns>The opened root key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey LoadKey(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr, LoadKeyFlags flags, KeyAccessRights desired_access)
        {
            return LoadKey(key_obj_attr, file_obj_attr, flags, desired_access, true).Result;
        }

        /// <summary>
        /// Load a new hive
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="file_obj_attr">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="trust_key">Key that this hive will be trusted for.</param>
        /// <param name="key_event">Event handle for key load.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtKey> LoadKey(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr,
            LoadKeyFlags flags, KeyAccessRights desired_access, NtKey trust_key, NtEvent key_event, bool throw_on_error)
        {
            return LoadKey(key_obj_attr, file_obj_attr, flags, desired_access, trust_key, key_event, false, throw_on_error);
        }

        /// <summary>
        /// Load a new hive and do not open the root key.
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="file_obj_attr">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="trust_key">Key that this hive will be trusted for.</param>
        /// <param name="key_event">Event handle for key load.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus LoadKeyNoOpen(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr,
            LoadKeyFlags flags, NtKey trust_key, NtEvent key_event, bool throw_on_error)
        {
            using (var result = LoadKey(key_obj_attr, file_obj_attr, flags, 
                KeyAccessRights.MaximumAllowed, trust_key, key_event, true, throw_on_error))
            {
                return result.Status;
            }
        }

        /// <summary>
        /// Load a new hive
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="file_obj_attr">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="trust_key">Key that this hive will be trusted for.</param>
        /// <param name="key_event">Event handle for key load.</param>
        /// <returns>The opened key.</returns>
        public static NtKey LoadKey(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr,
            LoadKeyFlags flags, KeyAccessRights desired_access, NtKey trust_key, NtEvent key_event)
        {
            return LoadKey(key_obj_attr, file_obj_attr, flags, desired_access, trust_key, key_event, true).Result;
        }

        /// <summary>
        /// Load a new hive and do not open the root key.
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="file_obj_attr">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="trust_key">Key that this hive will be trusted for.</param>
        /// <param name="key_event">Event handle for key load.</param>
        public static void LoadKeyNoOpen(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr,
            LoadKeyFlags flags, NtKey trust_key, NtEvent key_event)
        {
            LoadKeyNoOpen(key_obj_attr, file_obj_attr, flags, trust_key, key_event, true);
        }

        /// <summary>
        /// Load a new hive
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="file_obj_attr">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtKey> LoadKey(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr,
            LoadKeyFlags flags, KeyAccessRights desired_access, bool throw_on_error)
        {
            return LoadKey(key_obj_attr, file_obj_attr, flags, desired_access, null, null, throw_on_error);
        }

        /// <summary>
        /// Load a new hive
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="file_obj_attr">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="token">Token to open the hive files under.</param>
        /// <param name="trust_key">Key that this hive will be trusted for.</param>
        /// <param name="key_event">Event handle for key load.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtKey> LoadKey(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr,
            LoadKeyFlags flags, KeyAccessRights desired_access, NtKey trust_key, NtEvent key_event, NtToken token, bool throw_on_error)
        {
            return LoadKey(key_obj_attr, file_obj_attr, flags, desired_access, trust_key, key_event, token, false, throw_on_error);
        }

        /// <summary>
        /// Load a new hive and do not open the root key.
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="file_obj_attr">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="token">Token to open the hive files under.</param>
        /// <param name="trust_key">Key that this hive will be trusted for.</param>
        /// <param name="key_event">Event handle for key load.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus LoadKeyNoOpen(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr,
            LoadKeyFlags flags, NtKey trust_key, NtEvent key_event, NtToken token, bool throw_on_error)
        {
            using (var result = LoadKey(key_obj_attr, file_obj_attr, flags, 
                KeyAccessRights.MaximumAllowed, trust_key, key_event, token, true, throw_on_error))
            {
                return result.Status;
            }
        }

        /// <summary>
        /// Load a new hive
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="file_obj_attr">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="token">Token to open the hive files under.</param>
        /// <param name="trust_key">Key that this hive will be trusted for.</param>
        /// <param name="key_event">Event handle for key load.</param>
        /// <returns>The loaded key.</returns>
        public static NtKey LoadKey(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr,
            LoadKeyFlags flags, KeyAccessRights desired_access, NtKey trust_key, NtEvent key_event, NtToken token)
        {
            return LoadKey(key_obj_attr, file_obj_attr, flags, desired_access, trust_key, key_event, token, true).Result;
        }

        /// <summary>
        /// Load a new hive and do not open the root key.
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="file_obj_attr">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="token">Token to open the hive files under.</param>
        /// <param name="trust_key">Key that this hive will be trusted for.</param>
        /// <param name="key_event">Event handle for key load.</param>
        public static void LoadKeyNoOpen(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr,
            LoadKeyFlags flags, NtKey trust_key, NtEvent key_event, NtToken token)
        {
            LoadKeyNoOpen(key_obj_attr, file_obj_attr, flags, trust_key, key_event, token, true);
        }

        /// <summary>
        /// Unload an existing hive.
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="flags">Unload flags</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus UnloadKey(ObjectAttributes key_obj_attr, UnloadKeyFlags flags, bool throw_on_error)
        {
            return NtSystemCalls.NtUnloadKey2(key_obj_attr, flags).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Unload an existing hive.
        /// </summary>
        /// <param name="key">Path to key to unload.</param>
        /// <param name="flags">Unload flags</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static void UnloadKey(string key, UnloadKeyFlags flags)
        {
            using (var obj_attr = new ObjectAttributes(key, AttributeFlags.CaseInsensitive))
            {
                UnloadKey(obj_attr, flags, true);
            }
        }

        /// <summary>
        /// Unload an existing hive.
        /// </summary>
        /// <param name="key">Path to key to unload.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static void UnloadKey(string key)
        {
            UnloadKey(key, UnloadKeyFlags.None);
        }

        /// <summary>
        /// Create a new Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="options">Create options</param>
        /// <param name="transaction">Optional transaction object.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtKey> Create(ObjectAttributes obj_attributes, KeyAccessRights desired_access, KeyCreateOptions options, INtTransaction transaction, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            KeyDisposition disposition;
            NtStatus status;

            if (transaction != null)
            {
                status = NtSystemCalls.NtCreateKeyTransacted(out handle, desired_access, obj_attributes, 0, null, options, transaction.Handle, out disposition);
            }
            else
            {
                status = NtSystemCalls.NtCreateKey(out handle, desired_access, obj_attributes, 0, null, options, out disposition);
            }
            return status.CreateResult(throw_on_error, s => new NtKey(handle, disposition, s == NtStatus.STATUS_PREDEFINED_HANDLE));
        }

        /// <summary>
        /// Create a new Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="options">Create options</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtKey> Create(ObjectAttributes obj_attributes, KeyAccessRights desired_access, KeyCreateOptions options, bool throw_on_error)
        {
            return Create(obj_attributes, desired_access, options, null, throw_on_error);
        }

        /// <summary>
        /// Create a new Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="options">Create options</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey Create(ObjectAttributes obj_attributes, KeyAccessRights desired_access, KeyCreateOptions options)
        {
            return Create(obj_attributes, desired_access, options, null);
        }

        /// <summary>
        /// Create a new Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="options">Create options</param>
        /// <param name="transaction">Optional transaction object.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtKey Create(ObjectAttributes obj_attributes, KeyAccessRights desired_access, KeyCreateOptions options, INtTransaction transaction)
        {
            return Create(obj_attributes, desired_access, options, transaction, true).Result;
        }

        /// <summary>
        /// Create a new Key
        /// </summary>
        /// <param name="key_name">Path to the key to create</param>
        /// <param name="root">Root key if key_name is relative</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="options">Create options</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey Create(string key_name, NtObject root, KeyAccessRights desired_access, KeyCreateOptions options)
        {
            using (ObjectAttributes obja = new ObjectAttributes(key_name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, desired_access, options);
            }
        }

        /// <summary>
        /// Try and open a Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="open_options">Open options.</param>
        /// <param name="transaction">Optional transaction object.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtKey> Open(ObjectAttributes obj_attributes, KeyAccessRights desired_access, KeyCreateOptions open_options, INtTransaction transaction, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            NtStatus status;
            if (transaction != null)
            {
                status = NtSystemCalls.NtOpenKeyTransactedEx(out handle, desired_access, obj_attributes, open_options, transaction.Handle);
            }
            else
            {
                status = NtSystemCalls.NtOpenKeyEx(out handle, desired_access, obj_attributes, open_options);
            }
            return status.CreateResult(throw_on_error, s => new NtKey(handle, KeyDisposition.OpenedExistingKey, s == NtStatus.STATUS_PREDEFINED_HANDLE));
        }

        /// <summary>
        /// Try and open a Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="open_options">Open options.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtKey> Open(ObjectAttributes obj_attributes, KeyAccessRights desired_access, KeyCreateOptions open_options, bool throw_on_error)
        {
            return Open(obj_attributes, desired_access, open_options, null, throw_on_error);
        }

        /// <summary>
        /// Try and open a Key
        /// </summary>
        /// <param name="key_name">Path to the key to open</param>
        /// <param name="root">Root key if key_name is relative</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="open_options">Open options.</param>
        /// <param name="transaction">Optional transaction object.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtKey> Open(string key_name, NtObject root, KeyAccessRights desired_access, KeyCreateOptions open_options, INtTransaction transaction, bool throw_on_error)
        {
            using (ObjectAttributes obja = new ObjectAttributes(key_name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access, open_options, transaction, throw_on_error);
            }
        }

        /// <summary>
        /// Try and open a Key
        /// </summary>
        /// <param name="key_name">Path to the key to open</param>
        /// <param name="root">Root key if key_name is relative</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="open_options">Open options.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtKey> Open(string key_name, NtObject root, KeyAccessRights desired_access, KeyCreateOptions open_options, bool throw_on_error)
        {
            return Open(key_name, root, desired_access, open_options, null, throw_on_error);
        }

        /// <summary>
        /// Open a Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="open_options">Open options.</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey Open(ObjectAttributes obj_attributes, KeyAccessRights desired_access, KeyCreateOptions open_options)
        {
            return Open(obj_attributes, desired_access, open_options, null);
        }

        /// <summary>
        /// Open a Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="open_options">Open options.</param>
        /// <param name="transaction">Optional transaction object.</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey Open(ObjectAttributes obj_attributes, KeyAccessRights desired_access, KeyCreateOptions open_options, INtTransaction transaction)
        {
            return Open(obj_attributes, desired_access, open_options, transaction, true).Result;
        }

        /// <summary>
        /// Open a Key
        /// </summary>
        /// <param name="key_name">Path to the key to open</param>
        /// <param name="root">Root key if key_name is relative</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey Open(string key_name, NtObject root, KeyAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(key_name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access, 0);
            }
        }

        /// <summary>
        /// Query a license value. While technically not directly a registry key
        /// it has many of the same properties such as using the same registry
        /// value types.
        /// </summary>
        /// <param name="name">The name of the license value.</param>
        /// <param name="throw_on_error">True to throw an exception on error</param>
        /// <returns>The license value key</returns>
        public static NtResult<NtKeyValue> QueryLicenseValue(string name, bool throw_on_error)
        {
            UnicodeString name_string = new UnicodeString(name);
            NtStatus status = NtSystemCalls.NtQueryLicenseValue(name_string, out RegistryValueType type, SafeHGlobalBuffer.Null, 0, out int ret_length);
            if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
            {
                return status.CreateResultFromError<NtKeyValue>(throw_on_error);
            }

            using (var buffer = new SafeHGlobalBuffer(ret_length))
            {
                return NtSystemCalls.NtQueryLicenseValue(name_string, out type, buffer, buffer.Length, out ret_length)
                    .CreateResult(throw_on_error, () => new NtKeyValue(name, type, buffer.ToArray(), 0));
            }
        }

        /// <summary>
        /// Query a license value. While technically not directly a registry key
        /// it has many of the same properties such as using the same registry
        /// value types.
        /// </summary>
        /// <param name="name">The name of the license value.</param>
        /// <returns>The license value key</returns>
        public static NtKeyValue QueryLicenseValue(string name)
        {
            return QueryLicenseValue(name, true).Result;
        }

        /// <summary>
        /// Create a registry key symbolic link
        /// </summary>
        /// <param name="rootkey">Root key if path is relative</param>
        /// <param name="path">Path to the key to create</param>
        /// <param name="target">Target resistry path</param>
        /// <returns>The created symbolic link key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey CreateSymbolicLink(string path, NtKey rootkey, string target)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path,
                AttributeFlags.CaseInsensitive | AttributeFlags.OpenIf | AttributeFlags.OpenLink, rootkey))
            {
                using (NtKey key = Create(obja, KeyAccessRights.MaximumAllowed, KeyCreateOptions.CreateLink))
                {
                    try
                    {
                        key.SetSymbolicLinkTarget(target);
                        return key.Duplicate();
                    }
                    catch
                    {
                        key.Delete();
                        throw;
                    }
                }
            }
        }

        /// <summary>
        /// Open the machine key
        /// </summary>
        /// <returns>The opened key with the maximum access allowed.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey GetMachineKey()
        {
            return GetMachineKey(true).Result;
        }

        /// <summary>
        /// Open the machine key
        /// </summary>
        /// <returns>The opened key with the maximum access allowed.</returns>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtKey> GetMachineKey(bool throw_on_error)
        {
            return Open(@"\Registry\Machine", null, KeyAccessRights.MaximumAllowed, KeyCreateOptions.NonVolatile, throw_on_error);
        }

        /// <summary>
        /// Open the user key
        /// </summary>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey GetUserKey()
        {
            return GetUserKey(true).Result;
        }

        /// <summary>
        /// Open the user key
        /// </summary>
        /// <returns>The opened key with the maximum access allowed.</returns>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtKey> GetUserKey(bool throw_on_error)
        {
            return Open(@"\Registry\User", null, KeyAccessRights.MaximumAllowed, KeyCreateOptions.NonVolatile, throw_on_error);
        }

        /// <summary>
        /// Open a specific user key
        /// </summary>
        /// <param name="sid">The SID of the user to open</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey GetUserKey(Sid sid)
        {
            return GetUserKey(sid, true).Result;
        }

        /// <summary>
        /// Open the user key
        /// </summary>
        /// <param name="sid">The SID of the user to open</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened key with the maximum access allowed.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtKey> GetUserKey(Sid sid, bool throw_on_error)
        {
            return Open(@"\Registry\User\" + sid, null, KeyAccessRights.MaximumAllowed, KeyCreateOptions.NonVolatile, throw_on_error);
        }

        /// <summary>
        /// Open the current user key
        /// </summary>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey GetCurrentUserKey()
        {
            return GetCurrentUserKey(true).Result;
        }

        /// <summary>
        /// Open the current user key
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened key with the maximum access allowed.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtKey> GetCurrentUserKey(bool throw_on_error)
        {
            var user = NtToken.GetCurrentUser(throw_on_error);
            if (!user.IsSuccess)
                return user.Cast<NtKey>();

            return GetUserKey(user.Result.Sid, throw_on_error);
        }

        /// <summary>
        /// Open the root key
        /// </summary>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey GetRootKey()
        {
            return GetRootKey(true).Result;
        }

        /// <summary>
        /// Open the root key
        /// </summary>
        /// <returns>The opened key with the maximum access allowed.</returns>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtKey> GetRootKey(bool throw_on_error)
        {
            return Open(@"\Registry", null, KeyAccessRights.MaximumAllowed, KeyCreateOptions.NonVolatile, throw_on_error);
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Create a new Key
        /// </summary>
        /// <param name="key_name">Path to the key to create</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtKey Create(string key_name)
        {
            return Create(key_name, this, KeyAccessRights.MaximumAllowed, KeyCreateOptions.NonVolatile);
        }

        /// <summary>
        /// Create a new Key
        /// </summary>
        /// <param name="key_name">Path to the key to create</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="options">Create options</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtKey Create(string key_name, KeyAccessRights desired_access, KeyCreateOptions options)
        {
            return Create(key_name, this, desired_access, options);
        }

        /// <summary>
        /// Delete the key
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        public NtStatus Delete(bool throw_on_error)
        {
            return NtSystemCalls.NtDeleteKey(Handle).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Delete the key
        /// </summary>
        public void Delete()
        {
            Delete(true);
        }

        /// <summary>
        /// Set a resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="type">The type of the value</param>
        /// <param name="data">The raw value data</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The NT status code.</returns>
        public NtStatus SetValue(string value_name, RegistryValueType type, byte[] data, bool throw_on_error)
        {
            return NtSystemCalls.NtSetValueKey(Handle, new UnicodeString(value_name ?? string.Empty),
                0, type, data, data.Length).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Set a resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="type">The type of the value</param>
        /// <param name="data">The raw value data</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetValue(string value_name, RegistryValueType type, byte[] data)
        {
            SetValue(value_name, type, data, true);
        }

        /// <summary>
        /// Set a string resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="type">The type of the value</param>
        /// <param name="data">The value data</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The NT status code.</returns>
        public NtStatus SetValue(string value_name, RegistryValueType type, string data, bool throw_on_error)
        {
            return SetValue(value_name, type, Encoding.Unicode.GetBytes(data), throw_on_error);
        }

        /// <summary>
        /// Set a string resistry value as REG_SZ.
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="data">The value data</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The NT status code.</returns>
        public NtStatus SetValue(string value_name, string data, bool throw_on_error)
        {
            return SetValue(value_name, RegistryValueType.String, data, throw_on_error);
        }

        /// <summary>
        /// Set a string resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="type">The type of the value</param>
        /// <param name="data">The value data</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetValue(string value_name, RegistryValueType type, string data)
        {
            SetValue(value_name, type, data, true);
        }

        /// <summary>
        /// Set a string resistry value as REG_SZ.
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="data">The value data</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetValue(string value_name, string data)
        {
            SetValue(value_name, data, true);
        }

        /// <summary>
        /// Set a list of strings as a resistry value.
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="data">The list of strings to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The NT status code.</returns>
        public NtStatus SetValue(string value_name, IEnumerable<string> data, bool throw_on_error)
        {
            string value = string.Join("\0", data) + "\0\0";

            return SetValue(value_name, RegistryValueType.MultiString, value, throw_on_error);
        }

        /// <summary>
        /// Set a list of strings as a resistry value.
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="data">The list of strings to set.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetValue(string value_name, IEnumerable<string> data)
        {
            SetValue(value_name, data, true);
        }

        /// <summary>
        /// Set a DWORD resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="data">The value data</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The NT status code.</returns>
        public NtStatus SetValue(string value_name, uint data, bool throw_on_error)
        {
            return SetValue(value_name, RegistryValueType.Dword, BitConverter.GetBytes(data), throw_on_error);
        }

        /// <summary>
        /// Set a DWORD resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="data">The value data</param>
        /// <param name="big_endian">True to set the value of big endian.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The NT status code.</returns>
        public NtStatus SetValue(string value_name, bool big_endian, uint data, bool throw_on_error)
        {
            byte[] ba = BitConverter.GetBytes(data);
            if (big_endian)
            {
                ba = ba.Reverse().ToArray();
            }
            return SetValue(value_name, big_endian ? RegistryValueType.DwordBigEndian : RegistryValueType.Dword, ba, throw_on_error);
        }

        /// <summary>
        /// Set a QWORD resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="data">The value data</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The NT status code.</returns>
        public NtStatus SetValue(string value_name, ulong data, bool throw_on_error)
        {
            return SetValue(value_name, RegistryValueType.Qword, BitConverter.GetBytes(data), throw_on_error);
        }

        /// <summary>
        /// Set a DWORD resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="data">The value data</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetValue(string value_name, uint data)
        {
            SetValue(value_name, data, true);
        }

        /// <summary>
        /// Set a DWORD resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="data">The value data</param>
        /// <param name="big_endian">True to set the value of big endian.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetValue(string value_name, bool big_endian, uint data)
        {
            SetValue(value_name, big_endian, data, true);
        }

        /// <summary>
        /// Set a QWORD resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="data">The value data</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetValue(string value_name, ulong data)
        {
            SetValue(value_name, data, true);
        }

        /// <summary>
        /// Delete a registry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The NT status code.</returns>
        public NtStatus DeleteValue(string value_name, bool throw_on_error)
        {
            return NtSystemCalls.NtDeleteValueKey(Handle, new UnicodeString(value_name ?? string.Empty)).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Delete a registry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void DeleteValue(string value_name)
        {
            DeleteValue(value_name, true);
        }

        /// <summary>
        /// Query a value by name
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The value information</returns>
        public NtResult<NtKeyValue> QueryValue(string value_name, bool throw_on_error)
        {
            UnicodeString name = new UnicodeString(value_name);
            int return_len = 0;
            int query_count = 0;

            while (query_count++ < 64)
            {
                using (var info = new SafeStructureInOutBuffer<KeyValuePartialInformation>(return_len, false))
                {
                    NtStatus status = NtSystemCalls.NtQueryValueKey(Handle, name, KeyValueInformationClass.KeyValuePartialInformation,
                        info, info.Length, out return_len);
                    if (status == NtStatus.STATUS_BUFFER_OVERFLOW || status == NtStatus.STATUS_BUFFER_TOO_SMALL)
                    {
                        continue;
                    }

                    return status.CreateResult(throw_on_error, () =>
                    {
                        KeyValuePartialInformation result = info.Result;
                        return new NtKeyValue(value_name, info.Result.Type,
                                    info.Data.ReadBytes(result.DataLength), result.TitleIndex);
                    });
                }
            }
            return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<NtKeyValue>(throw_on_error);
        }

        /// <summary>
        /// Query a value by name
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <returns>The value information</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtKeyValue QueryValue(string value_name)
        {
            return QueryValue(value_name, true).Result;
        }

        /// <summary>
        /// Query all values for this key
        /// </summary>
        /// <returns>A list of values</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<NtKeyValue> QueryValues()
        {
            int index = 0;
            using (SafeStructureInOutBuffer<KeyValueFullInformation> value_info = new SafeStructureInOutBuffer<KeyValueFullInformation>(512, true))
            {
                while (true)
                {
                    NtStatus status = NtSystemCalls.NtEnumerateValueKey(Handle, index, KeyValueInformationClass.KeyValueFullInformation,
                        value_info, value_info.Length, out int result_length);
                    if (status == NtStatus.STATUS_BUFFER_OVERFLOW || status == NtStatus.STATUS_BUFFER_TOO_SMALL)
                    {
                        value_info.Resize(result_length);
                        continue;
                    }
                    index++;
                    if (status != NtStatus.STATUS_SUCCESS)
                    {
                        break;
                    }
                    KeyValueFullInformation res = value_info.Result;
                    char[] name_buffer = new char[res.NameLength / 2];
                    value_info.Data.ReadArray(0, name_buffer, 0, name_buffer.Length);
                    string name = new string(name_buffer);
                    byte[] data_buffer = new byte[res.DataLength];
                    if (res.DataLength > 0)
                    {
                        value_info.ReadArray((ulong)res.DataOffset, data_buffer, 0, data_buffer.Length);
                    }
                    yield return new NtKeyValue(name, res.Type, data_buffer, res.TitleIndex);
                }
            }
        }

        /// <summary>
        /// Query all subkey entries.
        /// </summary>
        /// <returns>The list of subkey entries</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<NtKeyEntry> QueryKeyEntries()
        {
            int index = 0;
            using (var buffer = new SafeStructureInOutBuffer<KeyBasicInformation>(512, true))
            {
                while (true)
                {
                    NtStatus status = NtSystemCalls.NtEnumerateKey(Handle, index, KeyInformationClass.KeyBasicInformation, buffer, buffer.Length, out int result_length);
                    if (status == NtStatus.STATUS_BUFFER_OVERFLOW || status == NtStatus.STATUS_BUFFER_TOO_SMALL)
                    {
                        buffer.Resize(result_length);
                        continue;
                    }
                    index++;
                    if (status != NtStatus.STATUS_SUCCESS)
                    {
                        break;
                    }
                    yield return new NtKeyEntry(buffer);
                }
            }
        }

        /// <summary>
        /// Query all subkey names
        /// </summary>
        /// <returns>The list of subkey names</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<string> QueryKeys()
        {
            return QueryKeyEntries().Select(k => k.Name);
        }

        /// <summary>
        /// Return a list of subkeys which can be accessed.
        /// </summary>
        /// <param name="desired_access">The required access rights for the subkeys</param>
        /// <param name="open_link">True to open link keys rather than following the link.</param>
        /// <param name="open_for_backup">True to open keys with backup flag set.</param>
        /// <returns>The disposable list of subkeys.</returns>
        public IEnumerable<NtKey> QueryAccessibleKeys(KeyAccessRights desired_access, bool open_link, bool open_for_backup)
        {
            return QueryAccessibleKeys(desired_access, open_link, open_for_backup, false);
        }

        /// <summary>
        /// Return a list of subkeys which can be accessed.
        /// </summary>
        /// <param name="desired_access">The required access rights for the subkeys</param>
        /// <returns>The disposable list of subkeys.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<NtKey> QueryAccessibleKeys(KeyAccessRights desired_access)
        {
            return QueryAccessibleKeys(desired_access, false, false);
        }

        /// <summary>
        /// Set a symbolic link target for this key (must have been created with
        /// appropriate create flags)
        /// </summary>
        /// <param name="target">The symbolic link target.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus SetSymbolicLinkTarget(string target, bool throw_on_error)
        {
            return SetValue(SymbolicLinkValueName, RegistryValueType.Link, Encoding.Unicode.GetBytes(target), throw_on_error);
        }

        /// <summary>
        /// Set a symbolic link target for this key (must have been created with
        /// appropriate create flags)
        /// </summary>
        /// <param name="target">The symbolic link target.</param>
        public void SetSymbolicLinkTarget(string target)
        {
            SetSymbolicLinkTarget(target, true);
        }

        /// <summary>
        /// Get the symbolic link target for this key.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The symbolic link target.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<string> GetSymbolicLinkTarget(bool throw_on_error)
        {
            return QueryValue(SymbolicLinkValueName, throw_on_error).Map(v => v.ToString());
        }

        /// <summary>
        /// Get the symbolic link target for this key.
        /// </summary>
        /// <returns>The symbolic link target.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public string GetSymbolicLinkTarget()
        {
            return GetSymbolicLinkTarget(true).Result;
        }

        /// <summary>
        /// Open a key
        /// </summary>
        /// <param name="key_name">The path to the key to open</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtKey Open(string key_name)
        {
            return Open(key_name, this, KeyAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open a key
        /// </summary>
        /// <param name="key_name">The path to the key to open</param>
        /// <param name="desired_access">Access rights for the key</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtKey Open(string key_name, KeyAccessRights desired_access)
        {
            return Open(key_name, this, desired_access);
        }

        /// <summary>
        /// Open a key
        /// </summary>
        /// <param name="key_name">The path to the key to open</param>
        /// <param name="desired_access">Access rights for the key</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<NtKey> Open(string key_name, KeyAccessRights desired_access, bool throw_on_error)
        {
            return Open(key_name, this, desired_access, KeyCreateOptions.NonVolatile, throw_on_error);
        }

        /// <summary>
        /// Open a key
        /// </summary>
        /// <param name="key_name">The path to the key to open</param>
        /// <param name="desired_access">Access rights for the key</param>
        /// <param name="open_options">Key open options.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<NtKey> Open(string key_name, KeyAccessRights desired_access, KeyCreateOptions open_options, bool throw_on_error)
        {
            return Open(key_name, this, desired_access, open_options, throw_on_error);
        }

        /// <summary>
        /// Reopen the key with different access rights.
        /// </summary>
        /// <param name="desired_access">The access rights to reopen with.</param>
        /// <param name="options">Open options.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened key.</returns>
        public NtResult<NtKey> ReOpen(KeyAccessRights desired_access, KeyCreateOptions options, bool throw_on_error)
        {
            return ReOpen(desired_access, AttributeFlags.CaseInsensitive, options, throw_on_error);
        }

        /// <summary>
        /// Reopen the key with different access rights.
        /// </summary>
        /// <param name="desired_access">The access rights to reopen with.</param>
        /// <param name="attributes">The object attributes to open with.</param>
        /// <param name="options">Open options.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened key.</returns>
        public NtResult<NtKey> ReOpen(KeyAccessRights desired_access, AttributeFlags attributes, KeyCreateOptions options, bool throw_on_error)
        {
            using (var obj_attr = new ObjectAttributes(string.Empty, attributes, this))
            {
                return Open(obj_attr, desired_access, options, throw_on_error);
            }
        }

        /// <summary>
        /// Reopen the key with different access rights.
        /// </summary>
        /// <param name="desired_access">The access rights to reopen with.</param>
        /// <param name="options">Open options.</param>
        /// <returns>The opened key.</returns>
        public NtKey ReOpen(KeyAccessRights desired_access, KeyCreateOptions options)
        {
            return ReOpen(desired_access, options, true).Result;
        }

        /// <summary>
        /// Convert object to a .NET RegistryKey object
        /// </summary>
        /// <returns>The registry key object</returns>
        public RegistryKey ToRegistryKey()
        {
            return RegistryKey.FromHandle(DuplicateAsRegistry(Handle));
        }

        /// <summary>
        /// Rename key.
        /// </summary>
        /// <param name="new_name">The new name for the key.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus Rename(string new_name, bool throw_on_error)
        {
            return NtSystemCalls.NtRenameKey(Handle, new UnicodeString(new_name)).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Rename key.
        /// </summary>
        /// <param name="new_name">The new name for the key.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Rename(string new_name)
        {
            Rename(new_name, true);
        }

        /// <summary>
        /// Save the opened key into a file.
        /// </summary>
        /// <param name="file">The file to save to.</param>
        /// <param name="flags">Save key flags</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus Save(NtFile file, SaveKeyFlags flags, bool throw_on_error)
        {
            return NtSystemCalls.NtSaveKeyEx(Handle, file.Handle,
                flags).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Save the opened key into a file.
        /// </summary>
        /// <param name="file">The file to save to.</param>
        /// <param name="flags">Save key flags</param>
        public void Save(NtFile file, SaveKeyFlags flags)
        {
            Save(file, flags, true);
        }

        /// <summary>
        /// Save the opened key into a file.
        /// </summary>
        /// <param name="path">The file path to save to.</param>
        /// <param name="flags">Save key flags</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus Save(string path, SaveKeyFlags flags, bool throw_on_error)
        {
            using (var file = NtFile.Create(path, null, FileAccessRights.GenericWrite | FileAccessRights.Synchronize,
                FileAttributes.Normal, FileShareMode.None, FileOpenOptions.SynchronousIoNonAlert, FileDisposition.Create, null, throw_on_error))
            {
                if (!file.IsSuccess)
                {
                    return file.Status;
                }

                return Save(file.Result, flags, throw_on_error);
            }
        }

        /// <summary>
        /// Save the opened key into a file.
        /// </summary>
        /// <param name="path">The file path to save to.</param>
        /// <param name="flags">Save key flags</param>
        public void Save(string path, SaveKeyFlags flags)
        {
            Save(path, flags, true);
        }

        /// <summary>
        /// Save the opened key into a file.
        /// </summary>
        /// <param name="path">The file path to save to.</param>
        public void Save(string path)
        {
            Save(path, SaveKeyFlags.StandardFormat);
        }

        /// <summary>
        /// Restore key from a file.
        /// </summary>
        /// <param name="file">The file to restore from</param>
        /// <param name="flags">Restore key flags</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus Restore(NtFile file, RestoreKeyFlags flags, bool throw_on_error)
        {
            return NtSystemCalls.NtRestoreKey(Handle, file.Handle, flags).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Restore key from a file.
        /// </summary>
        /// <param name="file">The file to restore from</param>
        /// <param name="flags">Restore key flags</param>
        public void Restore(NtFile file, RestoreKeyFlags flags)
        {
            Restore(file, flags, true);
        }

        /// <summary>
        /// Restore key from a file.
        /// </summary>
        /// <param name="path">The file path to restore from</param>
        /// <param name="flags">Restore key flags</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus Restore(string path, RestoreKeyFlags flags, bool throw_on_error)
        {
            using (var file = NtFile.Open(path, null, FileAccessRights.GenericRead | FileAccessRights.Synchronize,
                    FileShareMode.Read, FileOpenOptions.SynchronousIoNonAlert, throw_on_error))
            {
                if (!file.IsSuccess)
                {
                    return file.Status;
                }
                return Restore(file.Result, flags, throw_on_error);
            }
        }

        /// <summary>
        /// Restore key from a file.
        /// </summary>
        /// <param name="path">The file path to restore from</param>
        /// <param name="flags">Restore key flags</param>
        public void Restore(string path, RestoreKeyFlags flags)
        {
            using (NtFile file = NtFile.Open(path, null, FileAccessRights.GenericRead | FileAccessRights.Synchronize,
                    FileShareMode.Read, FileOpenOptions.SynchronousIoNonAlert))
            {
                Restore(file, flags);
            }
        }

        /// <summary>
        /// Restore key from a file.
        /// </summary>
        /// <param name="path">The file path to restore from</param>
        public void Restore(string path)
        {
            Restore(path, RestoreKeyFlags.None);
        }

        /// <summary>
        /// Try and lock the registry key to prevent further modification.
        /// </summary>
        /// <remarks>Note that this almost certainly never works from usermode, there's an explicit
        /// check to prevent it in the kernel.</remarks>
        public void Lock()
        {
            NtSystemCalls.NtLockRegistryKey(Handle).ToNtException();
        }

        /// <summary>
        /// Wait for a change on the registry key.
        /// </summary>
        /// <param name="completion_filter">Specify what changes will be notified.</param>
        /// <param name="watch_tree">True to watch the entire tree.</param>
        /// <returns>The status from the change notification.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus NotifyChange(NotifyCompletionFilter completion_filter, bool watch_tree)
        {
            using (SafeIoStatusBuffer io_status = new SafeIoStatusBuffer())
            {
                return NtSystemCalls.NtNotifyChangeKey(Handle, SafeKernelObjectHandle.Null, IntPtr.Zero,
                    IntPtr.Zero, io_status, completion_filter, watch_tree, SafeHGlobalBuffer.Null, 0, false).ToNtException();
            }
        }

        /// <summary>
        /// Wait for a change on thie registry key asynchronously.
        /// </summary>
        /// <param name="completion_filter">Specify what changes will be notified.</param>
        /// <param name="watch_tree">True to watch the entire tree.</param>
        /// <returns>The status from the change notification.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public async Task<NtStatus> NotifyChangeAsync(NotifyCompletionFilter completion_filter, bool watch_tree)
        {
            using (NtAsyncResult result = new NtAsyncResult(this))
            {
                NtStatus status = await result.CompleteCallAsync(NtSystemCalls.NtNotifyChangeKey(Handle, result.EventHandle, IntPtr.Zero,
                    IntPtr.Zero, result.IoStatusBuffer, completion_filter, watch_tree, SafeHGlobalBuffer.Null, 0, true), CancellationToken.None);
                return status.ToNtException();
            }
        }

        /// <summary>
        /// Visit all accessible keys under this one.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible key. Return true to continue enumeration.</param>
        /// <param name="desired_access">Specify the desired access for the keys.</param>
        /// <param name="recurse">True to recurse into sub keys.</param>
        /// <param name="max_depth">Specify max recursive depth. -1 to not set a limit.</param>
        /// <param name="open_for_backup">Open the key using backup privileges.</param>
        public bool VisitAccessibleKeys(Func<NtKey, bool> visitor, KeyAccessRights desired_access, bool open_for_backup, bool recurse, int max_depth)
        {
            if (max_depth == 0)
            {
                return true;
            }

            using (var for_enum = GetKeyForEnumeration(open_for_backup))
            {
                if (!for_enum.IsSuccess)
                {
                    return true;
                }

                using (var keys = for_enum.Result.QueryAccessibleKeys(desired_access, true, open_for_backup, true).ToDisposableList())
                {
                    if (max_depth > 0)
                    {
                        max_depth--;
                    }

                    foreach (var key in keys)
                    {
                        if (!visitor(key))
                        {
                            return false;
                        }

                        if (recurse)
                        {
                            if (!key.VisitAccessibleKeys(visitor, desired_access, open_for_backup, recurse, max_depth))
                            {
                                return false;
                            }
                        }
                    }
                }
            }

            return true;
        }

        /// <summary>
        /// Visit all accessible directories under this one.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible directory. Return true to continue enumeration.</param>
        public void VisitAccessibleKeys(Func<NtKey, bool> visitor)
        {
            VisitAccessibleKeys(visitor, false);
        }

        /// <summary>
        /// Visit all accessible directories under this one.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible directory. Return true to continue enumeration.</param>
        /// <param name="recurse">True to recurse into sub directories.</param>
        public void VisitAccessibleKeys(Func<NtKey, bool> visitor, bool recurse)
        {
            VisitAccessibleKeys(visitor, KeyAccessRights.MaximumAllowed, false, recurse);
        }

        /// <summary>
        /// Visit all accessible directories under this one.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible directory. Return true to continue enumeration.</param>
        /// <param name="desired_access">Specify the desired access for the directory</param>
        /// <param name="recurse">True to recurse into sub directories.</param>
        /// <param name="open_for_backup">Open the key using backup privileges.</param>
        public void VisitAccessibleKeys(Func<NtKey, bool> visitor, KeyAccessRights desired_access, bool open_for_backup, bool recurse)
        {
            VisitAccessibleKeys(visitor, desired_access, open_for_backup, recurse, -1);
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(KeyInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryKey(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public override NtStatus SetInformation(KeySetInformationClass info_class, SafeBuffer buffer)
        {
            return NtSystemCalls.NtSetInformationKey(Handle, info_class, buffer, buffer.GetLength());
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Get key last write time
        /// </summary>
        /// <returns>The last write time</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public DateTime LastWriteTime => DateTime.FromFileTime(GetFullInfo().Item1.LastWriteTime.QuadPart);

        /// <summary>
        /// Get key subkey count
        /// </summary>
        /// <returns>The subkey count</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int SubKeyCount => GetFullInfo().Item1.SubKeys;

        /// <summary>
        /// Get key value count
        /// </summary>
        /// <returns>The key value count</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int ValueCount => GetFullInfo().Item1.Values;

        /// <summary>
        /// Get the key title index
        /// </summary>
        /// <returns>The key title index</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int TitleIndex => GetFullInfo().Item1.TitleIndex;

        /// <summary>
        /// Get the key class name
        /// </summary>
        /// <returns>The key class name</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public string ClassName => GetFullInfo().Item2;

        /// <summary>
        /// Get the maximum key value name length
        /// </summary>
        /// <returns>The maximum key value name length</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int MaxValueNameLength => GetFullInfo().Item1.MaxValueNameLen;

        /// <summary>
        /// Get the maximum key value data length
        /// </summary>
        /// <returns>The maximum key value data length</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int MaxValueDataLength => GetFullInfo().Item1.MaxValueDataLen;

        /// <summary>
        /// Get the maximum subkey name length
        /// </summary>
        /// <returns>The maximum subkey name length</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int MaxNameLength => GetFullInfo().Item1.MaxNameLen;

        /// <summary>
        /// Get the maximum class name length
        /// </summary>
        /// <returns>The maximum class name length</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int MaxClassLength => GetFullInfo().Item1.MaxClassLen;

        /// <summary>
        /// Get the key path as a Win32 style one. If not possible returns
        /// the original path.
        /// </summary>
        public string Win32Path => NtKeyUtils.NtKeyNameToWin32(FullPath);

        /// <summary>
        /// The disposition when the key was created.
        /// </summary>
        public KeyDisposition Disposition { get; }

        /// <summary>
        /// Indicates the handle is a special pre-defined one by the kernel.
        /// </summary>
        public bool PredefinedHandle { get; }

        /// <summary>
        /// Get or set virtualization flags.
        /// </summary>
        public KeyVirtualizationFlags VirtualizationFlags
        {
            get => (KeyVirtualizationFlags)Query<int>(KeyInformationClass.KeyVirtualizationInformation);
            set
            {
                // Map value to set virtualization flags.
                KeySetVirtualizationFlags flags = KeySetVirtualizationFlags.None;
                if (value.HasFlag(KeyVirtualizationFlags.VirtualSource))
                {
                    flags |= KeySetVirtualizationFlags.VirtualSource;
                }
                if (value.HasFlag(KeyVirtualizationFlags.VirtualStore))
                {
                    flags |= KeySetVirtualizationFlags.VirtualStore;
                }
                if (value.HasFlag(KeyVirtualizationFlags.VirtualTarget))
                {
                    flags |= KeySetVirtualizationFlags.VirtualTarget;
                }

                Set(KeySetInformationClass.KeySetVirtualizationInformation, (int)flags);
            }
        }

        /// <summary>
        /// Get or set key control flags.
        /// </summary>
        public KeyControlFlags ControlFlags
        {
            get => Query<KeyFlagsInformation>(KeyInformationClass.KeyFlagsInformation).ControlFlags;
            set => Set(KeySetInformationClass.KeyControlFlagsInformation, (int)value);
        }

        /// <summary>
        /// Get or set wow64 flags.
        /// </summary>
        public int Wow64Flags
        {
            get => Query<KeyFlagsInformation>(KeyInformationClass.KeyFlagsInformation).Wow64Flags;
            set => Set(KeySetInformationClass.KeyWow64FlagsInformation, value);
        }

        /// <summary>
        /// Get key flags.
        /// </summary>
        public KeyFlags KeyFlags => Query<KeyFlagsInformation>(KeyInformationClass.KeyFlagsInformation).KeyFlags;

        /// <summary>
        /// Indicates if this key is from a trusted hive.
        /// </summary>
        public bool Trusted => Query<KeyTrustInformation>(KeyInformationClass.KeyTrustInformation).TrustedKey;

        /// <summary>
        /// Indicates if this key is a symbolic link.
        /// </summary>
        public bool IsLink => KeyFlags.HasFlag(KeyFlags.Link);

        /// <summary>
        /// Indicates if this key is volatile.
        /// </summary>
        public bool IsVolatile => KeyFlags.HasFlag(KeyFlags.Volatile);

        /// <summary>
        /// Get the name from NtQueryKey.
        /// </summary>
        public string NameInformation
        {
            get
            {
                using (var buffer = QueryBuffer<KeyNameInformation>(KeyInformationClass.KeyNameInformation))
                {
                    return buffer.Data.ReadUnicodeString(buffer.Result.NameLength / 2);
                }
            }
        }

        /// <summary>
        /// Returns whether this object is a container.
        /// </summary>
        public override bool IsContainer => true;

        #endregion

        #region Private Members

        private const string SymbolicLinkValueName = "SymbolicLinkValue";

        private NtResult<NtKey> GetKeyForEnumeration(bool open_for_backup)
        {
            if (IsAccessGranted(KeyAccessRights.EnumerateSubKeys))
            {
                return Duplicate(KeyAccessRights.EnumerateSubKeys, AttributeFlags.None, DuplicateObjectOptions.SameAttributes, false);
            }
            else
            {
                return ReOpen(KeyAccessRights.EnumerateSubKeys, AttributeFlags.OpenLink | AttributeFlags.CaseInsensitive,
                    open_for_backup ? KeyCreateOptions.BackupRestore : KeyCreateOptions.NonVolatile, false);
            }
        }

        private IEnumerable<NtKey> QueryAccessibleKeys(KeyAccessRights desired_access, bool open_link, bool open_for_backup, bool ignore_predefined_keys)
        {
            List<NtKey> ret = new List<NtKey>();
            AttributeFlags flags = AttributeFlags.CaseInsensitive;
            if (open_link)
            {
                flags |= AttributeFlags.OpenLink;
            }

            if (IsAccessGranted(KeyAccessRights.EnumerateSubKeys))
            {
                foreach (string name in QueryKeys())
                {
                    using (ObjectAttributes obja = new ObjectAttributes(name, flags, this))
                    {
                        var result = Open(obja, desired_access, open_for_backup ? KeyCreateOptions.BackupRestore : 0, false);
                        if (result.IsSuccess && (!ignore_predefined_keys || result.Status != NtStatus.STATUS_PREDEFINED_HANDLE))
                        {
                            ret.Add(result.Result);
                        }
                    }
                }
            }
            return ret;
        }

        private static SafeRegistryHandle DuplicateAsRegistry(SafeKernelObjectHandle handle)
        {
            using (var dup_handle = DuplicateHandle(handle))
            {
                SafeRegistryHandle ret = new SafeRegistryHandle(dup_handle.DangerousGetHandle(), true);
                dup_handle.SetHandleAsInvalid();
                return ret;
            }
        }

        private Tuple<KeyFullInformation, string> GetFullInfo()
        {
            using (var buffer = QueryBuffer<KeyFullInformation>(KeyInformationClass.KeyFullInformation))
            {
                KeyFullInformation ret = buffer.Result;
                byte[] class_name = new byte[ret.ClassLength];
                if ((class_name.Length > 0) && (ret.ClassOffset > 0))
                {
                    buffer.ReadArray((ulong)ret.ClassOffset, class_name, 0, class_name.Length);
                }
                return new Tuple<KeyFullInformation, string>(ret, Encoding.Unicode.GetString(class_name));
            }
        }

        private static NtResult<NtKey> LoadKey(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr,
            LoadKeyFlags flags, KeyAccessRights desired_access, NtKey trust_key, NtEvent key_event, bool no_open, bool throw_on_error)
        {
            if (flags.HasFlagSet(LoadKeyFlags.AppKey))
            {
                if (no_open)
                    throw new ArgumentException("Can't create an Application Key without returning a handle.");

                return NtSystemCalls.NtLoadKeyEx(key_obj_attr, file_obj_attr, flags,
                    trust_key.GetHandle().DangerousGetHandle(), key_event.GetHandle().DangerousGetHandle(),
                    desired_access, out SafeKernelObjectHandle key_handle, 0)
                    .CreateResult(throw_on_error, () => new NtKey(key_handle, KeyDisposition.OpenedExistingKey, false));
            }
            else
            {
                var result = NtSystemCalls.NtLoadKeyEx(key_obj_attr, file_obj_attr, flags,
                    trust_key.GetHandle().DangerousGetHandle(), key_event.GetHandle().DangerousGetHandle(),
                    0, IntPtr.Zero, 0).CreateResult<NtKey>(throw_on_error, () => null);
                if (!result.IsSuccess || no_open)
                {
                    return result;
                }

                return Open(key_obj_attr, desired_access, KeyCreateOptions.NonVolatile, throw_on_error);
            }
        }

        private static NtResult<NtKey> LoadKey(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr,
            LoadKeyFlags flags, KeyAccessRights desired_access, NtKey trust_key, NtEvent key_event, NtToken token, bool no_open, bool throw_on_error)
        {
            if (token == null)
            {
                return LoadKey(key_obj_attr, file_obj_attr, flags, desired_access, 
                    trust_key, key_event, no_open, throw_on_error);
            }

            List<KeyLoadArgument> args = new List<KeyLoadArgument>();
            if (trust_key != null)
            {
                args.Add(new KeyLoadArgument()
                {
                    ArgumentType = KeyLoadArgumentType.TrustKeyHandle,
                    Argument = trust_key.Handle.DangerousGetHandle()
                });
            }

            if (key_event != null)
            {
                args.Add(new KeyLoadArgument()
                {
                    ArgumentType = KeyLoadArgumentType.EventHandle,
                    Argument = key_event.Handle.DangerousGetHandle()
                });
            }
            args.Add(new KeyLoadArgument()
            {
                ArgumentType = KeyLoadArgumentType.TokenHandle,
                Argument = token.Handle.DangerousGetHandle()
            });

            if (flags.HasFlagSet(LoadKeyFlags.AppKey))
            {
                if (no_open)
                    throw new ArgumentException("Can't create an Application Key without returning a handle.");

                return NtSystemCalls.NtLoadKey3(key_obj_attr, file_obj_attr, flags,
                    args.ToArray(), args.Count, desired_access, out SafeKernelObjectHandle key_handle, 0)
                    .CreateResult(throw_on_error, () => new NtKey(key_handle, KeyDisposition.OpenedExistingKey, false));
            }
            else
            {
                var result = NtSystemCalls.NtLoadKey3(key_obj_attr, file_obj_attr, flags,
                    args.ToArray(), args.Count, 0, IntPtr.Zero, 0).CreateResult<NtKey>(throw_on_error, () => null);
                if (!result.IsSuccess || no_open)
                {
                    return result;
                }

                return Open(key_obj_attr, desired_access, KeyCreateOptions.NonVolatile, throw_on_error);
            }
        }

        #endregion
    }
}
