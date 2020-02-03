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

using System;
using System.Collections.Generic;

namespace NtApiDotNet
{
    /// <summary>
    /// NT WNF object.
    /// </summary>
    public class NtWnf
    {
        #region Private Members
        private bool _read_state_data;
        private SecurityDescriptor _security_descriptor;
        private static readonly string[] _root_keys = { @"\Registry\Machine\System\CurrentControlSet\Control\Notifications",
            @"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\Notifications",
            @"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\VolatileNotifications" };

        private static NtResult<T> Query<T>(ulong state_name, WnfStateNameInformation info_class, bool throw_on_error) where T : struct
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                return NtSystemCalls.NtQueryWnfStateNameInformation(ref state_name,
                    WnfStateNameInformation.NameExist, 
                    IntPtr.Zero, buffer, buffer.Length).CreateResult(throw_on_error, () => buffer.Result);
            }
        }

        private void ReadStateData(NtKeyValue value)
        {
            _security_descriptor = new SecurityDescriptor(value.Data);
        }

        private void ReadStateData()
        {
            if (_read_state_data)
            {
                return;
            }
            _read_state_data = true;
            using (ObjectAttributes obj_attr = new ObjectAttributes(_root_keys[(int)Lifetime], AttributeFlags.CaseInsensitive))
            {
                using (var key = NtKey.Open(obj_attr, KeyAccessRights.QueryValue, KeyCreateOptions.NonVolatile, false))
                {
                    if (!key.IsSuccess)
                    {
                        return;
                    }

                    var value = key.Result.QueryValue(StateName.ToString("X016"), false);
                    if (value.IsSuccess)
                    {
                        ReadStateData(value.Result);
                    }
                }
            }
        }

        #endregion

        #region Static Members
        /// <summary>
        /// Get the generic mapping for a 
        /// </summary>
        public static GenericMapping GenericMapping
        {
            get
            {
                return new GenericMapping()
                {
                    GenericRead = WnfAccessRights.Synchronize | WnfAccessRights.ReadControl | WnfAccessRights.ReadData,
                    GenericWrite = WnfAccessRights.WriteData,
                    GenericExecute = WnfAccessRights.Synchronize | WnfAccessRights.WriteOwner | WnfAccessRights.WriteDac | WnfAccessRights.ReadControl,
                    GenericAll = WnfAccessRights.Synchronize | WnfAccessRights.WriteOwner | WnfAccessRights.WriteDac
                    | WnfAccessRights.ReadControl | WnfAccessRights.ReadData | WnfAccessRights.WriteData | WnfAccessRights.Unknown10,
                };
            }
        }

        /// <summary>
        /// Create a new WNF state name.
        /// </summary>
        /// <param name="name_lifetime">The lifetime of the name.</param>
        /// <param name="data_scope">The scope of the data.</param>
        /// <param name="persist_data">Whether to persist data.</param>
        /// <param name="type_id">Optional type ID.</param>
        /// <param name="maximum_state_size">Maximum state size.</param>
        /// <param name="security_descriptor">Mandatory security descriptor.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created object.</returns>
        public static NtResult<NtWnf> Create(
            WnfStateNameLifetime name_lifetime,
            WnfDataScope data_scope,
            bool persist_data,
            WnfTypeId type_id,
            int maximum_state_size,
            SecurityDescriptor security_descriptor,
            bool throw_on_error)
        {
            if (security_descriptor == null)
            {
                throw new ArgumentNullException("Must specify a security descriptor");
            }
            using (var sd_buffer = security_descriptor.ToSafeBuffer())
            {
                return NtSystemCalls.NtCreateWnfStateName(out ulong state_name, name_lifetime,
                    data_scope, persist_data, type_id, maximum_state_size, sd_buffer)
                    .CreateResult(throw_on_error, () => new NtWnf(state_name) { _security_descriptor = security_descriptor });
            }
        }

        /// <summary>
        /// Kernel derived key which is used to mask the state name.
        /// </summary>
        public const ulong StateNameKey = 0x41C64E6DA3BC0074UL;

        /// <summary>
        /// Create a new WNF state name.
        /// </summary>
        /// <param name="name_lifetime">The lifetime of the name.</param>
        /// <param name="data_scope">The scope of the data.</param>
        /// <param name="persist_data">Whether to persist data.</param>
        /// <param name="type_id">Optional type ID.</param>
        /// <param name="maximum_state_size">Maximum state size.</param>
        /// <param name="security_descriptor">Mandatory security descriptor.</param>
        /// <returns>The created object.</returns>
        public static NtWnf Create(
            WnfStateNameLifetime name_lifetime,
            WnfDataScope data_scope,
            bool persist_data,
            WnfTypeId type_id,
            int maximum_state_size,
            SecurityDescriptor security_descriptor)
        {
            return Create(name_lifetime, data_scope, persist_data, type_id, maximum_state_size, security_descriptor, true).Result;
        }

        /// <summary>
        /// Open a state name. Doesn't check if it exists.
        /// </summary>
        /// <param name="state_name">The statename to open.</param>
        /// <param name="check_exists">True to check state name exists.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created object.</returns>
        public static NtResult<NtWnf> Open(ulong state_name, bool check_exists, bool throw_on_error)
        {
            if (check_exists)
            {
                var exists = Query<int>(state_name, WnfStateNameInformation.NameExist, throw_on_error);
                if (!exists.IsSuccess)
                {
                    return exists.Status.CreateResultFromError<NtWnf>(false);
                }

                if (exists.Result == 0)
                {
                    return NtStatus.STATUS_OBJECT_NAME_NOT_FOUND.CreateResultFromError<NtWnf>(throw_on_error);
                }
            }

            return new NtResult<NtWnf>(NtStatus.STATUS_SUCCESS, new NtWnf(state_name));
        }

        /// <summary>
        /// Open a state name. Doesn't check if it exists.
        /// </summary>
        /// <param name="state_name">The statename to open.</param>
        /// <param name="check_exists">True to check state name exists.</param>
        /// <returns>The created object.</returns>
        public static NtWnf Open(ulong state_name, bool check_exists)
        {
            return Open(state_name, check_exists, true).Result;
        }

        /// <summary>
        /// Open a state name. Doesn't check if it exists.
        /// </summary>
        /// <param name="state_name">The statename to open.</param>
        /// <returns>The created object.</returns>
        public static NtWnf Open(ulong state_name)
        {
            return Open(state_name, true);
        }

        /// <summary>
        /// Open a state name. Doesn't check if it exists.
        /// </summary>
        /// <param name="name">The name to open.</param>
        /// <param name="check_exists">True to check state name exists.</param>
        /// <returns>The created object.</returns>
        public static NtWnf Open(string name, bool check_exists)
        {
            if (!NtWnfWellKnownNames.Names.ContainsKey(name))
            {
                throw new NtException(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND);
            }
            return Open(NtWnfWellKnownNames.Names[name], check_exists, true).Result;
        }

        /// <summary>
        /// Open a state name. Doesn't check if it exists.
        /// </summary>
        /// <param name="name">The name to open.</param>
        /// <returns>The created object.</returns>
        public static NtWnf Open(string name)
        {
            return Open(name, true);
        }

        /// <summary>
        /// Get registered notifications.
        /// </summary>
        /// <returns>The list of registered notifications.</returns>
        public static IEnumerable<NtWnf> GetRegisteredNotifications()
        {
            foreach (string key_name in _root_keys)
            {
                using (ObjectAttributes obj_attr = new ObjectAttributes(key_name, AttributeFlags.CaseInsensitive))
                {
                    using (var key = NtKey.Open(obj_attr, KeyAccessRights.QueryValue, KeyCreateOptions.NonVolatile, false))
                    {
                        if (!key.IsSuccess)
                        {
                            continue;
                        }
                        foreach (var value in key.Result.QueryValues())
                        {
                            if (!ulong.TryParse(value.Name, System.Globalization.NumberStyles.HexNumber, null, out ulong state_name))
                            {
                                continue;
                            }
                            NtWnf result = new NtWnf(state_name);
                            result.ReadStateData(value);
                            result._read_state_data = true;
                            yield return result;
                        }
                    }
                }
            }
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get the state name for this WNF entry.
        /// </summary>
        public ulong StateName { get; }

        /// <summary>
        /// Get the associated lifetime for the state name.
        /// </summary>
        public WnfStateNameLifetime Lifetime
        {
            get
            {
                ulong decoded_statename = StateName ^ StateNameKey;
                return (WnfStateNameLifetime)(int)((decoded_statename >> 4) & 3);
            }
        }

        /// <summary>
        /// Get if the state has subscribers.
        /// </summary>
        public bool SubscribersPresent
        {
            get
            {
                return Query<int>(StateName, WnfStateNameInformation.SubscribersPresent, true).Result != 0;
            }
        }

        /// <summary>
        /// Get the security descriptor for this object, if known.
        /// </summary>
        public SecurityDescriptor SecurityDescriptor
        {
            get
            {
                ReadStateData();
                if (Lifetime == WnfStateNameLifetime.Temporary)
                {
                    return null;
                }

                return _security_descriptor;
            }
        }

        /// <summary>
        /// Get a name for the WNF notification.
        /// </summary>
        public string Name => NtWnfWellKnownNames.GetName(StateName) ?? StateName.ToString("X016");

        #endregion

        #region Public Methods
        /// <summary>
        /// Query state data for the WNF object.
        /// </summary>
        /// <param name="type_id">Optional Type ID.</param>
        /// <param name="explicit_scope">Optional explicit scope.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The state data.</returns>
        public NtResult<WnfStateData> QueryStateData(WnfTypeId type_id, IntPtr explicit_scope, bool throw_on_error)
        {
            int tries = 10;
            int size = 4096;
            while (tries-- > 0)
            {
                using (var buffer = new SafeHGlobalBuffer(size))
                {
                    ulong state_name = StateName;
                    NtStatus status = NtSystemCalls.NtQueryWnfStateData(ref state_name, type_id, 
                        explicit_scope, out int changestamp, buffer, ref size);
                    if (status == NtStatus.STATUS_BUFFER_TOO_SMALL)
                    {
                        continue;
                    }

                    return status.CreateResult(throw_on_error, () => new WnfStateData(buffer.ReadBytes(size), changestamp));
                }
            }

            return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<WnfStateData>(throw_on_error);
        }

        /// <summary>
        /// Query state data for the WNF object.
        /// </summary>
        /// <param name="type_id">Optional Type ID.</param>
        /// <param name="explicit_scope">Optional explicit scope.</param>
        /// <returns>The state data.</returns>
        public WnfStateData QueryStateData(WnfTypeId type_id, IntPtr explicit_scope)
        {
            return QueryStateData(type_id, explicit_scope, true).Result;
        }

        /// <summary>
        /// Query state data for the WNF object.
        /// </summary>
        /// <returns>The state data.</returns>
        public WnfStateData QueryStateData()
        {
            return QueryStateData(null, IntPtr.Zero);
        }

        /// <summary>
        /// Update state data for the WNF object.
        /// </summary>
        /// <param name="data">The data to set.</param>
        /// <param name="type_id">Optional Type ID.</param>
        /// <param name="explicit_scope">Optional explicit scope.</param>
        /// <param name="matching_changestamp">Optional matching changestamp.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The status from the update.</returns>
        public NtStatus UpdateStateData(byte[] data, WnfTypeId type_id, IntPtr explicit_scope, int? matching_changestamp, bool throw_on_error)
        {
            using (var buffer = data.ToBuffer())
            {
                ulong state_name = StateName;
                return NtSystemCalls.NtUpdateWnfStateData(ref state_name, buffer, 
                    buffer.Length, type_id, explicit_scope,
                    matching_changestamp ?? 0, matching_changestamp.HasValue).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Update state data for the WNF object.
        /// </summary>
        /// <param name="data">The data to set.</param>
        public void UpdateStateData(byte[] data)
        {
            UpdateStateData(data, null, IntPtr.Zero, null, true);
        }

        #endregion

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The string representation.</returns>
        public override string ToString()
        {
            return $"WNF:{Name} {Lifetime}";
        }

        internal NtWnf(ulong state_name)
        {
            StateName = state_name;
        }
    }
}
