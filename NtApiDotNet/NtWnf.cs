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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    public enum WnfStateNameLifetime
    {
        WellKnown,
        Permanent,
        Volatile,
        Temporary
    }

    public enum WnfStateNameInformation
    {
        NameExist,
        SubscribersPresent,
        IsQuiescent
    }

    public enum WnfDataScope
    {
        System,
        Session,
        User,
        Process,
        Machine
    }

    [StructLayout(LayoutKind.Sequential)]
    public class WnfTypeId
    {
        public Guid TypeId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WnfDeliveryDescriptor 
    {
        public ulong SubscriptionId;
        public ulong StateName;
        public uint ChangeStamp;
        public uint StateDataSize;
        public uint EventMask;
        public WnfTypeId TypeId;
        public uint StateDataOffset;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateWnfStateName(
            out ulong StateName,
            WnfStateNameLifetime NameLifetime,
            WnfDataScope DataScope,
            bool PersistData,
            [In, Optional] WnfTypeId TypeId,
            int MaximumStateSize,
            SafeBuffer SecurityDescriptor
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryWnfStateData(
             ref ulong StateName,
             [In, Optional] WnfTypeId TypeId,
             [Optional] IntPtr ExplicitScope,
             out int ChangeStamp,
             SafeBuffer Buffer,
             ref int BufferSize
         );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtUpdateWnfStateData(
            ref ulong StateName,
            SafeBuffer Buffer,
            int Length,
            [In, Optional] WnfTypeId TypeId,
            [Optional] IntPtr ExplicitScope,
            int MatchingChangeStamp,
            int CheckStamp
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDeleteWnfStateName(
            ref ulong StateName
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryWnfStateNameInformation(
            ref ulong StateName,
            WnfStateNameInformation NameInfoClass,
            IntPtr ExplicitScope,
            SafeBuffer InfoBuffer,
            int InfoBufferSize
        );
    }

    public class WnfStateData
    {
        public byte[] Data { get; }
        public int Changestamp { get; }

        internal WnfStateData(byte[] data, int changestamp)
        {
            Data = data;
            Changestamp = changestamp;
        }
    }

    public enum WnfAccessRights : uint
    {
        ReadData = 1,
        WriteData = 2,
        Unknown10 = 0x10,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

#pragma warning restore 1591

    /// <summary>
    /// NT WNF object.
    /// </summary>
    public class NtWnf
    {
        private bool _read_state_data;
        private SecurityDescriptor _security_descriptor;
        private static readonly string[] _root_keys = { @"\Registry\Machine\System\CurrentControlSet\Control\Notifications",
            @"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\Notifications",
            @"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\VolatileNotifications" };

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
                using (var buffer = new SafeStructureInOutBuffer<int>())
                {
                    NtStatus status = NtSystemCalls.NtQueryWnfStateNameInformation(ref state_name, 
                        WnfStateNameInformation.NameExist, IntPtr.Zero, buffer, buffer.Length);
                    if (!status.IsSuccess())
                    {
                        return status.CreateResultFromError<NtWnf>(throw_on_error);
                    }
                    if (buffer.Result == 0)
                    {
                        return NtStatus.STATUS_OBJECT_NAME_NOT_FOUND.CreateResultFromError<NtWnf>(throw_on_error);
                    }
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

                    var value = key.Result.QueryValue(StateName.ToString("X"), false);
                    if (value.IsSuccess)
                    {
                        ReadStateData(value.Result);
                    }
                }
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

        internal NtWnf(ulong state_name)
        {
            StateName = state_name;
        }
    }
}
