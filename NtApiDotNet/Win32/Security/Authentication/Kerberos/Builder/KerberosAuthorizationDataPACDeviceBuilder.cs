//  Copyright 2022 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Ndr.Marshal;
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Ndr;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// Class to represent a builder for the PAC device entry.
    /// </summary>
    public sealed class KerberosAuthorizationDataPACDeviceBuilder : KerberosAuthorizationDataPACEntryBuilder
    {
        #region Private Members
        private PAC_DEVICE_INFO _info;
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosAuthorizationDataPACDeviceBuilder() 
            : base(KerberosAuthorizationDataPACEntryType.Device)
        {
            _info = new PAC_DEVICE_INFO();
        }

        internal KerberosAuthorizationDataPACDeviceBuilder(byte[] data) : this()
        {
            _info = PacDeviceInfoParser.Decode(new NdrPickledType(data))
                ?? throw new ArgumentException("Invalid PAC_DEVICE_INFO buffer.");
            AccountGroupIds = KerberosGroupMembership.CreateGroup(_info.AccountGroupIds);
            if (_info.ExtraSids != null)
            {
                ExtraSids = _info.ExtraSids.GetValue().Select(KERB_SID_AND_ATTRIBUTES_DEVICE.ToGroup).ToList();
            }
            DomainGroup = KerberosDomainGroupMembership.FromGroup(_info.DomainGroup);
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The RID of the device's user SID.
        /// </summary>
        public uint UserId { get => (uint)_info.UserId; set => _info.UserId = (int)value; }
        /// <summary>
        /// The RID of the primary group SID.
        /// </summary>
        public uint PrimaryGroupId { get => (uint)_info.PrimaryGroupId; set => _info.PrimaryGroupId = (int)value; }
        /// <summary>
        /// The device account domain SID.
        /// </summary>
        public Sid AccountDomainId
        {
            get => _info.AccountDomainId?.GetValue().ToSid();
            set
            {
                if (value == null)
                    _info.AccountDomainId = null;
                else
                    _info.AccountDomainId = new RPC_SID_DEVICE(value);
            }
        }
        /// <summary>
        /// List of account groups.
        /// </summary>
        public List<KerberosGroupMembership> AccountGroupIds { get; set; }
        /// <summary>
        /// List of extra SIDs.
        /// </summary>
        public List<UserGroup> ExtraSids { get; }
        /// <summary>
        /// List of domain groups.
        /// </summary>
        public List<KerberosDomainGroupMembership> DomainGroup { get; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Create the authorization data.
        /// </summary>
        /// <returns>The authorization data object.</returns>
        public override KerberosAuthorizationDataPACEntry Create()
        {
            _info.AccountGroupIds = KerberosGroupMembership.FromGroupDevice(AccountGroupIds, ref _info.AccountGroupCount);
            _info.SidCount = ExtraSids?.Count ?? 0;
            if (ExtraSids != null)
            {
                _info.ExtraSids = ExtraSids.Select(KERB_SID_AND_ATTRIBUTES_DEVICE.ToStruct).ToArray();
            }
            else
            {
                _info.ExtraSids = null;
            }
            _info.DomainGroup = KerberosDomainGroupMembership.FromGroup(DomainGroup, ref _info.DomainGroupCount);

            var data = PacDeviceInfoParser.Encode(_info);
            if (!KerberosAuthorizationDataPACDevice.Parse(data.ToArray(), out KerberosAuthorizationDataPACEntry entry))
                throw new InvalidDataException("PAC Logon type is invalid.");
            return entry;
        }
        #endregion
    }
}
