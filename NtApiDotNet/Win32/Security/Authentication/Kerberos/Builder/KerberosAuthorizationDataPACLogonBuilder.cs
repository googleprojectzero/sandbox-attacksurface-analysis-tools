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
    /// Class to represent a builder for the PAC Logon entry.
    /// </summary>
    public sealed class KerberosAuthorizationDataPACLogonBuilder : KerberosAuthorizationDataPACEntryBuilder
    {
        #region Private Members
        private KERB_VALIDATION_INFO _info;

        private List<KerberosGroupMembership> CreateGroup(NdrEmbeddedPointer<GROUP_MEMBERSHIP[]> ptr)
        {
            if (ptr == null)
                return null;
            return ptr.GetValue().Select(KerberosGroupMembership.Create).ToList();
        }

        private NdrEmbeddedPointer<GROUP_MEMBERSHIP[]> FromGroup(IList<KerberosGroupMembership> groups, ref int count)
        {
            count = groups?.Count ?? 0;
            if (groups != null)
            {
                return groups.Select(KerberosGroupMembership.ToStruct).ToArray();
            }
            return null;
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Logon time.
        /// </summary>
        public DateTime LogonTime { get => _info.LogonTime.ToTime(); set => _info.LogonTime.Set(value); }
        /// <summary>
        /// Logoff time.
        /// </summary>
        public DateTime LogoffTime { get => _info.LogoffTime.ToTime(); set => _info.LogoffTime.Set(value); }
        /// <summary>
        /// Kick off time.
        /// </summary>
        public DateTime KickOffTime { get => _info.KickOffTime.ToTime(); set => _info.KickOffTime.Set(value); }
        /// <summary>
        /// Time password last set.
        /// </summary>
        public DateTime PasswordLastSet { get => _info.PasswordLastSet.ToTime(); set => _info.PasswordLastSet.Set(value); }
        /// <summary>
        /// Time password can change.
        /// </summary>
        public DateTime PasswordCanChange { get => _info.PasswordCanChange.ToTime(); set => _info.PasswordCanChange.Set(value); }
        /// <summary>
        /// Time password must change.
        /// </summary>
        public DateTime PasswordMustChange { get => _info.PasswordMustChange.ToTime(); set => _info.PasswordMustChange.Set(value); }
        /// <summary>
        /// Effective name.
        /// </summary>
        public string EffectiveName { get => _info.EffectiveName.ToString(); set => _info.EffectiveName.Set(value); }
        /// <summary>
        /// Full name.
        /// </summary>
        public string FullName { get => _info.FullName.ToString(); set => _info.FullName.Set(value); }
        /// <summary>
        /// Logon script path.
        /// </summary>
        public string LogonScript { get => _info.LogonScript.ToString(); set => _info.LogonScript.Set(value); }
        /// <summary>
        /// Profile path.
        /// </summary>
        public string ProfilePath { get => _info.ProfilePath.ToString(); set => _info.ProfilePath.Set(value); }
        /// <summary>
        /// Home directory path.
        /// </summary>
        public string HomeDirectory { get => _info.HomeDirectory.ToString(); set => _info.HomeDirectory.Set(value); }
        /// <summary>
        /// Home directory drive.
        /// </summary>
        public string HomeDirectoryDrive { get => _info.HomeDirectoryDrive.ToString(); set => _info.HomeDirectoryDrive.Set(value); }
        /// <summary>
        /// Logon count.
        /// </summary>
        public short LogonCount { get => _info.LogonCount; set => _info.LogonCount = value; }
        /// <summary>
        /// Bad password count.
        /// </summary>
        public short BadPasswordCount { get => _info.BadPasswordCount; set => _info.BadPasswordCount = value; }
        /// <summary>
        /// User RID.
        /// </summary>
        public uint UserId { get => (uint) _info.UserId; set => _info.UserId = (int) value; }
        /// <summary>
        /// Primary group RID.
        /// </summary>
        public uint PrimaryGroupId { get => (uint)_info.PrimaryGroupId; set => _info.PrimaryGroupId = (int)value; }
        /// <summary>
        /// Group list.
        /// </summary>
        public IList<KerberosGroupMembership> GroupIds { get; set; }
        /// <summary>
        /// User flags.
        /// </summary>
        public KerberosUserFlags UserFlags { get => (KerberosUserFlags)_info.UserFlags; set => _info.UserFlags = (int)value; }
        /// <summary>
        /// User session key.
        /// </summary>
        public byte[] UserSessionKey { get => _info.UserSessionKey.ToArray(); set => _info.UserSessionKey.Set(value); }
        /// <summary>
        /// Logon server name.
        /// </summary>
        public string LogonServer { get => _info.LogonServer.ToString(); set => _info.LogonServer.Set(value); }
        /// <summary>
        /// Logon domain name.
        /// </summary>
        public string LogonDomainName { get => _info.LogonDomainName.ToString(); set => _info.LogonDomainName.Set(value); }
        /// <summary>
        /// Logon domain sid.
        /// </summary>
        public Sid LogonDomainId
        {
            get => _info.LogonDomainId.GetValue().ToSid();
            set
            {
                if (value == null)
                    _info.LogonDomainId = null;
                else
                    _info.LogonDomainId = new RPC_SID(value);
            }
        }
        /// <summary>
        /// Extra SIDs.
        /// </summary>
        public IList<UserGroup> ExtraSids { get; set; }
        /// <summary>
        /// Reserved1 field.
        /// </summary>
        public int[] Reserved1 { 
            get => _info.Reserved1; 
            set => _info.Reserved1 = value.Length == 2 ? value : throw new ArgumentException("Reserved1 must be 2 integers in size", nameof(value)); 
        }
        /// <summary>
        /// User account control flags.
        /// </summary>
        public UserAccountControlFlags UserAccountControl 
        { 
            get => (UserAccountControlFlags)_info.UserAccountControl; 
            set => _info.UserAccountControl = (int)value; 
        }
        /// <summary>
        /// Reserved3 field.
        /// </summary>
        public int[] Reserved3
        {
            get => _info.Reserved3;
            set => _info.Reserved3 = value.Length == 7 ? value : throw new ArgumentException("Reserved3 must be 7 integers in size", nameof(value));
        }
        /// <summary>
        /// Resource domain group SID.
        /// </summary>
        public Sid ResourceGroupDomainSid 
        { 
            get => _info.ResourceGroupDomainSid.GetValue().ToSid(); 
            set
            {
                if (value == null)
                    _info.ResourceGroupDomainSid = null;
                else
                    _info.ResourceGroupDomainSid = new RPC_SID(value);
            }
        }
        /// <summary>
        /// Resource groups.
        /// </summary>
        public IList<KerberosGroupMembership> ResourceGroupIds { get; set; }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosAuthorizationDataPACLogonBuilder() : base(KerberosAuthorizationDataPACEntryType.Logon)
        {
            _info = new KERB_VALIDATION_INFO();
        }

        internal KerberosAuthorizationDataPACLogonBuilder(byte[] data) : this()
        {
            _info = KerbValidationInfoParser.Decode(new NdrPickledType(data))
                ?? throw new ArgumentException("Invalid KERB_VALIDATION_INFO buffer.");
            GroupIds = CreateGroup(_info.GroupIds);
            ResourceGroupIds = CreateGroup(_info.ResourceGroupIds);
            if (_info.ExtraSids != null)
            {
                ExtraSids = _info.ExtraSids.GetValue().Select(KERB_SID_AND_ATTRIBUTES.ToGroup).ToList();
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Add a group ID.
        /// </summary>
        /// <param name="relative_id">The group ID to add.</param>
        /// <param name="attributes">The attributes for the group.</param>
        public void AddGroupId(uint relative_id, GroupAttributes attributes)
        {
            if (GroupIds == null)
                GroupIds = new List<KerberosGroupMembership>();
            GroupIds.Add(new KerberosGroupMembership() { RelativeId = relative_id, Attributes = attributes });
        }

        /// <summary>
        /// Add a resource group ID.
        /// </summary>
        /// <param name="relative_id">The group ID to add.</param>
        /// <param name="attributes">The attributes for the group.</param>
        public void AddResourceGroupId(uint relative_id, GroupAttributes attributes)
        {
            if (ResourceGroupIds == null)
                ResourceGroupIds = new List<KerberosGroupMembership>();
            ResourceGroupIds.Add(new KerberosGroupMembership() { RelativeId = relative_id, Attributes = attributes });
        }

        /// <summary>
        /// Add an extra SID.
        /// </summary>
        /// <param name="sid">The SID to add.</param>
        /// <param name="attributes">The attributes for the group.</param>
        public void AddExtraSid(Sid sid, GroupAttributes attributes)
        {
            if (ExtraSids == null)
                ExtraSids = new List<UserGroup>();
            ExtraSids.Add(new UserGroup(sid, attributes));
        }

        /// <summary>
        /// Create the authorization data.
        /// </summary>
        /// <returns>The authorization data object.</returns>
        public override KerberosAuthorizationDataPACEntry Create()
        {
            _info.GroupIds = FromGroup(GroupIds, ref _info.GroupCount);
            _info.ResourceGroupIds = FromGroup(ResourceGroupIds, ref _info.ResourceGroupCount);
            _info.SidCount = ExtraSids?.Count ?? 0;;
            if (ExtraSids != null)
            {
                _info.ExtraSids = ExtraSids.Select(KERB_SID_AND_ATTRIBUTES.ToStruct).ToArray();
            }
            else
            {
                _info.ExtraSids = null;
            }

            var data = KerbValidationInfoParser.Encode(_info);
            if (!KerberosAuthorizationDataPACLogon.Parse(PACType, data.ToArray(), out KerberosAuthorizationDataPACEntry entry))
                throw new InvalidDataException("PAC Logon type is invalid.");
            return entry;
        }
        #endregion
    }
}
