﻿//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
#pragma warning disable 1591
    /// <summary>
    /// User account control flags.
    /// </summary>
    [Flags]
    public enum UserAccountControlFlags
    {
        None = 0,
        AccountDisabled = 0x00000001,
        HomeDirectoryRequired = 0x00000002,
        PasswordNotRequired = 0x00000004,
        TempDuplicateAccount = 0x00000008,
        NormalAccount = 0x00000010,
        MnsLogonAccount = 0x00000020,
        InterdomainTrustAccount = 0x00000040,
        WorkstationTrustAccount = 0x00000080,
        ServerTrustAccount = 0x00000100,
        DontExpirePassword = 0x00000200,
        AccountAutoLocked = 0x00000400,
        EncryptedTextPasswordAllowed = 0x00000800,
        SmartcardRequired = 0x00001000,
        TrustedForDelegation = 0x00002000,
        NotDelegated = 0x00004000,
        UseDesKeyOnly = 0x00008000,
        DontRequirePreauth = 0x00010000,
        PasswordExpired = 0x00020000,
        TrustedToAuthenticateForDelegation = 0x00040000,
        NoAuthDataRequired = 0x00080000,
        PartialSecretsAccount = 0x00100000,
        UseAesKeys = 0x00200000,
    }

    /// <summary>
    /// User flags for kerberos authentication.
    /// </summary>
    [Flags]
    public enum KerberosUserFlags
    {
        None = 0,
        Guest = 0x0001,
        NoEncryption = 0x0002,
        LanManKey = 0x0008,
        ExtraSidsPresent = 0x0020,
        SubAuthentication = 0x0040,
        MachineAccount = 0x0080,
        NTLMv2 = 0x0100,
        ResourceGroupsPresent = 0x0200,
        ProfilePathPresent = 0x0400,
        NTLMv2Used = 0x0800,
        LMv2Used = 0x1000,
        LMV2UsedNTLMv2Session = 0x2000
    }

#pragma warning restore 1591

    /// <summary>
    /// Class to represent PAC Logon Information.
    /// </summary>
    public sealed class KerberosAuthorizationDataPACLogon : KerberosAuthorizationDataPACEntry
    {
        /// <summary>
        /// Logon time.
        /// </summary>
        public DateTime LogonTime { get; set; }
        /// <summary>
        /// Logoff time.
        /// </summary>
        public DateTime LogoffTime { get; set; }
        /// <summary>
        /// Kick off time.
        /// </summary>
        public DateTime KickOffTime { get; set; }
        /// <summary>
        /// Time password last set.
        /// </summary>
        public DateTime PasswordLastSet { get; set; }
        /// <summary>
        /// Time password can change.
        /// </summary>
        public DateTime PasswordCanChange { get; set; }
        /// <summary>
        /// Time password must change.
        /// </summary>
        public DateTime PasswordMustChange { get; set; }
        /// <summary>
        /// Effective name.
        /// </summary>
        public string EffectiveName { get; set; }
        /// <summary>
        /// Full name.
        /// </summary>
        public string FullName { get; set; }
        /// <summary>
        /// Logon script path.
        /// </summary>
        public string LogonScript { get; set; }
        /// <summary>
        /// Profile path.
        /// </summary>
        public string ProfilePath { get; set; }
        /// <summary>
        /// Home directory path.
        /// </summary>
        public string HomeDirectory { get; set; }
        /// <summary>
        /// Home directory drive.
        /// </summary>
        public string HomeDirectoryDrive { get; set; }
        /// <summary>
        /// Logon count.
        /// </summary>
        public int LogonCount { get; set; }
        /// <summary>
        /// Bad password count.
        /// </summary>
        public int BadPasswordCount { get; set; }
        /// <summary>
        /// User SID.
        /// </summary>
        public Sid User { get; set; }
        /// <summary>
        /// Primary group SID.
        /// </summary>
        public Sid PrimaryGroup { get; set; }
        /// <summary>
        /// Group list.
        /// </summary>
        public List<UserGroup> Groups { get; set; }
        /// <summary>
        /// User flags.
        /// </summary>
        public KerberosUserFlags UserFlags { get; set; }
        /// <summary>
        /// User session key.
        /// </summary>
        public byte[] UserSessionKey { get; set; }
        /// <summary>
        /// Logon server name.
        /// </summary>
        public string LogonServer { get; set; }
        /// <summary>
        /// Logon domain name.
        /// </summary>
        public string LogonDomainName { get; set; }
        /// <summary>
        /// Logon domain sid.
        /// </summary>
        public Sid LogonDomainSid { get; set; }
        /// <summary>
        /// Extra SIDs.
        /// </summary>
        public List<UserGroup> ExtraSids { get; set; }
        /// <summary>
        /// User account control flags.
        /// </summary>
        public UserAccountControlFlags UserAccountControl { get; set; }
        /// <summary>
        /// Resource domain group SID.
        /// </summary>
        public Sid ResourceGroupDomainSid { get; set; }
        /// <summary>
        /// Resource groups.
        /// </summary>
        public List<UserGroup> ResourceGroups { get; set;  }

        private KERB_VALIDATION_INFO _logon_info;

        internal KerberosAuthorizationDataPACLogon(KerberosAuthorizationDataPACEntryType type,
            byte[] data, KERB_VALIDATION_INFO logon_info) : base(type, data)
        {
            this._logon_info = logon_info;

            LogonTime = logon_info.LogonTime.ToTime();
            LogoffTime = logon_info.LogoffTime.ToTime();
            KickOffTime = logon_info.KickOffTime.ToTime();
            PasswordLastSet = logon_info.PasswordLastSet.ToTime();
            PasswordCanChange = logon_info.PasswordCanChange.ToTime();
            PasswordMustChange = logon_info.PasswordMustChange.ToTime();
            EffectiveName = logon_info.EffectiveName.ToString();
            FullName = logon_info.FullName.ToString();
            LogonScript = logon_info.LogonScript.ToString();
            ProfilePath = logon_info.ProfilePath.ToString();
            HomeDirectory = logon_info.HomeDirectory.ToString();
            HomeDirectoryDrive = logon_info.HomeDirectoryDrive.ToString();
            LogonCount = logon_info.LogonCount;
            BadPasswordCount = logon_info.BadPasswordCount;
            LogonDomainSid = logon_info.LogonDomainId.GetValue().ToSid();
            LogonDomainName = logon_info.LogonDomainName.ToString();

            User = LogonDomainSid.CreateRelative((uint)logon_info.UserId);
            PrimaryGroup = LogonDomainSid.CreateRelative((uint) logon_info.PrimaryGroupId);

            if (logon_info.GroupIds != null)
            {
                Groups = logon_info.GroupIds.GetValue().Select(r => new UserGroup(LogonDomainSid.CreateRelative((uint)r.RelativeId), (GroupAttributes)r.Attributes)).ToList();
            }
            else
            {
                Groups = new List<UserGroup>(0);
            }

            UserFlags = (KerberosUserFlags)logon_info.UserFlags;
            List<sbyte> session_key = new List<sbyte>();
            if (logon_info.UserSessionKey.data != null)
            {
                foreach (var key in logon_info.UserSessionKey.data)
                {
                    if (key.data != null)
                    {
                        session_key.AddRange(key.data);
                    }
                }
            }

            UserSessionKey = (byte[])(object)session_key.ToArray();
            LogonServer = logon_info.LogonServer.ToString();
            LogonDomainName = logon_info.LogonDomainName.ToString();

            if (logon_info.ExtraSids != null)
            {
                ExtraSids = logon_info.ExtraSids.GetValue().Select(r => new UserGroup(r.Sid.GetValue().ToSid(), (GroupAttributes)r.Attributes)).ToList();
            }
            else
            {
                ExtraSids = new List<UserGroup>(0);
            }

            UserAccountControl = (UserAccountControlFlags)logon_info.UserAccountControl;
            if (logon_info.ResourceGroupDomainSid != null)
            {
                ResourceGroupDomainSid = logon_info.ResourceGroupDomainSid.GetValue().ToSid();
            }

            if (logon_info.ResourceGroupIds != null)
            {
                ResourceGroups = logon_info.ResourceGroupIds.GetValue().Select(r => new UserGroup(LogonDomainSid.CreateRelative((uint)r.RelativeId), (GroupAttributes)r.Attributes)).ToList();
            }
            else
            {
                ResourceGroups = new List<UserGroup>(0);
            }
        }

        internal static bool Parse(KerberosAuthorizationDataPACEntryType type, byte[] data, out KerberosAuthorizationDataPACEntry entry)
        {
            entry = null;
            try
            {
                var info = KerbValidationInfoParser.Decode(new NdrPickledType(data));
                if (!info.HasValue)
                    return false;
                entry = new KerberosAuthorizationDataPACLogon(type, data, info.Value);
                return true;
            }
            catch
            {
                return false;
            }
        }

        internal protected override byte[] Encode()
        {
            KERB_VALIDATION_INFO logon_info = new KERB_VALIDATION_INFO()
            {
                // Tracking and inserting this._logon_info values is inefficient, but our casting
                // can slightly alter values and we want to maintain checksums where possible
                LogonTime = LogonTime == DateTime.MaxValue ? _logon_info.LogonTime : new FILETIME(LogonTime),
                LogoffTime = LogoffTime == DateTime.MaxValue ? _logon_info.LogoffTime : new FILETIME(LogoffTime),
                KickOffTime = KickOffTime == DateTime.MaxValue ? _logon_info.KickOffTime : new FILETIME(KickOffTime),
                PasswordLastSet = PasswordLastSet == DateTime.MaxValue ? _logon_info.PasswordLastSet : new FILETIME(PasswordLastSet),
                PasswordCanChange = PasswordCanChange == DateTime.MaxValue ? _logon_info.PasswordCanChange : new FILETIME(PasswordCanChange),
                PasswordMustChange = PasswordMustChange == DateTime.MaxValue ? _logon_info.PasswordMustChange : new FILETIME(PasswordMustChange),
                EffectiveName = EffectiveName == _logon_info.EffectiveName.ToString() ? _logon_info.EffectiveName : new RPC_UNICODE_STRING(EffectiveName),
                FullName = FullName == _logon_info.FullName.ToString() ? _logon_info.FullName : new RPC_UNICODE_STRING(FullName),
                LogonScript = LogonScript == _logon_info.LogonScript.ToString() ? _logon_info.LogonScript : new RPC_UNICODE_STRING(LogonScript),
                ProfilePath = ProfilePath == _logon_info.ProfilePath.ToString() ? _logon_info.ProfilePath : new RPC_UNICODE_STRING(ProfilePath),
                HomeDirectory = HomeDirectory == _logon_info.HomeDirectory.ToString() ? _logon_info.HomeDirectory : new RPC_UNICODE_STRING(HomeDirectory),
                HomeDirectoryDrive = HomeDirectoryDrive == _logon_info.HomeDirectoryDrive.ToString() ? _logon_info.HomeDirectoryDrive : new RPC_UNICODE_STRING(HomeDirectoryDrive),
                LogonCount = (short)LogonCount,
                BadPasswordCount = (short)BadPasswordCount,
                UserId = (int)User.SubAuthorities.Last(),
                PrimaryGroupId = (int)PrimaryGroup.SubAuthorities.Last(),
                GroupCount = Groups.Count,
                GroupIds = Groups.Select(g => new GROUP_MEMBERSHIP() { RelativeId = (int)g.Sid.SubAuthorities.Last(), Attributes = (int)g.Attributes }).ToArray(),
                UserFlags = (int)UserFlags,
                LogonServer = LogonServer == _logon_info.LogonServer.ToString() ? _logon_info.LogonServer : new RPC_UNICODE_STRING(LogonServer),
                LogonDomainName = LogonDomainName == _logon_info.LogonDomainName.ToString() ? _logon_info.LogonDomainName : new RPC_UNICODE_STRING(LogonDomainName),
                LogonDomainId = new RPC_SID(LogonDomainSid),
                Reserved1 = _logon_info.Reserved1,
                UserAccountControl = (int)UserAccountControl,
                Reserved3 = _logon_info.Reserved3,
                SidCount = ExtraSids.Count,
                ExtraSids = ExtraSids.Select(s => new KERB_SID_AND_ATTRIBUTES() { Sid = new RPC_SID(s.Sid), Attributes = (int)s.Attributes }).ToArray(),
                ResourceGroupCount = ResourceGroups.Count,
                ResourceGroupIds = ResourceGroups.Count > 0 ? ResourceGroups.Select(g => new GROUP_MEMBERSHIP() { RelativeId = (int)g.Sid.SubAuthorities.Last(), Attributes = (int)g.Attributes }).ToArray() : null,
            };

            if (ResourceGroupDomainSid != null)
            {
                logon_info.ResourceGroupDomainSid = new RPC_SID(ResourceGroupDomainSid);
            }

            if (UserSessionKey.Length > 0)
            {
                if (UserSessionKey.Length != 16)
                {
                    throw new NotImplementedException();
                }

                logon_info.UserSessionKey = new USER_SESSION_KEY()
                {
                    data = new CYPHER_BLOCK[]
                    {
                        new CYPHER_BLOCK() { data = (sbyte[])(object)UserSessionKey.Take(8).ToArray() },
                        new CYPHER_BLOCK() { data = (sbyte[])(object)UserSessionKey.Skip(8).ToArray() },
                    }
                };
            }


            return KerbValidationInfoParser.Encode(logon_info);
        }

        private protected override void FormatData(StringBuilder builder)
        {
            builder.AppendLine("<User Information>");
            builder.AppendLine($"Effective Name   : {EffectiveName}");
            builder.AppendLine($"Full Name        : {FullName}");
            builder.AppendLine($"User SID         : {User}");
            builder.AppendLine($"Primary Group    : {PrimaryGroup.Name}");
            builder.AppendLine($"Primary Group SID: {PrimaryGroup}");

            if (Groups.Count > 0)
            {
                builder.AppendLine("<Groups>");
                foreach (var g in Groups)
                {
                    builder.AppendLine($"{g.Sid.Name,-30} - {g.Attributes}");
                }
            }

            if (ResourceGroups.Count > 0 || ResourceGroupDomainSid != null)
            {
                builder.AppendLine("<Resource Groups>");
                if (ResourceGroupDomainSid != null)
                {
                    builder.AppendLine($"Resource Group   : {ResourceGroupDomainSid}");
                }

                foreach (var g in ResourceGroups)
                {
                    builder.AppendLine($"{g.Sid.Name,-30} - {g.Attributes}");
                }
            }

            if (ExtraSids.Count > 0)
            {
                builder.AppendLine("<Extra Groups>");
                foreach (var g in ExtraSids)
                {
                    builder.AppendLine($"{g.Sid.Name,-30} - {g.Attributes}");
                }
            }

            builder.AppendLine("<Account Details>");
            if (LogonTime != DateTime.MaxValue)
                builder.AppendLine($"Logon Time       : {LogonTime}");
            if (LogoffTime != DateTime.MaxValue)
                builder.AppendLine($"Logoff Time      : {LogoffTime}");
            if (KickOffTime != DateTime.MaxValue)
                builder.AppendLine($"Kickoff Time     : {KickOffTime}");
            if (PasswordLastSet != DateTime.MaxValue)
                builder.AppendLine($"Password Last Set: {PasswordLastSet}");
            if (PasswordCanChange != DateTime.MaxValue)
                builder.AppendLine($"Password Change  : {PasswordCanChange}");
            if (PasswordMustChange != DateTime.MaxValue)
                builder.AppendLine($"Password Must    : {PasswordMustChange}");
            builder.AppendLine($"Logon Count      : {LogonCount}");
            builder.AppendLine($"Bad Password #   : {BadPasswordCount}");
            if (!string.IsNullOrEmpty(LogonScript))
                builder.AppendLine($"Logon Script     : {LogonScript}");
            if (!string.IsNullOrEmpty(ProfilePath))
                builder.AppendLine($"Profile Path     : {ProfilePath}");
            if (!string.IsNullOrEmpty(HomeDirectory))
                builder.AppendLine($"Home Directory   : {HomeDirectory}");
            if (!string.IsNullOrEmpty(HomeDirectoryDrive))
                builder.AppendLine($"Home Drive       : {HomeDirectoryDrive}");
            if (!string.IsNullOrEmpty(LogonServer))
                builder.AppendLine($"Logon Server     : {LogonServer}");
            if (!string.IsNullOrEmpty(LogonDomainName))
                builder.AppendLine($"Logon Domain     : {LogonDomainName}");
            builder.AppendLine($"Logon Domain SID : {LogonDomainSid}");
            builder.AppendLine($"User Flags       : {UserFlags}");
            builder.AppendLine($"User Account Cntl: {UserAccountControl}");
            builder.AppendLine($"Session Key      : {NtObjectUtils.ToHexString(UserSessionKey)}");
        }
    }
}
