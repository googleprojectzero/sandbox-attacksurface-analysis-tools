//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent PAC Device Info.
    /// </summary>
    public class KerberosAuthorizationDataPACDevice : KerberosAuthorizationDataPACEntry
    {
        /// <summary>
        /// Sid of the Device.
        /// </summary>
        public Sid DeviceId { get; }
        /// <summary>
        /// Primary group SID.
        /// </summary>
        public Sid PrimaryGroupId { get; }
        /// <summary>
        /// List of account groups.
        /// </summary>
        public IReadOnlyList<UserGroup> AccountGroups { get; }
        /// <summary>
        /// List of extra SIDs.
        /// </summary>
        public IReadOnlyList<UserGroup> ExtraSids { get; }
        /// <summary>
        /// List of domain groups.
        /// </summary>
        public IReadOnlyList<UserGroup> DomainGroups { get; }

        private KerberosAuthorizationDataPACDevice(byte[] data, PAC_DEVICE_INFO device_info)
            : base(KerberosAuthorizationDataPACEntryType.Device, data)
        {
            Sid account_domain_sid = device_info.AccountDomainId.GetValue().ToSid();
            DeviceId = account_domain_sid.CreateRelative((uint)device_info.UserId);
            PrimaryGroupId = account_domain_sid.CreateRelative((uint)device_info.PrimaryGroupId);
            List <UserGroup> groups = new List<UserGroup>();
            if (device_info.AccountGroupIds != null)
            {
                groups.AddRange(device_info.AccountGroupIds.GetValue()
                    .Select(g => new UserGroup(account_domain_sid.CreateRelative((uint)g.RelativeId), (GroupAttributes)g.Attributes)));
            }
            AccountGroups = groups.AsReadOnly();

            groups = new List<UserGroup>();
            if (device_info.ExtraSids != null)
            {
                groups.AddRange(device_info.ExtraSids.GetValue()
                    .Select(g => new UserGroup(g.Sid.GetValue().ToSid(), (GroupAttributes)g.Attributes)));
            }
            ExtraSids = groups.AsReadOnly();

            groups = new List<UserGroup>();
            if (device_info.DomainGroup != null)
            {
                foreach (var group in device_info.DomainGroup.GetValue())
                {
                    if (group.GroupIds != null)
                    {
                        Sid group_sid = group.DomainId.GetValue().ToSid();
                        groups.AddRange(group.GroupIds.GetValue()
                            .Select(g => new UserGroup(group_sid.CreateRelative((uint)g.RelativeId), (GroupAttributes)g.Attributes)));
                    }
                }
            }
            DomainGroups = groups.AsReadOnly();
        }

        internal static bool Parse(byte[] data, out KerberosAuthorizationDataPACEntry entry)
        {
            entry = null;
            try
            {
                var info = PacDeviceInfoParser.Decode(new NdrPickledType(data));
                if (!info.HasValue)
                    return false;

                entry = new KerberosAuthorizationDataPACDevice(data, info.Value);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private protected override void FormatData(StringBuilder builder)
        {
            builder.AppendLine($"Device Name      : {DeviceId.Name}");
            builder.AppendLine($"Primary Group    : {PrimaryGroupId.Name}");

            if (AccountGroups.Count > 0)
            {
                builder.AppendLine("<Groups>");
                foreach (var g in AccountGroups)
                {
                    builder.AppendLine($"{g.Sid.Name,-30} - {g.Attributes}");
                }
            }

            if (DomainGroups.Count > 0)
            {
                builder.AppendLine("<Domain Groups>");
                foreach (var g in DomainGroups)
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
        }
    }
}
