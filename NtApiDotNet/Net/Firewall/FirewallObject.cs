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
using System;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Abstract class to represent a firewall object.
    /// </summary>
    public abstract class FirewallObject : INtObjectSecurity
    {
        private readonly Lazy<SecurityDescriptor> _get_sd_default;
        private readonly Func<SecurityInformation, bool, NtResult<SecurityDescriptor>> _get_sd;
        private protected readonly FirewallEngine _engine;

        /// <summary>
        /// The object's key.
        /// </summary>
        public Guid Key { get; }
        /// <summary>
        /// The object's name.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The object's description.
        /// </summary>
        public string Description { get; }
        /// <summary>
        /// The object's key name.
        /// </summary>
        public string KeyName { get; }
        /// <summary>
        /// The object's security descriptor.
        /// </summary>
        public SecurityDescriptor SecurityDescriptor => _get_sd_default.Value;

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <returns>The security descriptor</returns>
        /// <remarks>The firewall engine object must still be open.</remarks>
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
        /// <remarks>The firewall engine object must still be open.</remarks>
        public NtResult<SecurityDescriptor> GetSecurityDescriptor(SecurityInformation security_information, bool throw_on_error)
        {
            return _get_sd(security_information, throw_on_error);
        }

        string INtObjectSecurity.ObjectName => Name;

        NtType INtObjectSecurity.NtType => FirewallUtils.FirewallType;

        bool INtObjectSecurity.IsContainer => false;

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

        private protected FirewallObject(Guid key, FWPM_DISPLAY_DATA0 display_data, NamedGuidDictionary key_to_name, FirewallEngine engine,
            Func<SecurityInformation, bool, NtResult<SecurityDescriptor>> get_sd)
        {
            Key = key;
            Name = display_data.name ?? string.Empty;
            Description = display_data.description ?? string.Empty;
            KeyName = key_to_name.GetName(key);
            _engine = engine;
            _get_sd = get_sd;
            _get_sd_default = new Lazy<SecurityDescriptor>(() => ((INtObjectSecurity)this).GetSecurityDescriptor(SecurityInformation.Owner 
                | SecurityInformation.Group | SecurityInformation.Dacl));
        }
    }
}
