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

namespace NtApiDotNet.Security.Policy
{
    /// <summary>
    /// Class representing a Central Access Rule.
    /// </summary>
    public class CentralAccessRule
    {
        /// <summary>
        /// CAP Rule Flags.
        /// </summary>
        public uint Flags { get; }

        /// <summary>
        /// Name of the CAP Rule.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Description of the CAP Rule.
        /// </summary>
        public string Description { get; }

        /// <summary>
        /// Change ID. Normally a date time when changed.
        /// </summary>
        public string ChangeId { get; }

        /// <summary>
        /// Conditional Expression to determine who to applie the rule to.
        /// </summary>
        public string AppliesTo { get; }

        /// <summary>
        /// The CAP Rule security descriptor.
        /// </summary>
        public SecurityDescriptor SecurityDescriptor { get; }

        /// <summary>
        /// The CAP Rule staged security descriptor.
        /// </summary>
        public SecurityDescriptor StagedSecurityDescriptor { get; }

        internal CentralAccessRule(string name, string description, SecurityDescriptor sd,
            SecurityDescriptor staged_sd, string applies_to, string change_id, uint flags)
        {
            Name = name;
            Description = description;
            SecurityDescriptor = sd;
            StagedSecurityDescriptor = staged_sd;
            AppliesTo = applies_to;
            ChangeId = change_id;
            Flags = flags;
        }

        internal static NtResult<CentralAccessRule> FromRegistry(NtKey key, bool throw_on_error)
        {
            string name = string.Empty;
            string description = string.Empty;
            SecurityDescriptor sd = null;
            SecurityDescriptor staged_sd = null;
            string applies_to = string.Empty;
            string change_id = string.Empty;
            uint flags = 0;

            foreach (var value in key.QueryValues())
            {
                switch (value.Name.ToLower())
                {
                    case "appliesto":
                        if (value.Data.Length > 0)
                        {
                            var result = NtSecurity.ConditionalAceToString(value.Data, throw_on_error);
                            if (!result.IsSuccess)
                                return result.Cast<CentralAccessRule>();
                            applies_to = result.Result;
                        }
                        break;
                    case "sd":
                        {
                            var sd_result = SecurityDescriptor.Parse(value.Data, throw_on_error);
                            if (!sd_result.IsSuccess)
                                return sd_result.Cast<CentralAccessRule>();
                            sd = sd_result.Result;
                        }
                        break;
                    case "stagedsd":
                        {
                            var sd_result = SecurityDescriptor.Parse(value.Data, throw_on_error);
                            if (!sd_result.IsSuccess)
                                return sd_result.Cast<CentralAccessRule>();
                            staged_sd = sd_result.Result;
                        }
                        break;
                    case "changeid":
                        change_id = value.ToString().TrimEnd('\0');
                        break;
                    case "description":
                        description = value.ToString().TrimEnd('\0');
                        break;
                    case "flags":
                        if (value.Type == RegistryValueType.Dword)
                        {
                            flags = (uint)value.ToObject();
                        }
                        break;
                    case "name":
                        name = value.ToString().TrimEnd('\0');
                        break;
                }
            }
            return new CentralAccessRule(name, description, sd, staged_sd, applies_to, change_id, flags).CreateResult();
        }
    }
}
