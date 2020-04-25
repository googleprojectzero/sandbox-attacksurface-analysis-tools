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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Security.Policy
{
    /// <summary>
    /// Class representing a Central Access Policy.
    /// </summary>
    public class CentralAccessPolicy
    {
        /// <summary>
        /// The CAP SID.
        /// </summary>
        public Sid CapId { get; }

        /// <summary>
        /// CAP Flags.
        /// </summary>
        public uint Flags { get; }

        /// <summary>
        /// Name of the CAP.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Description of the CAP.
        /// </summary>
        public string Description { get; }

        /// <summary>
        /// Change ID. Normally a date time when changed.
        /// </summary>
        public string ChangeId { get; }

        /// <summary>
        /// The list of rules associated with this policy.
        /// </summary>
        public IReadOnlyList<CentralAccessRule> Rules { get; }

        private CentralAccessPolicy(Sid capid, uint flags, string name, string description, string change_id, List<CentralAccessRule> capes)
        {
            CapId = capid;
            Flags = flags;
            Name = name;
            Description = description;
            ChangeId = change_id;
            Rules = capes.AsReadOnly();
        }

        private static NtResult<int[]> ParseCapeNumbers(NtKeyValue value, bool throw_on_error)
        {
            if (value.Type != RegistryValueType.Binary)
                return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<int[]>(throw_on_error);
            if (value.Data.Length % 4 != 0)
                return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<int[]>(throw_on_error);
            int[] ret = new int[value.Data.Length / 4];
            Buffer.BlockCopy(value.Data, 0, ret, 0, value.Data.Length);
            return ret.CreateResult();
        }

        internal static NtResult<CentralAccessPolicy> FromRegistry(NtKey key, Dictionary<int, CentralAccessRule> rules, bool throw_on_error)
        {
            List<CentralAccessRule> capes = new List<CentralAccessRule>();
            string name = string.Empty;
            string description = string.Empty;
            Sid capid = null;
            string change_id = string.Empty;
            uint flags = 0;

            foreach (var value in key.QueryValues())
            {
                switch (value.Name.ToLower())
                {
                    case "capes":
                        var idxs = ParseCapeNumbers(value, throw_on_error);
                        if (!idxs.IsSuccess)
                            return idxs.Cast<CentralAccessPolicy>();
                        foreach (var idx in idxs.Result)
                        {
                            if (rules.ContainsKey(idx))
                            {
                                capes.Add(rules[idx]);
                            }
                            else
                            {
                                return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<CentralAccessPolicy>(throw_on_error);
                            }
                        }
                        break;
                    case "capid":
                        var sid = Sid.Parse(value.Data, false);
                        if (!sid.IsSuccess)
                            return sid.Cast<CentralAccessPolicy>();
                        capid = sid.Result;
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
            return new CentralAccessPolicy(capid, flags, name, description, change_id, capes).CreateResult();
        }

        private const string POLICY_KEY = @"\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\CentralizedAccessPolicies";

        private static NtResult<Dictionary<int, CentralAccessRule>> ReadRules(NtKey base_key, bool throw_on_error)
        {
            Dictionary<int, CentralAccessRule> rules = new Dictionary<int, CentralAccessRule>();
            using (var key = base_key.Open("CAPEs", KeyAccessRights.EnumerateSubKeys, throw_on_error))
            {
                if (!key.IsSuccess)
                    return key.Cast<Dictionary<int, CentralAccessRule>>();
                using (var list = key.Result.QueryAccessibleKeys(KeyAccessRights.QueryValue).ToDisposableList())
                {
                    foreach (var subkey in list)
                    {
                        if (!int.TryParse(subkey.Name, out int index))
                            continue;
                        var rule = CentralAccessRule.FromRegistry(subkey, throw_on_error);
                        if (!rule.IsSuccess)
                            return rule.Cast<Dictionary<int, CentralAccessRule>>();
                        rules[index] = rule.Result;
                    }
                }
            }
            return rules.CreateResult();
        }

        private static NtResult<CentralAccessPolicy[]> ReadPolicies(NtKey base_key, Dictionary<int, CentralAccessRule> rules, bool throw_on_error)
        {
            List<CentralAccessPolicy> policies = new List<CentralAccessPolicy>();
            using (var key = base_key.Open("CAPs", KeyAccessRights.EnumerateSubKeys, throw_on_error))
            {
                if (!key.IsSuccess)
                    return key.Cast<CentralAccessPolicy[]>();
                using (var list = key.Result.QueryAccessibleKeys(KeyAccessRights.QueryValue).ToDisposableList())
                {
                    foreach (var subkey in list)
                    {
                        if (!int.TryParse(subkey.Name, out int index))
                            continue;
                        var policy = FromRegistry(subkey, rules, throw_on_error);
                        if (!policy.IsSuccess)
                            return policy.Cast<CentralAccessPolicy[]>();
                        policies.Add(policy.Result);
                    }
                }
            }
            return policies.ToArray().CreateResult();
        }

        /// <summary>
        /// Parse the policy from the registry.
        /// </summary>
        /// <param name="key">The base key for the registry policy.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of Central Access Policies.</returns>
        public static NtResult<CentralAccessPolicy[]> ParseFromRegistry(NtKey key, bool throw_on_error)
        {
            var rules = ReadRules(key, throw_on_error);
            if (!rules.IsSuccess)
                return rules.Cast<CentralAccessPolicy[]>();
            return ReadPolicies(key, rules.Result, throw_on_error);
        }

        /// <summary>
        /// Parse the policy from the registry.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of Central Access Policies.</returns>
        public static NtResult<CentralAccessPolicy[]> ParseFromRegistry(bool throw_on_error)
        {
            using (var key = NtKey.Open(POLICY_KEY,
                null, KeyAccessRights.EnumerateSubKeys, KeyCreateOptions.NonVolatile, throw_on_error))
            {
                if (!key.IsSuccess)
                    return key.Cast<CentralAccessPolicy[]>();
                return ParseFromRegistry(key.Result, throw_on_error);
            }
        }

        /// <summary>
        /// Parse the policy from the registry.
        /// </summary>
        /// <returns>The list of Central Access Policies.</returns>
        public static CentralAccessPolicy[] ParseFromRegistry()
        {
            return ParseFromRegistry(true).Result;
        }

        /// <summary>
        /// Parse the policy from the Local Security Authority.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of Central Access Policies.</returns>
        public static NtResult<CentralAccessPolicy[]> ParseFromLsa(bool throw_on_error)
        {
            NtStatus status = SecurityNativeMethods.LsaGetAppliedCAPIDs(null, out SafeLsaMemoryBuffer capids, out int capid_count);
            if (!status.IsSuccess())
                return status.CreateResultFromError<CentralAccessPolicy[]>(throw_on_error);
            List<CentralAccessPolicy> ret = new List<CentralAccessPolicy>();
            using (capids)
            {
                status = SecurityNativeMethods.LsaQueryCAPs(capids.DangerousGetHandle(), capid_count, out SafeLsaMemoryBuffer caps, out uint cap_count);
                if (!status.IsSuccess())
                    return status.CreateResultFromError<CentralAccessPolicy[]>(throw_on_error);
                caps.Initialize<CENTRAL_ACCESS_POLICY>(cap_count);
                CENTRAL_ACCESS_POLICY[] policies = new CENTRAL_ACCESS_POLICY[cap_count];
                caps.ReadArray(0, policies, 0, policies.Length);
                foreach (var policy in policies)
                {
                    SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(policy.CAPEs, policy.CAPECount * IntPtr.Size, false);
                    IntPtr[] rule_entries = new IntPtr[policy.CAPECount];
                    buffer.ReadArray(0, rule_entries, 0, policy.CAPECount);
                    List<CentralAccessRule> rules = new List<CentralAccessRule>();
                    foreach (var ptr in rule_entries)
                    {
                        var entry = new SafeStructureInOutBuffer<CENTRAL_ACCESS_POLICY_ENTRY>(ptr, Marshal.SizeOf(typeof(CENTRAL_ACCESS_POLICY_ENTRY)), false);
                        var r = entry.Result;
                        SecurityDescriptor sd = null;
                        SecurityDescriptor staged_sd = null;
                        string applies_to = string.Empty;
                        if (r.LengthSD > 0)
                        {
                            var result = SecurityDescriptor.Parse(r.SD, throw_on_error);
                            if (!result.IsSuccess)
                                return result.Cast<CentralAccessPolicy[]>();
                            sd = result.Result;
                        }
                        if (r.LengthStagedSD > 0)
                        {
                            var result = SecurityDescriptor.Parse(r.StagedSD, throw_on_error);
                            if (!result.IsSuccess)
                                return result.Cast<CentralAccessPolicy[]>();
                            staged_sd = result.Result;
                        }
                        if (r.LengthAppliesTo > 0)
                        {
                            byte[] condition = new byte[r.LengthAppliesTo];
                            Marshal.Copy(r.AppliesTo, condition, 0, r.LengthAppliesTo);
                            var result = NtSecurity.ConditionalAceToString(condition, throw_on_error);
                            if (!result.IsSuccess)
                                return result.Cast<CentralAccessPolicy[]>();
                            applies_to = result.Result;
                        }

                        rules.Add(new CentralAccessRule(r.Name.ToString(), r.Description.ToString(),
                            sd, staged_sd, applies_to, r.ChangeId.ToString(), r.Flags));
                    }
                    var capid = Sid.Parse(policy.CAPID, throw_on_error);
                    if (!capid.IsSuccess)
                        return capid.Cast<CentralAccessPolicy[]>();
                    ret.Add(new CentralAccessPolicy(capid.Result, policy.Flags, policy.Name.ToString(), 
                        policy.Description.ToString(), policy.ChangeId.ToString(), rules));
                }
            }
            return ret.ToArray().CreateResult();
        }

        /// <summary>
        /// Parse the policy from the Local Security Authority.
        /// </summary>
        /// <returns>The list of Central Access Policies.</returns>
        public static CentralAccessPolicy[] ParseFromLsa()
        {
            return ParseFromLsa(true).Result;
        }
    }
}
