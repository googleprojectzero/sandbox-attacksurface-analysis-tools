//  Copyright 2019 Google Inc. All Rights Reserved.
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

using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Access rights generic mapping.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct GenericMapping
    {
        /// <summary>
        /// Mapping for Generic Read
        /// </summary>
        public AccessMask GenericRead;
        /// <summary>
        /// Mapping for Generic Write
        /// </summary>
        public AccessMask GenericWrite;
        /// <summary>
        /// Mapping for Generic Execute
        /// </summary>
        public AccessMask GenericExecute;
        /// <summary>
        /// Mapping for Generic All
        /// </summary>
        public AccessMask GenericAll;

        /// <summary>
        /// Map a generic access mask to a specific one.
        /// </summary>
        /// <param name="mask">The generic mask to map.</param>
        /// <returns>The mapped mask.</returns>
        public AccessMask MapMask(AccessMask mask)
        {
            NtRtl.RtlMapGenericMask(ref mask, ref this);
            return mask;
        }

        /// <summary>
        /// Get whether this generic mapping gives read access.
        /// </summary>
        /// <param name="mask">The mask to check against.</param>
        /// <returns>True if we have read access.</returns>
        public bool HasRead(AccessMask mask)
        {
            return (MapMask(mask) & GenericRead).HasAccess;
        }

        /// <summary>
        /// Get whether this generic mapping gives write access.
        /// </summary>
        /// <param name="mask">The mask to check against.</param>
        /// <returns>True if we have write access.</returns>
        public bool HasWrite(AccessMask mask)
        {
            return (MapMask(mask) & ~GenericRead &
                ~GenericExecute & GenericWrite).HasAccess;
        }

        /// <summary>
        /// Get whether this generic mapping gives execute access.
        /// </summary>
        /// <param name="mask">The mask to check against.</param>
        /// <returns>True if we have execute access.</returns>
        public bool HasExecute(AccessMask mask)
        {
            return (MapMask(mask) & ~GenericRead & GenericExecute).HasAccess;
        }

        /// <summary>
        /// Get whether this generic mapping gives all access.
        /// </summary>
        /// <param name="mask">The mask to check against.</param>
        /// <returns>True if we have all access.</returns>
        public bool HasAll(AccessMask mask)
        {
            return MapMask(mask) == GenericAll;
        }

        /// <summary>
        /// Try and unmap access mask to generic rights.
        /// </summary>
        /// <param name="mask">The mask to unmap.</param>
        /// <returns>The unmapped mask. Any access which can be generic mapped is left in the mask as specific rights.</returns>
        public AccessMask UnmapMask(AccessMask mask)
        {
            AccessMask remaining = mask;
            AccessMask result = 0;
            if (mask == GenericAll)
            {
                return GenericAccessRights.GenericAll;
            }
            if ((mask & GenericRead) == GenericRead)
            {
                result |= GenericAccessRights.GenericRead;
                remaining &= ~GenericRead;
            }
            if ((mask & GenericWrite) == GenericWrite)
            {
                result |= GenericAccessRights.GenericWrite;
                remaining &= ~GenericWrite;
            }
            if ((mask & GenericExecute) == GenericExecute)
            {
                result |= GenericAccessRights.GenericExecute;
                remaining &= ~GenericExecute;
            }

            return result | remaining;
        }

        /// <summary>
        /// Get the allowed access mask for a specified mandatory access policy.
        /// </summary>
        /// <param name="policy">The mandatory access policy.</param>
        /// <returns>The allowed access mask for the policy.</returns>
        /// <remarks>In general NoWriteUp will always be set on the policy.</remarks>
        public AccessMask GetAllowedMandatoryAccess(MandatoryLabelPolicy policy)
        {
            bool can_read = !policy.HasFlag(MandatoryLabelPolicy.NoReadUp);
            bool can_write = !policy.HasFlag(MandatoryLabelPolicy.NoWriteUp);
            bool can_execute = !policy.HasFlag(MandatoryLabelPolicy.NoExecuteUp);

            AccessMask allowed_access;
            if (can_write)
            {
                allowed_access = GenericAll | GenericRead | GenericExecute | GenericAccessRights.Synchronize | GenericAccessRights.ReadControl;
            }
            else
            {
                allowed_access = GenericRead | GenericExecute | GenericAccessRights.Synchronize | GenericAccessRights.ReadControl;
            }
            AccessMask allowed_write_access = GenericAccessRights.Delete | GenericAccessRights.WriteDac | GenericAccessRights.WriteOwner | GenericAccessRights.AccessSystemSecurity;
            AccessMask allowed_read_access = GenericAccessRights.ReadControl;
            AccessMask allowed_execute_access = GenericAccessRights.Synchronize;

            if (policy == MandatoryLabelPolicy.None)
                return GenericAll;

            if (!can_read)
            {
                AccessMask temp_mask = 0;
                if (can_write)
                    temp_mask = GenericWrite | allowed_write_access;
                if (can_execute)
                    temp_mask |= (~GenericRead & GenericExecute) | GenericAccessRights.Synchronize;
                temp_mask = ~temp_mask & (GenericRead | allowed_read_access);
                allowed_access &= ~temp_mask;
            }

            if (!can_execute)
            {
                AccessMask temp_mask = 0;
                if (can_write)
                    temp_mask = GenericWrite | allowed_write_access;
                if (can_read)
                    temp_mask |= GenericRead | allowed_read_access;
                temp_mask = ~temp_mask & ((~GenericRead & GenericExecute) | allowed_execute_access);
                allowed_access &= ~temp_mask;
            }

            if (!can_write)
            {
                AccessMask temp_mask = 0;
                if (can_execute)
                    temp_mask = (~GenericRead & GenericExecute) | allowed_execute_access;
                if (can_read)
                    temp_mask |= GenericRead | allowed_read_access;
                temp_mask =  ~temp_mask & (GenericWrite | allowed_write_access);
                allowed_access &= ~temp_mask;
            }

            return allowed_access;
        }

        /// <summary>
        /// Convert generic mapping to a string.
        /// </summary>
        /// <returns>The generic mapping as a string.</returns>
        public override string ToString()
        {
            return $"R:{GenericRead:X08} W:{GenericWrite:X08} E:{GenericExecute:X08} A:{GenericAll:X08}";
        }
    }
}
