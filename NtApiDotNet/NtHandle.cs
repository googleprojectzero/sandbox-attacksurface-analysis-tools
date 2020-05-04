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

using System;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent a system handle
    /// </summary>
    public class NtHandle
    {
        /// <summary>
        /// The ID of the process holding the handle
        /// </summary>
        public int ProcessId { get; }

        /// <summary>
        /// The object type index
        /// </summary>
        public int ObjectTypeIndex { get; }

        /// <summary>
        /// The object type name
        /// </summary>
        public string ObjectType
        {
            get
            {
                if (NtType == null)
                {
                    return $"Unknown Type: {ObjectTypeIndex}";
                }
                return NtType.Name;
            }
        }

        /// <summary>
        /// The object type
        /// </summary>
        public NtType NtType { get; private set; }

        /// <summary>
        /// The handle attribute flags.
        /// </summary>
        public AttributeFlags Attributes { get; }

        /// <summary>
        /// The handle value
        /// </summary>
        public int Handle { get; }

        /// <summary>
        /// The address of the object.
        /// </summary>
        public ulong Object { get; }

        /// <summary>
        /// The granted access mask
        /// </summary>
        public AccessMask GrantedAccess { get; }

        /// <summary>
        /// The granted access mask as a string.
        /// </summary>
        public string GrantedAccessString => NtType?.AccessMaskToString(GrantedAccess) ?? $"0x{GrantedAccess:X08}";

        /// <summary>
        /// The granted access mask as a string.
        /// </summary>
        public string GrantedGenericAccessString => NtType?.AccessMaskToString(GrantedAccess, true) ?? $"0x{GrantedAccess:X08}";

        /// <summary>
        /// Whether the handle is inheritable.
        /// </summary>
        public bool Inherit => Attributes.HasFlag(AttributeFlags.Inherit);

        /// <summary>
        /// Whether the handle is protected from close.
        /// </summary>
        public bool ProtectFromClose => Attributes.HasFlag(AttributeFlags.ProtectClose);

        /// <summary>
        /// The name of the object (needs to have set query access in constructor)
        /// </summary>
        public string Name
        {
            get
            {
                QueryValues();
                return _name ?? string.Empty;
            }
        }

        /// <summary>
        /// The security of the object  (needs to have set query access in constructor)
        /// </summary>
        public SecurityDescriptor SecurityDescriptor
        {
            get
            {
                QueryValues();
                return _sd;
            }
        }

        private void QueryValues()
        {
            if (_allow_query)
            {
                _allow_query = false;
                NtToken.EnableDebugPrivilege();
                using (var obj = NtGeneric.DuplicateFrom(ProcessId,
                    new IntPtr(Handle), 0, DuplicateObjectOptions.SameAccess, false))
                {
                    if (!obj.IsSuccess)
                    {
                        return;
                    }

                    NtType = obj.Result.NtType;
                    _name = GetName(obj.Result);
                    _sd = GetSecurityDescriptor(obj.Result);
                }
            }
        }

        internal NtHandle(SystemHandleTableInfoEntryEx entry, bool allow_query)
        {
            ProcessId = entry.UniqueProcessId.ToInt32();
            NtType info = NtType.GetTypeByIndex(entry.ObjectTypeIndex);
            if (info != null)
            {
                NtType = info;
            }

            Attributes = (AttributeFlags)entry.HandleAttributes;
            Handle = entry.HandleValue.ToInt32();
            Object = entry.Object.ToUInt64();
            GrantedAccess = entry.GrantedAccess;
            _allow_query = allow_query;
        }

        internal NtHandle(int process_id, ProcessHandleTableEntryInfo entry, bool allow_query)
        {
            ProcessId = process_id;
            NtType = NtType.GetTypeByIndex(entry.ObjectTypeIndex);
            Attributes = entry.HandleAttributes;
            Handle = entry.HandleValue.ToInt32();
            GrantedAccess = entry.GrantedAccess;
            _allow_query = allow_query;
        }

        /// <summary>
        /// Get handle into the current process
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The handle to the object</returns>
        public NtResult<NtObject> GetObject(bool throw_on_error)
        {
            NtToken.EnableDebugPrivilege();
            using (var result = NtGeneric.DuplicateFrom(ProcessId, new IntPtr(Handle), 0,
                DuplicateObjectOptions.SameAccess | DuplicateObjectOptions.SameAttributes, throw_on_error))
            {
                if (!result.IsSuccess)
                {
                    return result.Cast<NtObject>();
                }

                NtGeneric generic = result.Result;

                // Ensure that we get the actual type from the handle.
                NtType = generic.NtType;
                return generic.ToTypedObject(throw_on_error).Cast<NtObject>();
            }
        }

        /// <summary>
        /// Get handle into the current process
        /// </summary>
        /// <returns>The handle to the object</returns>
        public NtObject GetObject()
        {
            return GetObject(true).Result;
        }

        private string GetName(NtGeneric obj)
        {
            if (obj == null)
            {
                return string.Empty;
            }
            return obj.FullPath;
        }

        private SecurityDescriptor GetSecurityDescriptor(NtGeneric obj)
        {
            if (obj != null)
            {
                using (var dup = obj.Duplicate(GenericAccessRights.ReadControl, false))
                {
                    if (!dup.IsSuccess)
                    {
                        return null;
                    }
                    var sd = dup.Result.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
                    if (!sd.IsSuccess)
                    {
                        return null;
                    }
                    return sd.Result;
                }
            }
            return null;
        }

        private string _name;
        private SecurityDescriptor _sd;
        private bool _allow_query;
    }
}
