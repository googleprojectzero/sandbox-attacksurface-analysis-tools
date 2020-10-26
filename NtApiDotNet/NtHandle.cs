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
using System.IO;

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
        /// Get the image path for the process which contains this handle.
        /// </summary>
        public string ProcessImagePath { get; }

        /// <summary>
        /// Get name of the process which contains this handle.
        /// </summary>
        public string ProcessName => Path.GetFileName(ProcessImagePath);

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
        /// Whether the handle has write access.
        /// </summary>
        public bool HasWriteAccess => NtType?.HasWritePermission(GrantedAccess) ?? false;
        /// <summary>
        /// Whether the handle has read access.
        /// </summary>
        public bool HasReadAccess => NtType?.HasReadPermission(GrantedAccess) ?? false;
        /// <summary>
        /// Whether the handle has execute access.
        /// </summary>
        public bool HasExecuteAccess => NtType?.HasExecutePermission(GrantedAccess) ?? false;
        /// <summary>
        /// Whether the handle has full access.
        /// </summary>
        public bool HasFullAccess => NtType?.HasFullPermission(GrantedAccess) ?? false;

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

        /// <summary>
        /// Indicates if the handle was valid.
        /// </summary>
        /// <remarks>This can cause the handle's values to be queried which can take time.</remarks>
        public bool HandleValid
        {
            get
            {
                QueryValues();
                return _handle_valid;
            }
        }

        /// <summary>
        /// Overridden ToString.
        /// </summary>
        /// <returns>The handle as a string.</returns>
        public override string ToString()
        {
            return $"PID: {ProcessId} Type: {ObjectType}";
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
                    if (!_force_file_query && obj.Result.NtTypeName == "File")
                    {
                        using (var file = obj.Result.ToTypedObject() as NtFile)
                        {
                            var device_type = file?.DeviceType ?? FileDeviceType.UNKNOWN;
                            switch (device_type)
                            {
                                case FileDeviceType.DISK:
                                case FileDeviceType.CD_ROM:
                                    break;
                                default:
                                    return;
                            }
                        }
                    }
                    _handle_valid = true;
                    _name = GetName(obj.Result);
                    _sd = GetSecurityDescriptor(obj.Result);
                }
            }
        }

        internal NtHandle(SystemHandleTableInfoEntryEx entry, bool allow_query, bool force_file_query, string process_image_path)
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
            _force_file_query = force_file_query;
            ProcessImagePath = process_image_path;
        }

        internal NtHandle(int process_id, ProcessHandleTableEntryInfo entry, bool allow_query, bool force_file_query, string process_image_path)
        {
            ProcessId = process_id;
            NtType = NtType.GetTypeByIndex(entry.ObjectTypeIndex);
            Attributes = entry.HandleAttributes;
            Handle = entry.HandleValue.ToInt32();
            GrantedAccess = entry.GrantedAccess;
            _allow_query = allow_query;
            _force_file_query = force_file_query;
            ProcessImagePath = process_image_path;
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

        /// <summary>
        /// Close the handle in the original process.
        /// </summary>
        /// <param name="throw_on_error">True throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <remarks>This is not recommended.</remarks>
        public NtStatus CloseHandle(bool throw_on_error)
        {
            return NtObject.CloseHandle(ProcessId, 
                new IntPtr(Handle), throw_on_error);
        }

        /// <summary>
        /// Close the handle in the original process.
        /// </summary>
        /// <remarks>This is not recommended.</remarks>
        public void CloseHandle()
        {
            CloseHandle(true);
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
        private bool _force_file_query;
        private bool _handle_valid;
    }
}
