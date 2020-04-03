//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Reflection;

namespace NtApiDotNet
{
    /// <summary>
    /// Class representing an NT object type
    /// </summary>
    public sealed class NtType
    {
        #region Public Properties
        /// <summary>
        /// The name of the type
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The mapping from generic to specific object rights
        /// </summary>
        public GenericMapping GenericMapping { get; }
        /// <summary>
        /// The valid access mask
        /// </summary>
        public AccessMask ValidAccess { get; }
        /// <summary>
        /// True if the object needs security even if unnamed
        /// </summary>
        public bool SecurityRequired { get; }
        /// <summary>
        /// Total number of objects (when originally retrieved)
        /// </summary>
        public uint TotalNumberOfObjects { get; }
        /// <summary>
        /// Total number of handles (when originally retrieved)
        /// </summary>
        public uint TotalNumberOfHandles { get; }
        /// <summary>
        /// Total paged pool usage (when originally retrieved)
        /// </summary>
        public uint TotalPagedPoolUsage { get; }
        /// <summary>
        /// Total non-paged pool usage (when originally retrieved)
        /// </summary>
        public uint TotalNonPagedPoolUsage { get; }
        /// <summary>
        /// Total name pool usage (when originally retrieved)
        /// </summary>
        public uint TotalNamePoolUsage { get; }
        /// <summary>
        /// Total handle table usage (when originally retrieved)
        /// </summary>
        public uint TotalHandleTableUsage { get; }
        /// <summary>
        /// Maximum number of objects (when originally retrieved)
        /// </summary>
        public uint HighWaterNumberOfObjects { get; }
        /// <summary>
        /// Maximum number of handles (when originally retrieved)
        /// </summary>
        public uint HighWaterNumberOfHandles { get; }
        /// <summary>
        /// Maximum paged pool usage (when originally retrieved)
        /// </summary>
        public uint HighWaterPagedPoolUsage { get; }
        /// <summary>
        /// Maximum non-paged pool usage (when originally retrieved)
        /// </summary>
        public uint HighWaterNonPagedPoolUsage { get; }
        /// <summary>
        /// Maximum name pool usage (when originally retrieved)
        /// </summary>
        public uint HighWaterNamePoolUsage { get; }
        /// <summary>
        /// Maximum handle table usage (when originally retrieved)
        /// </summary>
        public uint HighWaterHandleTableUsage { get; }
        /// <summary>
        /// The attributes flags which are invalid
        /// </summary>
        public AttributeFlags InvalidAttributes { get; }
        /// <summary>
        /// Indicates whether handle count is mainted
        /// </summary>
        public bool MaintainHandleCount { get; }
        /// <summary>
        /// Indicates the type list maintained
        /// </summary>
        public ushort MaintainTypeList { get; }
        /// <summary>
        /// Indicates the type of pool used in allocations
        /// </summary>
        public PoolType PoolType { get; }
        /// <summary>
        /// Current paged pool usage
        /// </summary>
        public uint PagedPoolUsage { get; }
        /// <summary>
        /// Current non-pages pool usage
        /// </summary>
        public uint NonPagedPoolUsage { get; }
        /// <summary>
        /// Type Index
        /// </summary>
        public int Index { get; }
        /// <summary>
        /// Generic Read Access rights
        /// </summary>
        public string GenericRead { get; }
        /// <summary>
        /// Generic Read Access rights
        /// </summary>
        public string GenericWrite { get; }
        /// <summary>
        /// Generic Read Access rights
        /// </summary>
        public string GenericExecute { get; }
        /// <summary>
        /// Generic Read Access rights
        /// </summary>
        public string GenericAll { get; }
        /// <summary>
        /// Get the maximum access mask for the type's default mandatory access policy.
        /// </summary>
        public string DefaultMandatoryAccess { get; }

        /// <summary>
        /// Get implemented object type for this NT type.
        /// </summary>
        public Type ObjectType
        {
            get
            {
                return _type_factory.ObjectType;
            }
        }

        /// <summary>
        /// Get the access rights enumerated type for this NT type.
        /// </summary>
        public Type AccessRightsType
        {
            get
            {
                return _type_factory.AccessRightsType;
            }
        }

        /// <summary>
        /// Get the access rights enumerated type for this NT type if it's a container.
        /// </summary>
        /// <remarks>There's only one known type at the moment which uses this, File.</remarks>
        public Type ContainerAccessRightsType
        {
            get
            {
                return _type_factory.ContainerAccessRightsType;
            }
        }

        /// <summary>
        /// Can this type of open be opened by name
        /// </summary>
        public bool CanOpen
        {
            get { return _type_factory.CanOpen; }
        }

        /// <summary>
        /// Get the valid access rights for this Type.
        /// </summary>
        public IEnumerable<AccessMaskEntry> AccessRights
        {
            get
            {
                if (_access_rights == null)
                {
                    var access_rights = new List<AccessMaskEntry>();
                    uint mask = 1;
                    while (mask < ValidAccess.Access)
                    {
                        if (Enum.IsDefined(AccessRightsType, mask))
                        {
                            GenericAccessType generic_access = GenericAccessType.None;
                            if (GenericMapping.GenericRead.IsAccessGranted(mask))
                            {
                                generic_access |= GenericAccessType.Read;
                            }
                            if (GenericMapping.GenericWrite.IsAccessGranted(mask))
                            {
                                generic_access |= GenericAccessType.Write;
                            }
                            if (GenericMapping.GenericExecute.IsAccessGranted(mask))
                            {
                                generic_access |= GenericAccessType.Execute;
                            }
                            if (GenericMapping.GenericAll.IsAccessGranted(mask))
                            {
                                generic_access |= GenericAccessType.All;
                            }

                            access_rights.Add(new AccessMaskEntry(mask,
                                (Enum)Enum.ToObject(AccessRightsType, mask), generic_access));
                        }
                        mask <<= 1;
                    }
                    _access_rights = access_rights.AsReadOnly();
                }
                return _access_rights;
            }
        }

        /// <summary>
        /// Get the valid read access rights for this Type.
        /// </summary>
        public IEnumerable<AccessMaskEntry> ReadAccessRights => AccessRights.Where(r => GenericMapping.GenericRead.IsAccessGranted(r.Mask));

        /// <summary>
        /// Get the valid write access rights for this Type.
        /// </summary>
        public IEnumerable<AccessMaskEntry> WriteAccessRights => AccessRights.Where(r => GenericMapping.GenericWrite.IsAccessGranted(r.Mask));

        /// <summary>
        /// Get the valid execute access rights for this Type.
        /// </summary>
        public IEnumerable<AccessMaskEntry> ExecuteAccessRights => AccessRights.Where(r => GenericMapping.GenericExecute.IsAccessGranted(r.Mask));

        /// <summary>
        /// Get the valid all access rights for this Type.
        /// </summary>
        public IEnumerable<AccessMaskEntry> AllAccessRights => AccessRights.Where(r => GenericMapping.GenericAll.IsAccessGranted(r.Mask));

        /// <summary>
        /// Get the valid mandatory access rights for this Type.
        /// </summary>
        public IEnumerable<AccessMaskEntry> MandatoryAccessRights
        {
            get
            {
                AccessMask mask = GetDefaultMandatoryAccess();
                return AccessRights.Where(r => mask.IsAccessGranted(r.Mask));
            }
        }

        /// <summary>
        /// Get defined query information classes for a type.
        /// </summary>
        public IReadOnlyDictionary<string, int> QueryInformationClass
        {
            get
            {
                if (_query_info_class == null)
                {
                    _query_info_class = BuildInfoClassDict(_type_factory.GetQueryInfoClass());
                }

                return _query_info_class;
            }
        }

        /// <summary>
        /// Get defined set information classes for a type.
        /// </summary>
        public IReadOnlyDictionary<string, int> SetInformationClass
        {
            get
            {
                if (_set_info_class == null)
                {
                    _set_info_class = BuildInfoClassDict(_type_factory.GetSetInfoClass());
                }

                return _set_info_class;
            }
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Open this NT type by name (if CanOpen is true)
        /// </summary>
        /// <param name="object_attributes">The object attributes to open.</param>
        /// <param name="desired_access">Desired access when opening.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public NtResult<NtObject> Open(ObjectAttributes object_attributes, AccessMask desired_access, bool throw_on_error)
        {
            if (!CanOpen)
            {
                if (throw_on_error)
                {
                    throw new ArgumentException($"Can't open type {Name} by name");
                }
                return NtStatus.STATUS_OBJECT_PATH_INVALID.CreateResultFromError<NtObject>(false);
            }

            return _type_factory.Open(object_attributes, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open this NT type by name (if CanOpen is true)
        /// </summary>
        /// <param name="name">The name of the object to open.</param>
        /// <param name="root">The root object for opening, if name is relative</param>
        /// <param name="desired_access">Desired access when opening.</param>
        /// <returns>The created object.</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtObject Open(string name, NtObject root, AccessMask desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access, true).Result;
            }
        }

        /// <summary>
        /// Open this NT type by name (if CanOpen is true)
        /// </summary>
        /// <param name="name">The name of the object to open.</param>
        /// <param name="root">The root object for opening, if name is relative</param>
        /// <returns>The created object.</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtObject Open(string name, NtObject root)
        {
            return Open(name, root, GenericAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open this NT type by name (if CanOpen is true)
        /// </summary>
        /// <param name="name">The name of the object to open.</param>
        /// <returns>The created object.</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtObject Open(string name)
        {
            return Open(name, null);
        }

        /// <summary>
        /// Get object from an existing handle.
        /// </summary>
        /// <param name="handle">The existing handle.</param>
        /// <returns>The new object.</returns>
        public NtObject FromHandle(SafeKernelObjectHandle handle)
        {
            return _type_factory.FromHandle(handle);
        }

        /// <summary>
        /// Get object from an existing handle.
        /// </summary>
        /// <param name="handle">The existing handle.</param>
        /// <param name="owns_handle">True to own the handle.</param>
        /// <returns>The new object.</returns>
        public NtObject FromHandle(IntPtr handle, bool owns_handle)
        {
            return FromHandle(new SafeKernelObjectHandle(handle, owns_handle));
        }

        /// <summary>
        /// Get object from an existing handle.
        /// </summary>
        /// <param name="handle">The existing handle.</param>
        /// <remarks>The call doesn't own the handle. The returned object can't be used to close the handle.</remarks>
        /// <returns>The new object.</returns>
        public NtObject FromHandle(IntPtr handle)
        {
            return FromHandle(handle, false);
        }

        /// <summary>
        /// Convert an enumerable access rights to a string
        /// </summary>
        /// <param name="container">True to use the container access type.</param>
        /// <param name="granted_access">The granted access mask.</param>
        /// <param name="map_to_generic">True to try and convert to generic rights where possible.</param>
        /// <returns>The string format of the access rights</returns>
        public string AccessMaskToString(bool container, AccessMask granted_access, bool map_to_generic)
        {
            return NtSecurity.AccessMaskToString(granted_access, container ? ContainerAccessRightsType : AccessRightsType,
                GenericMapping, map_to_generic);
        }

        /// <summary>
        /// Convert an enumerable access rights to a string
        /// </summary>
        /// <param name="granted_access">The granted access mask.</param>
        /// <param name="map_to_generic">True to try and convert to generic rights where possible.</param>
        /// <returns>The string format of the access rights</returns>
        public string AccessMaskToString(AccessMask granted_access, bool map_to_generic)
        {
            return NtSecurity.AccessMaskToString(granted_access, AccessRightsType, GenericMapping, map_to_generic);
        }

        /// <summary>
        /// Convert an enumerable access rights to a string
        /// </summary>
        /// <param name="granted_access">The granted access mask.</param>
        /// <returns>The string format of the access rights</returns>
        public string AccessMaskToString(AccessMask granted_access)
        {
            return AccessMaskToString(granted_access, false);
        }

        /// <summary>
        /// Checks if an access mask represents a read permission on this type
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it has read permissions</returns>
        public bool HasReadPermission(AccessMask access_mask)
        {
            return GenericMapping.HasRead(access_mask);
        }

        /// <summary>
        /// Checks if an access mask represents a write permission on this type
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it has write permissions</returns>
        public bool HasWritePermission(AccessMask access_mask)
        {
            // We consider here that Delete, WriteDac and WriteOwner are also write permissions.
            if ((access_mask & (GenericAccessRights.WriteDac
                                | GenericAccessRights.WriteOwner
                                | GenericAccessRights.Delete)).HasAccess)
            {
                return true;
            }

            return GenericMapping.HasWrite(access_mask);
        }

        /// <summary>
        /// Checks if an access mask represents a execute permission on this type
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it has execute permissions</returns>
        public bool HasExecutePermission(AccessMask access_mask)
        {
            return GenericMapping.HasExecute(access_mask);
        }

        /// <summary>
        /// Checks if an access mask represents a full permission on this type
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it has full permissions</returns>
        public bool HasFullPermission(AccessMask access_mask)
        {
            return GenericMapping.HasAll(access_mask);
        }

        /// <summary>
        /// Map generic access rights to specific access rights for this type
        /// </summary>
        /// <param name="access_mask">The access mask to map</param>
        /// <returns>The mapped access mask</returns>
        public AccessMask MapGenericRights(AccessMask access_mask)
        {
            return GenericMapping.MapMask(access_mask);
        }

        /// <summary>
        /// Unmap specific access rights to generic access rights for this type
        /// </summary>
        /// <param name="access_mask">The access mask to unmap</param>
        /// <returns>The unmapped access mask</returns>
        public AccessMask UnmapGenericRights(AccessMask access_mask)
        {
            return GenericMapping.UnmapMask(access_mask);
        }

        /// <summary>
        /// Checks if an access mask is valid for access of this object type.
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it valid access</returns>
        public bool IsValidAccess(AccessMask access_mask)
        {
            return (GenericMapping.MapMask(access_mask) & ~ValidAccess).IsEmpty;
        }

        /// <summary>
        /// Get the maximum access mask for the type's default mandatory access policy.
        /// </summary>
        /// <returns>The allowed access mask for the type with the default policy.</returns>
        public AccessMask GetDefaultMandatoryAccess()
        {
            return GenericMapping.GetAllowedMandatoryAccess(_type_factory.DefaultMandatoryPolicy);
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>Returns the type as a string.</returns>
        public override string ToString()
        {
            return $"Name = {Name} - Index = {Index}";
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Create an NtType object by name.
        /// </summary>
        /// <param name="name">The name of the NT type.</param>
        /// <remarks>This will always return a cached type.</remarks>
        /// <exception cref="ArgumentException">Invalid NT type name.</exception>
        public NtType(string name) 
            : this(name, GetTypeByName(name, false))
        {
        }

        internal NtType(string name, GenericMapping generic_mapping, Type access_rights_type, Type container_access_rights_type, MandatoryLabelPolicy default_policy)
        {
            if (!access_rights_type.IsEnum)
            {
                throw new ArgumentException("Specify an enumerated type", "access_rights_type");
            }
            _type_factory = new NtTypeFactory(access_rights_type, container_access_rights_type, typeof(object), false, default_policy);
            Name = name;
            ValidAccess = CalculateValidAccess(access_rights_type) | CalculateValidAccess(container_access_rights_type);
            GenericMapping = generic_mapping;
            GenericRead = NtSecurity.AccessMaskToString(GenericMapping.GenericRead, access_rights_type);
            GenericWrite = NtSecurity.AccessMaskToString(GenericMapping.GenericWrite, access_rights_type);
            GenericExecute = NtSecurity.AccessMaskToString(GenericMapping.GenericExecute, access_rights_type);
            GenericAll = NtSecurity.AccessMaskToString(GenericMapping.GenericAll, access_rights_type);
            DefaultMandatoryAccess = NtSecurity.AccessMaskToString(GetDefaultMandatoryAccess(), access_rights_type);
        }

        internal NtType(int id, string name)
        {
            Index = id;
            Name = name;
            if (Name == null)
            {
                Name = $"Unknown {id}";
            }
            System.Diagnostics.Debug.WriteLine($"Generating Fake Type for {Name}");
            _type_factory = _generic_factory;
            GenericRead = string.Empty;
            GenericWrite = string.Empty;
            GenericExecute = string.Empty;
            GenericAll = string.Empty;
        }

        internal NtType(int id, ObjectTypeInformation info, NtTypeFactory type_factory)
        {
            Index = id;
            Name = info.Name.ToString();
            InvalidAttributes = info.InvalidAttributes;
            GenericMapping = info.GenericMapping;
            ValidAccess = info.ValidAccess;
            SecurityRequired = info.SecurityRequired != 0;

            TotalNumberOfObjects = info.TotalNumberOfObjects;
            TotalNumberOfHandles = info.TotalNumberOfHandles;
            TotalPagedPoolUsage = info.TotalPagedPoolUsage;
            TotalNonPagedPoolUsage = info.TotalNonPagedPoolUsage;
            TotalNamePoolUsage = info.TotalNamePoolUsage;
            TotalHandleTableUsage = info.TotalHandleTableUsage;
            HighWaterNumberOfObjects = info.HighWaterNumberOfObjects;
            HighWaterNumberOfHandles = info.HighWaterNumberOfHandles;
            HighWaterPagedPoolUsage = info.HighWaterPagedPoolUsage;
            HighWaterNonPagedPoolUsage = info.HighWaterNonPagedPoolUsage;
            HighWaterNamePoolUsage = info.HighWaterNamePoolUsage;
            HighWaterHandleTableUsage = info.HighWaterHandleTableUsage;
            MaintainHandleCount = info.MaintainHandleCount != 0;
            MaintainTypeList = info.MaintainTypeList;
            PoolType = info.PoolType;
            PagedPoolUsage = info.PagedPoolUsage;
            NonPagedPoolUsage = info.NonPagedPoolUsage;
            _type_factory = type_factory;

            GenericRead = NtSecurity.AccessMaskToString(GenericMapping.GenericRead, _type_factory.AccessRightsType);
            GenericWrite = NtSecurity.AccessMaskToString(GenericMapping.GenericWrite, _type_factory.AccessRightsType);
            GenericExecute = NtSecurity.AccessMaskToString(GenericMapping.GenericExecute, _type_factory.AccessRightsType);
            GenericAll = NtSecurity.AccessMaskToString(GenericMapping.GenericAll, _type_factory.AccessRightsType);
            DefaultMandatoryAccess = NtSecurity.AccessMaskToString(GetDefaultMandatoryAccess(), _type_factory.AccessRightsType);
        }

        internal NtType(string name, NtType existing_type)
        {
            if (existing_type == null)
                throw new ArgumentException($"Invalid NT Type {name}", "name");
            Index = existing_type.Index;
            Name = existing_type.Name;
            InvalidAttributes = existing_type.InvalidAttributes;
            GenericMapping = existing_type.GenericMapping;
            ValidAccess = existing_type.ValidAccess;
            SecurityRequired = existing_type.SecurityRequired;

            TotalNumberOfObjects = existing_type.TotalNumberOfObjects;
            TotalNumberOfHandles = existing_type.TotalNumberOfHandles;
            TotalPagedPoolUsage = existing_type.TotalPagedPoolUsage;
            TotalNonPagedPoolUsage = existing_type.TotalNonPagedPoolUsage;
            TotalNamePoolUsage = existing_type.TotalNamePoolUsage;
            TotalHandleTableUsage = existing_type.TotalHandleTableUsage;
            HighWaterNumberOfObjects = existing_type.HighWaterNumberOfObjects;
            HighWaterNumberOfHandles = existing_type.HighWaterNumberOfHandles;
            HighWaterPagedPoolUsage = existing_type.HighWaterPagedPoolUsage;
            HighWaterNonPagedPoolUsage = existing_type.HighWaterNonPagedPoolUsage;
            HighWaterNamePoolUsage = existing_type.HighWaterNamePoolUsage;
            HighWaterHandleTableUsage = existing_type.HighWaterHandleTableUsage;
            MaintainHandleCount = existing_type.MaintainHandleCount;
            MaintainTypeList = existing_type.MaintainTypeList;
            PoolType = existing_type.PoolType;
            PagedPoolUsage = existing_type.PagedPoolUsage;
            NonPagedPoolUsage = existing_type.NonPagedPoolUsage;
            _type_factory = existing_type._type_factory;

            GenericRead = existing_type.GenericRead;
            GenericWrite = existing_type.GenericWrite;
            GenericExecute = existing_type.GenericExecute;
            GenericAll = existing_type.GenericAll;
        }

        #endregion

        #region Static Members
        /// <summary>
        /// Get a type object by index
        /// </summary>
        /// <param name="index">The index</param>
        /// <returns>The object type, null if not found</returns>
        public static NtType GetTypeByIndex(int index)
        {
            return GetTypeByIndex(index, true);
        }

        /// <summary>
        /// Get a type object by index
        /// </summary>
        /// <param name="index">The index</param>
        /// <param name="cached">True to get a cached type, false to return a live types.</param>
        /// <returns>The object type, null if not found</returns>
        public static NtType GetTypeByIndex(int index, bool cached)
        {
            foreach (NtType info in GetTypes(cached))
            {
                if (info.Index == index)
                    return info;
            }

            return new NtType(index, null);
        }

        /// <summary>
        /// Get a type object by name
        /// </summary>
        /// <param name="name">The name of the type</param>
        /// <param name="create_fake_type">True to create a fake type if needed.</param>
        /// <param name="cached">True to get a cached type, false to return a live types.</param>
        /// <returns>The object type, null if not found</returns>
        public static NtType GetTypeByName(string name, bool create_fake_type, bool cached)
        {
            var types = cached ? _types : LoadTypes();

            if (types.ContainsKey(name))
            {
                return types[name];
            }

            if (create_fake_type)
            {
                return new NtType(-1, name);
            }
            return null;
        }

        /// <summary>
        /// Get a type object by name
        /// </summary>
        /// <param name="name">The name of the type</param>
        /// <param name="create_fake_type">True to create a fake type if needed.</param>
        /// <returns>The object type, null if not found</returns>
        public static NtType GetTypeByName(string name, bool create_fake_type)
        {
            return GetTypeByName(name, create_fake_type, true);
        }

        /// <summary>
        /// Get a type object by a kernel handle.
        /// </summary>
        /// <param name="handle">The kernel handle.</param>
        /// <param name="create_fake_type">True to create a fake type if needed.</param>
        /// <returns>The object type, null if not found</returns>
        public static NtType GetTypeForHandle(SafeKernelObjectHandle handle, bool create_fake_type)
        {
            return GetTypeByName(handle.NtTypeName, create_fake_type);
        }

        /// <summary>
        /// Get an NT type based on the implemented .NET type.
        /// </summary>
        /// <typeparam name="T">A type derived from NtObject</typeparam>
        /// <param name="cached">True to get a cached type, false to return a live types.</param>
        /// <returns>The NtType represented by this .NET type. Note if a type is represented with multiple
        /// names only return the first one we find.</returns>
        /// <exception cref="ArgumentException">Thrown if there exists no .NET type which maps to this type.</exception>
        public static NtType GetTypeByType<T>(bool cached) where T : NtObject
        {
            IEnumerable<NtTypeAttribute> attrs = typeof(T).GetCustomAttributes<NtTypeAttribute>(false);
            if (!attrs.Any())
            {
                throw new ArgumentException("Type has no mapping to an NT Type");
            }
            return GetTypeByName(attrs.First().TypeName, false, cached);
        }

        /// <summary>
        /// Get an NT type based on the implemented .NET type.
        /// </summary>
        /// <typeparam name="T">A type derived from NtObject</typeparam>
        /// <returns>The NtType represented by this .NET type. Note if a type is represented with multiple
        /// names only return the first one we find.</returns>
        /// <exception cref="ArgumentException">Thrown if there exists no .NET type which maps to this type.</exception>
        public static NtType GetTypeByType<T>() where T : NtObject
        {
            return GetTypeByType<T>(true);
        }

        /// <summary>
        /// Get a fake type object. This can be used in access checking for operations which need an NtType object
        /// but there's no real NT object.
        /// </summary>
        /// <param name="name">The name of the fake type. Informational only.</param>
        /// <param name="generic_mapping">The GENERIC_MAPPING for security checking.</param>
        /// <param name="access_rights_type">The access rights enumeration type.</param>
        /// <param name="container_access_rights_type">The access rights enumeration type of the object is a container.</param>
        /// <returns>The fake NT type object.</returns>
        public static NtType GetFakeType(string name, GenericMapping generic_mapping, Type access_rights_type, Type container_access_rights_type)
        {
            return new NtType(name, generic_mapping, access_rights_type, container_access_rights_type, MandatoryLabelPolicy.NoWriteUp);
        }

        /// <summary>
        /// Get a fake type object. This can be used in access checking for operations which need an NtType object
        /// but there's no real NT object.
        /// </summary>
        /// <param name="name">The name of the fake type. Informational only.</param>
        /// <param name="generic_mapping">The GENERIC_MAPPING for security checking.</param>
        /// <param name="access_rights_type">The access rights enumeration type.</param>
        /// <returns>The fake NT type object.</returns>
        public static NtType GetFakeType(string name, GenericMapping generic_mapping, Type access_rights_type)
        {
            return GetFakeType(name, generic_mapping, access_rights_type, access_rights_type);
        }

        /// <summary>
        /// Get a fake type object. This can be used in access checking for operations which need an NtType object
        /// but there's no real NT object.
        /// </summary>
        /// <param name="name">The name of the fake type. Informational only.</param>
        /// <param name="generic_read">The GENERIC_READ for security checking.</param>
        /// <param name="generic_write">The GENERIC_WRITE for security checking.</param>
        /// <param name="generic_exec">The GENERIC_EXECUTE for security checking.</param>
        /// <param name="generic_all">The GENERIC_ALL for security checking.</param>
        /// <param name="access_rights_type">The access rights enumeration type.</param>
        /// <param name="container_access_rights_type">The access rights enumeration type of the object is a container.</param>
        /// <returns>The fake NT type object.</returns>
        public static NtType GetFakeType(string name, AccessMask generic_read, AccessMask generic_write,
            AccessMask generic_exec, AccessMask generic_all, Type access_rights_type, Type container_access_rights_type)
        {
            return new NtType(name, new GenericMapping() { GenericRead = generic_read, GenericWrite = generic_write, 
                GenericExecute = generic_exec, GenericAll = generic_all }, access_rights_type, container_access_rights_type,
                MandatoryLabelPolicy.NoWriteUp);
        }

        /// <summary>
        /// Get a fake type object. This can be used in access checking for operations which need an NtType object
        /// but there's no real NT object.
        /// </summary>
        /// <param name="name">The name of the fake type. Informational only.</param>
        /// <param name="generic_read">The GENERIC_READ for security checking.</param>
        /// <param name="generic_write">The GENERIC_WRITE for security checking.</param>
        /// <param name="generic_exec">The GENERIC_EXECUTE for security checking.</param>
        /// <param name="generic_all">The GENERIC_ALL for security checking.</param>
        /// <param name="access_rights_type">The access rights enumeration type.</param>
        /// <returns>The fake NT type object.</returns>
        public static NtType GetFakeType(string name, AccessMask generic_read, AccessMask generic_write,
            AccessMask generic_exec, AccessMask generic_all, Type access_rights_type)
        {
            return GetFakeType(name, generic_read, generic_write, generic_exec, generic_all, access_rights_type, access_rights_type);
        }

        /// <summary>
        /// Get a list of all types.
        /// </summary>
        /// <returns>The list of types.</returns>
        public static IEnumerable<NtType> GetTypes()
        {
            return GetTypes(true);
        }

        /// <summary>
        /// Get a list of all types.
        /// </summary>
        /// <param name="cached">True to get the cached list of types, false to return a live list of all types.</param>
        /// <returns>The list of types.</returns>
        public static IEnumerable<NtType> GetTypes(bool cached)
        {
            if (cached)
            {
                return _types.Values;
            }
            else
            {
                return LoadTypes().Values;
            }
        }

        #endregion

        #region Private Members
        private static readonly NtTypeFactory _generic_factory = new NtGeneric.NtTypeFactoryImpl();
        private static readonly Dictionary<string, NtType> _types = LoadTypes();
        private readonly NtTypeFactory _type_factory;
        private IEnumerable<AccessMaskEntry> _access_rights;
        private Dictionary<string, int> _set_info_class;
        private Dictionary<string, int> _query_info_class;

        private Dictionary<string, int> BuildInfoClassDict(IEnumerable<Enum> values)
        {
            var dict = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var value in values)
            {
                dict[value.ToString()] = (int)(object)value;
            }
            return dict;
        }

        private static Dictionary<string, NtType> LoadTypes()
        {
            var type_factories = NtTypeFactory.GetAssemblyNtTypeFactories(Assembly.GetExecutingAssembly());
            Dictionary<string, NtType> ret = new Dictionary<string, NtType>(StringComparer.OrdinalIgnoreCase);

            int size = 0x8000;

            // repeatly try to fill out ObjectTypes buffer by increasing it's size between each attempt
            while (size < 0x1000000)
            {
                using (var type_info = new SafeStructureInOutBuffer<ObjectAllTypesInformation>(size, true))
                {
                    NtStatus status = NtSystemCalls.NtQueryObject(SafeKernelObjectHandle.Null, ObjectInformationClass.ObjectTypesInformation,
                            type_info, type_info.Length, out int return_length);

                    switch (status)
                    {
                        // if the input buffer is too small, double it's size and retry
                        case NtStatus.STATUS_INFO_LENGTH_MISMATCH:
                            size *= 2;
                            break;

                        // From this point, the return values of NtSystemCalls.NtQueryObject are considered correct
                        case NtStatus.STATUS_SUCCESS:

                            int alignment = IntPtr.Size - 1;
                            ObjectAllTypesInformation result = type_info.Result;
                            IntPtr curr_typeinfo = type_info.DangerousGetHandle() + IntPtr.Size;

                            for (int count = 0; count < result.NumberOfTypes; ++count)
                            {
                                ObjectTypeInformation info = (ObjectTypeInformation)Marshal.PtrToStructure(curr_typeinfo, typeof(ObjectTypeInformation));
                                string name = info.Name.ToString();
                                NtTypeFactory factory = type_factories.ContainsKey(name) ? type_factories[name] : _generic_factory;
                                NtType ti = new NtType(count + 2, info, factory);
                                ret[ti.Name] = ti;

                                int offset = (info.Name.MaximumLength + alignment) & ~alignment;
                                curr_typeinfo = info.Name.Buffer + offset;
                            }

                            return ret;

                        default:
                            throw new NtException(status);
                    }
                }
            }

            // raise exception if the candidate buffer is over a MB.
            throw new NtException(NtStatus.STATUS_INSUFFICIENT_RESOURCES);
        }

        private static uint CalculateValidAccess(Type access_type)
        {
            uint valid_access = 0;
            foreach (uint value in Enum.GetValues(access_type))
            {
                if ((value & 0xFF000000) == 0)
                {
                    valid_access |= value;
                }
            }
            return valid_access;
        }
        #endregion
    }
}
