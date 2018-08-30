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
#pragma warning disable 1591
    /// <summary>
    /// Native structure used for getting type information.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectTypeInformation
    {
        public UnicodeStringOut Name;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;
        public uint HighWaterNumberOfHandles;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public AttributeFlags InvalidAttributes;
        public GenericMapping GenericMapping;
        public uint ValidAccess;
        public byte SecurityRequired;
        public byte MaintainHandleCount;
        public ushort MaintainTypeList;
        public PoolType PoolType;
        public uint PagedPoolUsage;
        public uint NonPagedPoolUsage;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectAllTypesInformation
    {
        public int NumberOfTypes;
        //ObjectTypeInformation TypeInformation; // Type Info list
    }

    [AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
    internal sealed class NtTypeAttribute : Attribute
    {
        public string TypeName { get; private set; }
        public NtTypeAttribute(string type_name)
        {
            TypeName = type_name;
        }
    }

    internal sealed class NtTypeFactory
    {
        private Func<SafeKernelObjectHandle, NtObject> _from_handle_method;
        private Func<ObjectAttributes, AccessMask, bool, NtResult<NtObject>> _from_name_method;
        public Type ObjectType { get; private set; }
        public Type AccessRightsType { get; private set; }
        public bool CanOpen { get { return _from_name_method != null; } }

        public NtObject FromHandle(SafeKernelObjectHandle handle)
        {
            return _from_handle_method(handle);
        }

        public NtResult<NtObject> Open(ObjectAttributes obj_attributes, AccessMask desired_access, bool throw_on_error)
        {
            try
            {
                System.Diagnostics.Debug.Assert(_from_name_method != null);
                return _from_name_method(obj_attributes, desired_access, throw_on_error);
            }
            catch (TargetInvocationException ex)
            {
                throw ex.InnerException;
            }
        }

        internal NtTypeFactory(Type access_rights_type, Type object_type)
        {
            AccessRightsType = access_rights_type;
            ObjectType = object_type;
            _from_handle_method = h => throw new NotImplementedException();
        }

        public NtTypeFactory(Type object_type)
        {
            Type base_type = object_type.BaseType;
            System.Diagnostics.Debug.Assert(base_type.GetGenericTypeDefinition() == typeof(NtObjectWithDuplicate<,>));
            ObjectType = object_type;

            MethodInfo from_handle_method = base_type.GetMethod("FromHandle", 
                BindingFlags.Public | BindingFlags.Static, 
                null, new Type[] { typeof(SafeKernelObjectHandle) }, null);
            _from_handle_method = (Func<SafeKernelObjectHandle, NtObject>)Delegate.CreateDelegate(typeof(Func<SafeKernelObjectHandle, NtObject>), from_handle_method);

            AccessRightsType = base_type.GetGenericArguments()[1];

            MethodInfo from_name_method = object_type.GetMethod("FromName", 
                BindingFlags.NonPublic | BindingFlags.Static, null, 
                new Type[] { typeof(ObjectAttributes), typeof(AccessMask), typeof(bool) }, null);
            if (from_name_method == null)
            {
                System.Diagnostics.Debug.WriteLine($"Type {object_type} doesn't have a FromName method");
            }
            else
            {
                _from_name_method = (Func<ObjectAttributes, AccessMask, bool, NtResult<NtObject>>)
                    Delegate.CreateDelegate(typeof(Func<ObjectAttributes, AccessMask, bool, NtResult<NtObject>>), from_name_method);
            }
        }

        public static Dictionary<string, NtTypeFactory> GetAssemblyNtTypeFactories(Assembly assembly)
        {
            Dictionary<string, NtTypeFactory> _factories = new Dictionary<string, NtTypeFactory>(StringComparer.OrdinalIgnoreCase);
            foreach (Type type in assembly.GetTypes().Where(t => t.IsClass && !t.IsAbstract && typeof(NtObject).IsAssignableFrom(t)))
            {
                IEnumerable<NtTypeAttribute> attrs = type.GetCustomAttributes<NtTypeAttribute>(false);
                foreach (NtTypeAttribute attr in attrs)
                {
                    System.Diagnostics.Debug.Assert(!_factories.ContainsKey(attr.TypeName));
                    _factories.Add(attr.TypeName, new NtTypeFactory(type));
                }
            }
            return _factories;
        }
    }

#pragma warning restore 1591

    /// <summary>
    /// Class representing an NT object type
    /// </summary>
    public sealed class NtType
    {
        private static NtTypeFactory _generic_factory = new NtTypeFactory(typeof(NtGeneric));
        private NtTypeFactory _type_factory;

        /// <summary>
        /// The name of the type
        /// </summary>
        public string Name { get; private set; }
        /// <summary>
        /// The mapping from generic to specific object rights
        /// </summary>
        public GenericMapping GenericMapping { get; private set; }
        /// <summary>
        /// The valid access mask
        /// </summary>
        public AccessMask ValidAccess { get; private set; }
        /// <summary>
        /// True if the object needs security even if unnamed
        /// </summary>
        public bool SecurityRequired { get; private set; }
        /// <summary>
        /// Total number of objects (when originally retrieved)
        /// </summary>
        public uint TotalNumberOfObjects { get; private set; }
        /// <summary>
        /// Total number of handles (when originally retrieved)
        /// </summary>
        public uint TotalNumberOfHandles { get; private set; }
        /// <summary>
        /// Total paged pool usage (when originally retrieved)
        /// </summary>
        public uint TotalPagedPoolUsage { get; private set; }
        /// <summary>
        /// Total non-paged pool usage (when originally retrieved)
        /// </summary>
        public uint TotalNonPagedPoolUsage { get; private set; }
        /// <summary>
        /// Total name pool usage (when originally retrieved)
        /// </summary>
        public uint TotalNamePoolUsage { get; private set; }
        /// <summary>
        /// Total handle table usage (when originally retrieved)
        /// </summary>
        public uint TotalHandleTableUsage { get; private set; }
        /// <summary>
        /// Maximum number of objects (when originally retrieved)
        /// </summary>
        public uint HighWaterNumberOfObjects { get; private set; }
        /// <summary>
        /// Maximum number of handles (when originally retrieved)
        /// </summary>
        public uint HighWaterNumberOfHandles { get; private set; }
        /// <summary>
        /// Maximum paged pool usage (when originally retrieved)
        /// </summary>
        public uint HighWaterPagedPoolUsage { get; private set; }
        /// <summary>
        /// Maximum non-paged pool usage (when originally retrieved)
        /// </summary>
        public uint HighWaterNonPagedPoolUsage { get; private set; }
        /// <summary>
        /// Maximum name pool usage (when originally retrieved)
        /// </summary>
        public uint HighWaterNamePoolUsage { get; private set; }
        /// <summary>
        /// Maximum handle table usage (when originally retrieved)
        /// </summary>
        public uint HighWaterHandleTableUsage { get; private set; }
        /// <summary>
        /// The attributes flags which are invalid
        /// </summary>
        public AttributeFlags InvalidAttributes { get; private set; }
        /// <summary>
        /// Indicates whether handle count is mainted
        /// </summary>
        public bool MaintainHandleCount { get; private set; }
        /// <summary>
        /// Indicates the type list maintained
        /// </summary>
        public ushort MaintainTypeList { get; private set; }
        /// <summary>
        /// Indicates the type of pool used in allocations
        /// </summary>
        public PoolType PoolType { get; private set; }
        /// <summary>
        /// Current paged pool usage
        /// </summary>
        public uint PagedPoolUsage { get; private set; }
        /// <summary>
        /// Current non-pages pool usage
        /// </summary>
        public uint NonPagedPoolUsage { get; private set; }
        /// <summary>
        /// Type Index
        /// </summary>
        public int Index { get; private set; }
        /// <summary>
        /// Generic Read Access rights
        /// </summary>
        public string GenericRead { get; private set; }
        /// <summary>
        /// Generic Read Access rights
        /// </summary>
        public string GenericWrite { get; private set; }
        /// <summary>
        /// Generic Read Access rights
        /// </summary>
        public string GenericExecute { get; private set; }
        /// <summary>
        /// Generic Read Access rights
        /// </summary>
        public string GenericAll { get; private set; }

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
        /// Can this type of open be opened by name
        /// </summary>
        public bool CanOpen
        {
            get { return _type_factory.CanOpen; }
        }

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
        /// <param name="granted_access">The granted access mask.</param>
        /// <param name="map_to_generic">True to try and convert to generic rights where possible.</param>
        /// <returns>The string format of the access rights</returns>
        public string AccessMaskToString(AccessMask granted_access, bool map_to_generic)
        {
            return NtObjectUtils.GrantedAccessAsString(granted_access, GenericMapping, AccessRightsType, map_to_generic);
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

        internal NtType(string name, GenericMapping generic_mapping, Type access_rights_type)
        {
            if (!access_rights_type.IsEnum)
            {
                throw new ArgumentException("Specify an enumerated type", "access_rights_type");
            }
            _type_factory = new NtTypeFactory(access_rights_type, typeof(object));
            Name = name;
            GenericMapping = generic_mapping;
            GenericRead = NtObjectUtils.GrantedAccessAsString(GenericMapping.GenericRead, GenericMapping, access_rights_type, false);
            GenericWrite = NtObjectUtils.GrantedAccessAsString(GenericMapping.GenericWrite, GenericMapping, access_rights_type, false);
            GenericExecute = NtObjectUtils.GrantedAccessAsString(GenericMapping.GenericExecute, GenericMapping, access_rights_type, false);
            GenericAll = NtObjectUtils.GrantedAccessAsString(GenericMapping.GenericAll, GenericMapping, access_rights_type, false);
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
            GenericRead = String.Empty;
            GenericWrite = String.Empty;
            GenericExecute = String.Empty;
            GenericAll = String.Empty;
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

            GenericRead = NtObjectUtils.GrantedAccessAsString(GenericMapping.GenericRead, GenericMapping, _type_factory.AccessRightsType, false);
            GenericWrite = NtObjectUtils.GrantedAccessAsString(GenericMapping.GenericWrite, GenericMapping, _type_factory.AccessRightsType, false);
            GenericExecute = NtObjectUtils.GrantedAccessAsString(GenericMapping.GenericExecute, GenericMapping, _type_factory.AccessRightsType, false);
            GenericAll = NtObjectUtils.GrantedAccessAsString(GenericMapping.GenericAll, GenericMapping, _type_factory.AccessRightsType, false);
        }

        private static Dictionary<string, NtType> _types = LoadTypes();

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
        /// <returns></returns>
        public static NtType GetFakeType(string name, GenericMapping generic_mapping, Type access_rights_type)
        {
            return new NtType(name, generic_mapping, access_rights_type);
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
        /// <returns></returns>
        public static NtType GetFakeType(string name, AccessMask generic_read, AccessMask generic_write, 
            AccessMask generic_exec, AccessMask generic_all, Type access_rights_type)
        {
            return new NtType(name, new GenericMapping() { GenericRead = generic_read, GenericWrite = generic_write, GenericExecute = generic_exec, GenericAll = generic_all }, access_rights_type);
        }

        private static Dictionary<string, NtType> LoadTypes()
        {
            var type_factories = NtTypeFactory.GetAssemblyNtTypeFactories(Assembly.GetExecutingAssembly());
            Dictionary<string, NtType> ret = new Dictionary<string, NtType>(StringComparer.OrdinalIgnoreCase);

            int size = 0x8000;
            NtStatus status = NtStatus.STATUS_INFO_LENGTH_MISMATCH;

            // repeatly try to fill out ObjectTypes buffer by increasing it's size between each attempt
            while (status == NtStatus.STATUS_INFO_LENGTH_MISMATCH)
            {
                using (var type_info = new SafeStructureInOutBuffer<ObjectAllTypesInformation>(size, true))
                {
                    status = NtSystemCalls.NtQueryObject(SafeKernelObjectHandle.Null, ObjectInformationClass.ObjectTypesInformation,
                        type_info, type_info.Length, out int return_length);

                    switch (status)
                    {
                        // if the input buffer is too small, double it's size and retry
                        case NtStatus.STATUS_INFO_LENGTH_MISMATCH:
                            size *= 2;

                            // raise exception if the candidate buffer is over a MB.
                            if (size > 0x1000000)
                                NtStatus.STATUS_INSUFFICIENT_RESOURCES.ToNtException();

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
                            status.ToNtException();
                            break;
                    }    
                }    
            }

            // This path is never taken since error paths throws an exception, but the C# compiler does not seem to understand it.
            // This is probably due to the usage of a 'using' statement which obfuscate the function's control flow graph.
            return ret;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>Returns the type as a string.</returns>
        public override string ToString()
        {
            return $"Name = {Name} - Index = {Index}";
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
    }
}
