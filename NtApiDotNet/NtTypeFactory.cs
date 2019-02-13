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
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace NtApiDotNet
{
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
            Type base_type = object_type.BaseType; // GetBaseType(object_type);
            if (base_type.GetGenericTypeDefinition() == typeof(NtObjectWithDuplicateAndInfo<,,,>))
            {
                base_type = base_type.BaseType;
            }
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
}
