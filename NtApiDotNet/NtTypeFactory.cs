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
        public string TypeName { get; }
        public NtTypeAttribute(string type_name)
        {
            TypeName = type_name;
        }
    }

    internal class NtTypeFactory
    {
        private const string FACTORY_TYPE_NAME = "NtTypeFactoryImpl";

        public Type ObjectType { get; }
        public Type AccessRightsType { get; }
        public Type ContainerAccessRightsType { get; }
        public bool CanOpen { get; }
        public MandatoryLabelPolicy DefaultMandatoryPolicy { get; }
        public virtual IEnumerable<Enum> GetQueryInfoClass()
        {
            return new Enum[0];
        }
        public virtual IEnumerable<Enum> GetSetInfoClass()
        {
            return new Enum[0];
        }

        public virtual NtObject FromHandle(SafeKernelObjectHandle handle)
        {
            throw new NotImplementedException();
        }

        public virtual NtResult<NtObject> Open(ObjectAttributes obj_attributes, AccessMask desired_access, bool throw_on_error)
        {
            return NtStatus.STATUS_NOT_IMPLEMENTED.CreateResultFromError<NtObject>(throw_on_error);
        }

        internal NtTypeFactory(Type access_rights_type, Type container_access_rights_type, Type object_type, bool can_open, MandatoryLabelPolicy default_policy)
        {
            AccessRightsType = access_rights_type;
            ContainerAccessRightsType = container_access_rights_type;
            ObjectType = object_type;
            CanOpen = can_open;
            DefaultMandatoryPolicy = default_policy;
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
                    TypeInfo factory_type = type.GetTypeInfo().GetDeclaredNestedType(FACTORY_TYPE_NAME);
                    System.Diagnostics.Debug.Assert(factory_type != null);
                    _factories.Add(attr.TypeName, (NtTypeFactory)Activator.CreateInstance(factory_type));
                }
            }
            return _factories;
        }
    }
}
