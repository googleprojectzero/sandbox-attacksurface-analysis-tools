using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace HandleUtils
{
    public static class NativeBridge
    {
        static void AddEnumToDictionary(Dictionary<uint, String> access, Type enumType)
        {
            Regex re = new Regex("([A-Z])");

            foreach(uint mask in Enum.GetValues(enumType))
            {
                access.Add(mask, re.Replace(Enum.GetName(enumType, mask), " $1").Trim());
            }
        }

        static Dictionary<uint, String> GetMaskDictionary(Type enumType)
        {
            Dictionary<uint, String> access = new Dictionary<uint, String>();
                        
            AddEnumToDictionary(access, enumType);

            return access;
        }
        
        [DllImport("aclui.dll")]
        static extern bool EditSecurity(IntPtr hwndOwner, ISecurityInformation psi);

        static Type TypeNameToEnum(string name)
        {
            switch(name.ToLower())
            {
                case "directory": return typeof(DirectoryAccessRights);
                case "event": return typeof(EventAccessRights);
                case "section": return typeof(SectionAccessRights);
                case "mutant": return typeof(MutantAccessRights);
                case "semaphore": return typeof(SemaphoreAccessRights);
                case "job": return typeof(JobAccessRights);
                case "symboliclink": return typeof(SymbolicLinkAccessRights);
                case "file":
                case "device":
                    return typeof(FileAccessRights);
                case "process":
                    return typeof(ProcessAccessRights);
                case "token":
                    return typeof(TokenAccessRights);
                case "thread":
                    return typeof(ThreadAccessRights);
                default:
                    throw new ArgumentException("Can't get type for access rights");
            }
        }

        public static void EditSecurity(IntPtr hwnd, IntPtr handle, string object_name, string typeName, bool writeable)
        {
            ObjectTypeInfo typeInfo = ObjectTypeInfo.GetTypeByName(typeName);
            Dictionary<uint, String> access = GetMaskDictionary(TypeNameToEnum(typeName));

            using (SecurityInformationImpl impl = new SecurityInformationImpl(object_name, new NativeHandle(handle, true), access,
               typeInfo.GenericMapping))
            {
                EditSecurity(hwnd, impl);
            }
        }
    }
}
