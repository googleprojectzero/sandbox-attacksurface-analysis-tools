using NtApiDotNet;

namespace SandboxPowerShellApi
{
    public class ObjectDirectoryEntry
    {
        private NtDirectory _base_directory;
        private string _full_path;

        public string Name { get; private set; }
        public string TypeName { get; private set; }
        public bool IsDirectory { get; private set; }
        public SecurityDescriptor SecurityDescriptor { get; private set; }

        private static SecurityDescriptor GetObjectSecurityDescriptor(ObjectDirectoryInformation dir_info)
        {
            try
            {
                using (NtObject obj = dir_info.Open(GenericAccessRights.ReadControl))
                {
                    return obj.GetSecurityDescriptor();
                }
            }
            catch
            {
            }

            return new SecurityDescriptor();
        }

        public NtObject ToObject()
        {
            return NtObject.OpenWithType(TypeName, _full_path, _base_directory, GenericAccessRights.MaximumAllowed);
        }

        internal ObjectDirectoryEntry(NtDirectory base_directory, string fullpath, string name, string typename, bool is_directory, SecurityDescriptor sd)
        {
            Name = name;
            TypeName = typename;
            IsDirectory = is_directory;
            SecurityDescriptor = sd ?? new SecurityDescriptor();
            _full_path = fullpath;
            _base_directory = base_directory;
        }

        internal ObjectDirectoryEntry(NtDirectory base_directory, string fullpath, ObjectDirectoryInformation dir_info) 
            : this(base_directory, fullpath, dir_info.Name, dir_info.TypeName, dir_info.IsDirectory, GetObjectSecurityDescriptor(dir_info))
        {
        }
    }
}
