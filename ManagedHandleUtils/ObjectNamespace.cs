using NtApiDotNet;
using System;

namespace HandleUtils
{
    public static class ObjectNamespace
    {
	    public static ObjectDirectory OpenDirectory(ObjectDirectory root, string object_path)
	    {		
		    return new ObjectDirectory(root, object_path);
        }

        public static ObjectDirectory OpenSessionDirectory(int sessionid)
	    {
		    return new ObjectDirectory(null, String.Format("\\Sessions\\{0}", sessionid));
	    }

        public static ObjectDirectory OpenSessionDirectory()
	    {
		    return OpenSessionDirectory(NtProcess.Current.GetProcessSessionId());
	    }

	    public static string ReadSymlink(string symlink_path)
	    {
            try
            {
                using (NtSymbolicLink symlink = NtSymbolicLink.Open(symlink_path, null, NtApiDotNet.SymbolicLinkAccessRights.Query))
                {
                    return symlink.Query();
                }
            }
            catch (NtException ex)
            {
                throw ex.AsWin32Exception();
            }
	    }
    }
}
