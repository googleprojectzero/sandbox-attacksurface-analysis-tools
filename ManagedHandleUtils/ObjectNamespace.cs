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

using NtApiDotNet;
using System;

namespace SandboxAnalysisUtils
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
		    return OpenSessionDirectory(NtProcess.Current.SessionId);
	    }

	    public static string ReadSymlink(string symlink_path)
	    {
            using (NtSymbolicLink symlink = NtSymbolicLink.Open(symlink_path, null, SymbolicLinkAccessRights.Query))
            {
                return symlink.Target;
            }
	    }
    }
}
