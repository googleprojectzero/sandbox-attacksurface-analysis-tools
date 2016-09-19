using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace HandleUtils
{
    public sealed class ImpersonateProcess : IDisposable
    {
        NativeHandle _token;
	    WindowsImpersonationContext _context;

        public void Dispose()
        {
            _context.Dispose();
            _token.Dispose();
        }

        public ImpersonateProcess(NativeHandle token)
        {
            _token = token;
            _context = WindowsIdentity.Impersonate(_token.DangerousGetHandle());
        }
    }

}
