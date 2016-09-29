using System;

namespace NtApiDotNet
{
    public sealed class ThreadImpersonationContext : IDisposable
    {
        private NtThread _thread;

        internal ThreadImpersonationContext(NtThread thread)
        {
            _thread = thread;
        }

        public void Dispose()
        {
            try
            {
                _thread.SetImpersonationToken(null);
                _thread.Dispose();
                _thread = null;
            }
            catch
            {
            }
        }
    }
}
