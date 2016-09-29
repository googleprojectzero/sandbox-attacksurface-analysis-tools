using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Represents a list where the elements can be trivially disposed in one go.
    /// </summary>
    /// <typeparam name="T">An IDisposable implementing type</typeparam>
    public class DisposableList<T> : List<T>, IDisposable where T : IDisposable
    {
        public DisposableList()
        {
        }

        public DisposableList(int capacity) : base(capacity)
        {
        }

        public DisposableList(IEnumerable<T> collection) : base(collection)
        {
        }

        #region IDisposable Support
        private bool disposedValue = false;

        // We don't support finalizable, as if this is the only container
        // it will finalize anything important anyway.
        public void Dispose()
        {
            if (!disposedValue)
            {
                foreach (IDisposable entry in this)
                {
                    entry.Dispose();
                }

                disposedValue = true;
            }
        }
        #endregion

    }

    public sealed class SafeHandleList : DisposableList<SafeHandle>
    {
        public SafeHandleList()
        {
        }

        public SafeHandleList(int capacity) : base(capacity)
        {
        }

        public SafeHandleList(IEnumerable<SafeHandle> collection) : base(collection)
        {
        }

        /// <summary>
        /// Take a copy of the safe handle list so the the original can be disposed.
        /// </summary>
        /// <returns>The copy of the handle list.</returns>
        public SafeHandleList DangerousTakeCopy()
        {
            SafeHandleList ret = new SafeHandleList(this);
            foreach (SafeHandle handle in ret)
            {
                bool success = false;
                handle.DangerousAddRef(ref success);
            }
            return ret;
        }
    }
}
