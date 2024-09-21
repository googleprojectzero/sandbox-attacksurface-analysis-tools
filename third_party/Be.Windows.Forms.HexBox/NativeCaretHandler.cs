using System;
using System.Windows.Forms;

namespace Be.Windows.Forms
{
    class NativeCaretHandler : CaretHandler
    {
        public override bool CreateCaret(Control control, int nWidth, int nHeight)
        {
            return NativeMethods.CreateCaret(control.Handle, IntPtr.Zero, nWidth, nHeight);
        }

        public override bool ShowCaret(Control control)
        {
            return NativeMethods.ShowCaret(control.Handle);
        }

        public override bool DestroyCaret()
        {
            return NativeMethods.DestroyCaret();
        }

        public override bool SetCaretPos(int X, int Y)
        {
            return NativeMethods.SetCaretPos(X, Y);
        }

        public override void Draw(System.Drawing.Graphics g)
        {
            // Do nothing
        }
    }
}
