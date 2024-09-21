using System.Drawing;
using System.Windows.Forms;

namespace Be.Windows.Forms
{
    abstract class CaretHandler
    {
        public abstract bool CreateCaret(Control control, int nWidth, int nHeight);
        
        public abstract bool ShowCaret(Control control);
        
        public abstract bool DestroyCaret();
        
        public abstract bool SetCaretPos(int X, int Y);

        public abstract void Draw(Graphics g);
    }
}
