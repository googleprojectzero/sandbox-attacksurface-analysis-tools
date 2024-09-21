using System.Drawing;
using System.Windows.Forms;

namespace Be.Windows.Forms
{
    class GDICaretHandler : CaretHandler
    {
        bool visible;
        int currWidth;
        int currHeight;
        int currX;
        int currY;

        public override bool CreateCaret(Control control, int nWidth, int nHeight)
        {
            currX = 0;
            currY = 0;
            currWidth = nWidth;
            currHeight = nHeight;
            visible = true;

            return true;
        }

        public override bool ShowCaret(Control control)
        {
            visible = true;

            return true;
        }

        public override bool DestroyCaret()
        {
            visible = false;

            return true;
        }

        public override bool SetCaretPos(int X, int Y)
        {
            currX = X;
            currY = Y;

            return true;
        }

        public override void Draw(Graphics g)
        {
            if (visible)
            {
                Color c = Color.FromArgb(100, Color.Gray);

                Brush b = new SolidBrush(c);
                try
                {
                    g.FillRectangle(b, new Rectangle(currX, currY, currWidth, currHeight));
                }
                finally
                {
                    b.Dispose();
                }
            }
        }
    }
}
