using System;
using System.Drawing;

namespace Be.Windows.Forms
{
    /// <summary>
    /// A annotation entry
    /// </summary>
    class HexAnnotation : IComparable<HexAnnotation>
    {
        public long StartPosition { get; set; }
        public long EndPosition { get; set; }
        public Color ForeColor { get; set; }
        public Color BackColor { get; set; }

        /// <summary>
        /// Just sort by start position
        /// </summary>
        /// <param name="other">The other annotation</param>
        /// <returns>The comparison</returns>
        public int CompareTo(HexAnnotation other)
        {
            return StartPosition.CompareTo(other.StartPosition);
        }

        public bool InAnnotation(long pos)
        {
            return (StartPosition <= pos) && (pos <= EndPosition);
        }

        public HexAnnotation()
        {
            ForeColor = Color.Black;
            BackColor = Color.White;
        }
    }
}
