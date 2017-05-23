using System;
//  Copyright 2015 Google Inc. All Rights Reserved.
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

using System.Collections;
using System.Globalization;
using System.Windows.Forms;

namespace TokenViewer
{
    class ListItemComparer : IComparer
    {
        public ListItemComparer(int column)
        {
            Column = column;
            Ascending = true;
        }

        private static IComparable GetComparableItem(string value)
        {
            long l;
            if (long.TryParse(value, out l))
            {
                return l;
            }
            else if (value.StartsWith("0x") && long.TryParse(value.Substring(2), NumberStyles.HexNumber, null, out l))
            {
                return l;
            }
            Guid g;
            if (Guid.TryParse(value, out g))
            {
                return g;
            }
            return value;
        }

        public int Compare(object x, object y)
        {
            ListViewItem xi = (ListViewItem)x;
            ListViewItem yi = (ListViewItem)y;

            if (xi.SubItems.Count <= Column)
            {
                throw new ArgumentException("Invalid item for comparer", "x");
            }

            if (yi.SubItems.Count <= Column)
            {
                throw new ArgumentException("Invalid item for comparer", "y");
            }

            IComparable left = GetComparableItem(xi.SubItems[Column].Text);
            IComparable right = GetComparableItem(yi.SubItems[Column].Text);

            if (Ascending)
            {
                return left.CompareTo(right);
            }
            else
            {
                return right.CompareTo(left);
            }
        }

        public int Column
        {
            get;
            set;
        }

        public bool Ascending
        {
            get;
            set;
        }

        public static void UpdateListComparer(ListView view, int selected_column)
        {
            if (view != null)
            {
                ListItemComparer comparer = view.ListViewItemSorter as ListItemComparer;

                if (comparer != null)
                {
                    if (selected_column != comparer.Column)
                    {
                        comparer.Column = selected_column;
                        comparer.Ascending = true;
                    }
                    else
                    {
                        comparer.Ascending = !comparer.Ascending;
                    }

                    view.Sort();
                }
            }
        }

    }
}
