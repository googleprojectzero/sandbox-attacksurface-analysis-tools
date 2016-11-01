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

using System;
using System.ComponentModel;
using System.Text;
using System.Windows.Forms;

namespace EditSection
{
    partial class CorruptSectionForm : Form
    {        
        ICorruptSection _corrupt_section;

        public CorruptSectionForm()
        {
            InitializeComponent();
            foreach (object value in Enum.GetValues(typeof(CorruptSectionOperation)))
            {
                comboBoxRandomOperation.Items.Add(value);
                comboBoxFixedOperation.Items.Add(value);
                comboBoxStringOperation.Items.Add(value);
            }

            comboBoxRandomOperation.SelectedIndex = 0;
            comboBoxFixedOperation.SelectedIndex = 0;
            comboBoxStringOperation.SelectedIndex = 0;
        }

        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
        internal ICorruptSection CorruptSectionObject
        {
            get
            {
                return _corrupt_section;
            }
        }

        private void radioRandom_CheckedChanged(object sender, System.EventArgs e)
        {
            groupBoxRandomCorruption.Enabled = radioRandom.Checked;

        }

        private void radioFixed_CheckedChanged(object sender, EventArgs e)
        {
            groupBoxFixedCorruption.Enabled = radioFixed.Checked;
        }

        private void radioString_CheckedChanged(object sender, EventArgs e)
        {
            groupBoxStringCorruption.Enabled = radioString.Checked;
        }

        private void btnOK_Click(object sender, EventArgs e)
        {
            bool succes = false;

            if (radioRandom.Checked)
            {
                if (numericMinimum.Value > numericMaximum.Value)
                {
                    MessageBox.Show(this, "Minimum value must be less than or equal to maximum", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    _corrupt_section = new CorruptSectionRandomValue((byte)numericMinimum.Value,
                        (byte)numericMaximum.Value, (CorruptSectionOperation)comboBoxRandomOperation.SelectedItem);
                    succes = true;
                }
            }
            else if (radioFixed.Checked)
            {
                byte[] data = new byte[1];
                data[0] = (byte)numericFixedValue.Value;
                _corrupt_section = new CorruptSectionFixedValue(data,
                    (CorruptSectionOperation)comboBoxFixedOperation.SelectedItem);
                succes = true;
            }
            else if (radioString.Checked)
            {
                byte[] data = Encoding.UTF8.GetBytes(textBoxString.Text);
                _corrupt_section = new CorruptSectionFixedValue(data,
                    (CorruptSectionOperation)comboBoxStringOperation.SelectedItem);
                succes = true;
            }
            
            if(succes)
            {
                DialogResult = DialogResult.OK;
                Close();
            }
        }
    }
}
