//  Copyright 2015 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System;
using System.ComponentModel;
using System.Security.Principal;
using System.Windows.Forms;

namespace TokenViewer
{
    public partial class AddSidForm : Form
    {
        public AddSidForm()
        {
            InitializeComponent();
        }

        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden), Browsable(false)]
        public SecurityIdentifier Sid {
            get; private set;
        }

        private void btnOK_Click(object sender, EventArgs e)
        {
            bool success = false;
            try
            {
                Sid = new SecurityIdentifier(textBoxSid.Text);
                success = true;
            }
            catch (Exception)
            {
            }

            if (!success)
            {
                try
                {
                    NTAccount acct = new NTAccount(textBoxSid.Text);
                    Sid = (SecurityIdentifier)acct.Translate(typeof(SecurityIdentifier));
                    success = true;
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

            if (success)
            {
                DialogResult = DialogResult.OK;
                Close();
            }
        }
    }
}
