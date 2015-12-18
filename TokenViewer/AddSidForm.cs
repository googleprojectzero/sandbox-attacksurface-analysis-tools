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
