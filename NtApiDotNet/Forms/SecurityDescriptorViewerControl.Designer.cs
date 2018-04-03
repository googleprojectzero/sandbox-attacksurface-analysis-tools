namespace NtApiDotNet.Forms
{
    partial class SecurityDescriptorViewerControl
    {
        /// <summary> 
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.Windows.Forms.Label lblOwner;
            System.Windows.Forms.Label lblGroup;
            System.Windows.Forms.Label lblIntegrity;
            this.tableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
            this.tabControl = new System.Windows.Forms.TabControl();
            this.tabPageDACL = new System.Windows.Forms.TabPage();
            this.tabPageSACL = new System.Windows.Forms.TabPage();
            this.lblOwnerValue = new System.Windows.Forms.Label();
            this.lblGroupValue = new System.Windows.Forms.Label();
            this.lblIntegrityValue = new System.Windows.Forms.Label();
            this.aclViewerControlDacl = new NtApiDotNet.Forms.AclViewerControl();
            this.aclViewerControlSacl = new NtApiDotNet.Forms.AclViewerControl();
            lblOwner = new System.Windows.Forms.Label();
            lblGroup = new System.Windows.Forms.Label();
            lblIntegrity = new System.Windows.Forms.Label();
            this.tableLayoutPanel.SuspendLayout();
            this.tabControl.SuspendLayout();
            this.tabPageDACL.SuspendLayout();
            this.tabPageSACL.SuspendLayout();
            this.SuspendLayout();
            // 
            // lblOwner
            // 
            lblOwner.Anchor = System.Windows.Forms.AnchorStyles.Left;
            lblOwner.AutoSize = true;
            lblOwner.Location = new System.Drawing.Point(3, 0);
            lblOwner.Name = "lblOwner";
            lblOwner.Padding = new System.Windows.Forms.Padding(0, 2, 0, 2);
            lblOwner.Size = new System.Drawing.Size(53, 21);
            lblOwner.TabIndex = 3;
            lblOwner.Text = "Owner:";
            // 
            // lblGroup
            // 
            lblGroup.Anchor = System.Windows.Forms.AnchorStyles.Left;
            lblGroup.AutoSize = true;
            lblGroup.Location = new System.Drawing.Point(3, 23);
            lblGroup.Name = "lblGroup";
            lblGroup.Size = new System.Drawing.Size(52, 17);
            lblGroup.TabIndex = 5;
            lblGroup.Text = "Group:";
            // 
            // lblIntegrity
            // 
            lblIntegrity.Anchor = System.Windows.Forms.AnchorStyles.Left;
            lblIntegrity.AutoSize = true;
            lblIntegrity.Location = new System.Drawing.Point(3, 44);
            lblIntegrity.Name = "lblIntegrity";
            lblIntegrity.Size = new System.Drawing.Size(62, 17);
            lblIntegrity.TabIndex = 7;
            lblIntegrity.Text = "Integrity:";
            // 
            // tableLayoutPanel
            // 
            this.tableLayoutPanel.ColumnCount = 2;
            this.tableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel.Controls.Add(this.tabControl, 0, 3);
            this.tableLayoutPanel.Controls.Add(lblOwner, 0, 0);
            this.tableLayoutPanel.Controls.Add(this.lblOwnerValue, 1, 0);
            this.tableLayoutPanel.Controls.Add(lblGroup, 0, 1);
            this.tableLayoutPanel.Controls.Add(this.lblGroupValue, 1, 1);
            this.tableLayoutPanel.Controls.Add(lblIntegrity, 0, 2);
            this.tableLayoutPanel.Controls.Add(this.lblIntegrityValue, 1, 2);
            this.tableLayoutPanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel.Location = new System.Drawing.Point(0, 0);
            this.tableLayoutPanel.Name = "tableLayoutPanel";
            this.tableLayoutPanel.RowCount = 4;
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel.Size = new System.Drawing.Size(419, 543);
            this.tableLayoutPanel.TabIndex = 2;
            // 
            // tabControl
            // 
            this.tableLayoutPanel.SetColumnSpan(this.tabControl, 2);
            this.tabControl.Controls.Add(this.tabPageDACL);
            this.tabControl.Controls.Add(this.tabPageSACL);
            this.tabControl.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tabControl.Location = new System.Drawing.Point(3, 66);
            this.tabControl.Name = "tabControl";
            this.tabControl.SelectedIndex = 0;
            this.tabControl.Size = new System.Drawing.Size(413, 474);
            this.tabControl.TabIndex = 2;
            // 
            // tabPageDACL
            // 
            this.tabPageDACL.Controls.Add(this.aclViewerControlDacl);
            this.tabPageDACL.Location = new System.Drawing.Point(4, 25);
            this.tabPageDACL.Name = "tabPageDACL";
            this.tabPageDACL.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageDACL.Size = new System.Drawing.Size(405, 445);
            this.tabPageDACL.TabIndex = 0;
            this.tabPageDACL.Text = "DACL";
            this.tabPageDACL.UseVisualStyleBackColor = true;
            // 
            // tabPageSACL
            // 
            this.tabPageSACL.Controls.Add(this.aclViewerControlSacl);
            this.tabPageSACL.Location = new System.Drawing.Point(4, 25);
            this.tabPageSACL.Name = "tabPageSACL";
            this.tabPageSACL.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageSACL.Size = new System.Drawing.Size(405, 445);
            this.tabPageSACL.TabIndex = 1;
            this.tabPageSACL.Text = "SACL";
            this.tabPageSACL.UseVisualStyleBackColor = true;
            // 
            // lblOwnerValue
            // 
            this.lblOwnerValue.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.lblOwnerValue.AutoSize = true;
            this.lblOwnerValue.Location = new System.Drawing.Point(71, 0);
            this.lblOwnerValue.Name = "lblOwnerValue";
            this.lblOwnerValue.Padding = new System.Windows.Forms.Padding(0, 2, 0, 2);
            this.lblOwnerValue.Size = new System.Drawing.Size(69, 21);
            this.lblOwnerValue.TabIndex = 4;
            this.lblOwnerValue.Text = "#OWNER";
            // 
            // lblGroupValue
            // 
            this.lblGroupValue.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.lblGroupValue.AutoSize = true;
            this.lblGroupValue.Location = new System.Drawing.Point(71, 21);
            this.lblGroupValue.Name = "lblGroupValue";
            this.lblGroupValue.Padding = new System.Windows.Forms.Padding(0, 2, 0, 2);
            this.lblGroupValue.Size = new System.Drawing.Size(67, 21);
            this.lblGroupValue.TabIndex = 6;
            this.lblGroupValue.Text = "#GROUP";
            // 
            // lblIntegrityValue
            // 
            this.lblIntegrityValue.Anchor = System.Windows.Forms.AnchorStyles.Left;
            this.lblIntegrityValue.AutoSize = true;
            this.lblIntegrityValue.Location = new System.Drawing.Point(71, 42);
            this.lblIntegrityValue.Name = "lblIntegrityValue";
            this.lblIntegrityValue.Padding = new System.Windows.Forms.Padding(0, 2, 0, 2);
            this.lblIntegrityValue.Size = new System.Drawing.Size(89, 21);
            this.lblIntegrityValue.TabIndex = 8;
            this.lblIntegrityValue.Text = "#INTEGRITY";
            // 
            // aclViewerControlDacl
            // 
            this.aclViewerControlDacl.Dock = System.Windows.Forms.DockStyle.Fill;
            this.aclViewerControlDacl.Location = new System.Drawing.Point(3, 3);
            this.aclViewerControlDacl.Name = "aclViewerControlDacl";
            this.aclViewerControlDacl.Size = new System.Drawing.Size(399, 439);
            this.aclViewerControlDacl.TabIndex = 0;
            // 
            // aclViewerControlSacl
            // 
            this.aclViewerControlSacl.Dock = System.Windows.Forms.DockStyle.Fill;
            this.aclViewerControlSacl.Location = new System.Drawing.Point(3, 3);
            this.aclViewerControlSacl.Name = "aclViewerControlSacl";
            this.aclViewerControlSacl.Size = new System.Drawing.Size(399, 439);
            this.aclViewerControlSacl.TabIndex = 0;
            // 
            // SecurityDescriptorViewerControl
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.tableLayoutPanel);
            this.Name = "SecurityDescriptorViewerControl";
            this.Size = new System.Drawing.Size(419, 543);
            this.tableLayoutPanel.ResumeLayout(false);
            this.tableLayoutPanel.PerformLayout();
            this.tabControl.ResumeLayout(false);
            this.tabPageDACL.ResumeLayout(false);
            this.tabPageSACL.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel;
        private System.Windows.Forms.TabControl tabControl;
        private System.Windows.Forms.TabPage tabPageDACL;
        private System.Windows.Forms.TabPage tabPageSACL;
        private System.Windows.Forms.Label lblOwnerValue;
        private System.Windows.Forms.Label lblGroupValue;
        private System.Windows.Forms.Label lblIntegrityValue;
        private AclViewerControl aclViewerControlDacl;
        private AclViewerControl aclViewerControlSacl;
    }
}
