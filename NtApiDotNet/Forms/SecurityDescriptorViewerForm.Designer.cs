namespace NtApiDotNet.Forms
{
    partial class SecurityDescriptorViewerForm
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

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(SecurityDescriptorViewerForm));
            this.tableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
            this.btnEditPermissions = new System.Windows.Forms.Button();
            this.securityDescriptorViewerControl = new NtApiDotNet.Forms.SecurityDescriptorViewerControl();
            this.tabControl = new System.Windows.Forms.TabControl();
            this.tabPageSecurity = new System.Windows.Forms.TabPage();
            this.tableLayoutPanel.SuspendLayout();
            this.tabControl.SuspendLayout();
            this.tabPageSecurity.SuspendLayout();
            this.SuspendLayout();
            // 
            // tableLayoutPanel
            // 
            this.tableLayoutPanel.ColumnCount = 1;
            this.tableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel.Controls.Add(this.securityDescriptorViewerControl, 0, 0);
            this.tableLayoutPanel.Controls.Add(this.btnEditPermissions, 0, 1);
            this.tableLayoutPanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel.Location = new System.Drawing.Point(3, 3);
            this.tableLayoutPanel.Name = "tableLayoutPanel";
            this.tableLayoutPanel.RowCount = 2;
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel.Size = new System.Drawing.Size(467, 415);
            this.tableLayoutPanel.TabIndex = 0;
            // 
            // btnEditPermissions
            // 
            this.btnEditPermissions.Enabled = false;
            this.btnEditPermissions.Location = new System.Drawing.Point(3, 378);
            this.btnEditPermissions.Name = "btnEditPermissions";
            this.btnEditPermissions.Size = new System.Drawing.Size(96, 34);
            this.btnEditPermissions.TabIndex = 1;
            this.btnEditPermissions.Text = "Edit";
            this.btnEditPermissions.UseVisualStyleBackColor = true;
            this.btnEditPermissions.Click += new System.EventHandler(this.btnEditPermissions_Click);
            // 
            // securityDescriptorViewerControl
            // 
            this.securityDescriptorViewerControl.Dock = System.Windows.Forms.DockStyle.Fill;
            this.securityDescriptorViewerControl.Location = new System.Drawing.Point(3, 3);
            this.securityDescriptorViewerControl.Name = "securityDescriptorViewerControl";
            this.securityDescriptorViewerControl.Size = new System.Drawing.Size(461, 369);
            this.securityDescriptorViewerControl.TabIndex = 0;
            // 
            // tabControl
            // 
            this.tabControl.Controls.Add(this.tabPageSecurity);
            this.tabControl.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tabControl.Location = new System.Drawing.Point(0, 0);
            this.tabControl.Name = "tabControl";
            this.tabControl.SelectedIndex = 0;
            this.tabControl.Size = new System.Drawing.Size(481, 450);
            this.tabControl.TabIndex = 1;
            // 
            // tabPageSecurity
            // 
            this.tabPageSecurity.Controls.Add(this.tableLayoutPanel);
            this.tabPageSecurity.Location = new System.Drawing.Point(4, 25);
            this.tabPageSecurity.Name = "tabPageSecurity";
            this.tabPageSecurity.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageSecurity.Size = new System.Drawing.Size(473, 421);
            this.tabPageSecurity.TabIndex = 0;
            this.tabPageSecurity.Text = "Security";
            this.tabPageSecurity.UseVisualStyleBackColor = true;
            // 
            // SecurityDescriptorViewerForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(481, 450);
            this.Controls.Add(this.tabControl);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "SecurityDescriptorViewerForm";
            this.Text = "SecurityDescriptorViewerForm";
            this.tableLayoutPanel.ResumeLayout(false);
            this.tabControl.ResumeLayout(false);
            this.tabPageSecurity.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel;
        private SecurityDescriptorViewerControl securityDescriptorViewerControl;
        private System.Windows.Forms.Button btnEditPermissions;
        private System.Windows.Forms.TabControl tabControl;
        private System.Windows.Forms.TabPage tabPageSecurity;
    }
}