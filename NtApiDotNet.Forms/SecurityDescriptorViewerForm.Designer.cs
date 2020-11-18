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
            this.btnEditPermissions = new System.Windows.Forms.Button();
            this.securityDescriptorViewerControl = new NtApiDotNet.Forms.SecurityDescriptorViewerControl();
            this.tableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
            this.tableLayoutPanel.SuspendLayout();
            this.SuspendLayout();
            // 
            // btnEditPermissions
            // 
            this.btnEditPermissions.Enabled = false;
            this.btnEditPermissions.Location = new System.Drawing.Point(2, 376);
            this.btnEditPermissions.Margin = new System.Windows.Forms.Padding(2);
            this.btnEditPermissions.Name = "btnEditPermissions";
            this.btnEditPermissions.Size = new System.Drawing.Size(72, 28);
            this.btnEditPermissions.TabIndex = 1;
            this.btnEditPermissions.Text = "Edit";
            this.btnEditPermissions.UseVisualStyleBackColor = true;
            this.btnEditPermissions.Click += new System.EventHandler(this.btnEditPermissions_Click);
            // 
            // securityDescriptorViewerControl
            // 
            this.securityDescriptorViewerControl.Dock = System.Windows.Forms.DockStyle.Fill;
            this.securityDescriptorViewerControl.Location = new System.Drawing.Point(2, 2);
            this.securityDescriptorViewerControl.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.securityDescriptorViewerControl.Name = "securityDescriptorViewerControl";
            this.securityDescriptorViewerControl.Size = new System.Drawing.Size(350, 370);
            this.securityDescriptorViewerControl.TabIndex = 2;
            // 
            // tableLayoutPanel
            // 
            this.tableLayoutPanel.ColumnCount = 1;
            this.tableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel.Controls.Add(this.securityDescriptorViewerControl, 0, 0);
            this.tableLayoutPanel.Controls.Add(this.btnEditPermissions, 0, 1);
            this.tableLayoutPanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel.Location = new System.Drawing.Point(0, 0);
            this.tableLayoutPanel.Margin = new System.Windows.Forms.Padding(2);
            this.tableLayoutPanel.Name = "tableLayoutPanel";
            this.tableLayoutPanel.RowCount = 2;
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel.Size = new System.Drawing.Size(354, 406);
            this.tableLayoutPanel.TabIndex = 3;
            // 
            // SecurityDescriptorViewerForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(354, 406);
            this.Controls.Add(this.tableLayoutPanel);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(2);
            this.Name = "SecurityDescriptorViewerForm";
            this.Text = "SecurityDescriptorViewerForm";
            this.tableLayoutPanel.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion
        private System.Windows.Forms.Button btnEditPermissions;
        private SecurityDescriptorViewerControl securityDescriptorViewerControl;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel;
    }
}