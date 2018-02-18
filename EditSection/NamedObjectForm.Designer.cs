namespace EditSection
{
    partial class NamedObjectForm
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
            System.Windows.Forms.ColumnHeader columnHeaderName;
            System.Windows.Forms.Label label1;
            this.btnOpen = new System.Windows.Forms.Button();
            this.btnCancel = new System.Windows.Forms.Button();
            this.checkReadOnly = new System.Windows.Forms.CheckBox();
            this.listViewSections = new System.Windows.Forms.ListView();
            this.txtObjectName = new System.Windows.Forms.TextBox();
            columnHeaderName = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            label1 = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // columnHeaderName
            // 
            columnHeaderName.Text = "Name";
            columnHeaderName.Width = 422;
            // 
            // label1
            // 
            label1.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            label1.AutoSize = true;
            label1.Location = new System.Drawing.Point(18, 435);
            label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(55, 20);
            label1.TabIndex = 5;
            label1.Text = "Name:";
            // 
            // btnOpen
            // 
            this.btnOpen.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.btnOpen.Location = new System.Drawing.Point(288, 472);
            this.btnOpen.Margin = new System.Windows.Forms.Padding(4, 5, 4, 5);
            this.btnOpen.Name = "btnOpen";
            this.btnOpen.Size = new System.Drawing.Size(112, 35);
            this.btnOpen.TabIndex = 0;
            this.btnOpen.Text = "Open";
            this.btnOpen.UseVisualStyleBackColor = true;
            this.btnOpen.Click += new System.EventHandler(this.btnOpen_Click);
            // 
            // btnCancel
            // 
            this.btnCancel.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.btnCancel.Location = new System.Drawing.Point(548, 472);
            this.btnCancel.Margin = new System.Windows.Forms.Padding(4, 5, 4, 5);
            this.btnCancel.Name = "btnCancel";
            this.btnCancel.Size = new System.Drawing.Size(112, 35);
            this.btnCancel.TabIndex = 1;
            this.btnCancel.Text = "Cancel";
            this.btnCancel.UseVisualStyleBackColor = true;
            this.btnCancel.Click += new System.EventHandler(this.btnCancel_Click);
            // 
            // checkReadOnly
            // 
            this.checkReadOnly.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.checkReadOnly.AutoSize = true;
            this.checkReadOnly.Location = new System.Drawing.Point(798, 476);
            this.checkReadOnly.Margin = new System.Windows.Forms.Padding(4, 5, 4, 5);
            this.checkReadOnly.Name = "checkReadOnly";
            this.checkReadOnly.Size = new System.Drawing.Size(109, 24);
            this.checkReadOnly.TabIndex = 2;
            this.checkReadOnly.Text = "Read Only";
            this.checkReadOnly.UseVisualStyleBackColor = true;
            // 
            // listViewSections
            // 
            this.listViewSections.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.listViewSections.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeaderName});
            this.listViewSections.FullRowSelect = true;
            this.listViewSections.HeaderStyle = System.Windows.Forms.ColumnHeaderStyle.Nonclickable;
            this.listViewSections.Location = new System.Drawing.Point(18, 19);
            this.listViewSections.Margin = new System.Windows.Forms.Padding(4, 5, 4, 5);
            this.listViewSections.MultiSelect = false;
            this.listViewSections.Name = "listViewSections";
            this.listViewSections.Size = new System.Drawing.Size(937, 402);
            this.listViewSections.TabIndex = 3;
            this.listViewSections.UseCompatibleStateImageBehavior = false;
            this.listViewSections.View = System.Windows.Forms.View.Details;
            this.listViewSections.SelectedIndexChanged += new System.EventHandler(this.listViewSections_SelectedIndexChanged);
            this.listViewSections.MouseDoubleClick += new System.Windows.Forms.MouseEventHandler(this.listViewSections_MouseDoubleClick);
            // 
            // txtObjectName
            // 
            this.txtObjectName.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtObjectName.Location = new System.Drawing.Point(84, 431);
            this.txtObjectName.Margin = new System.Windows.Forms.Padding(4, 5, 4, 5);
            this.txtObjectName.Name = "txtObjectName";
            this.txtObjectName.Size = new System.Drawing.Size(871, 26);
            this.txtObjectName.TabIndex = 4;
            // 
            // NamedObjectForm
            // 
            this.AcceptButton = this.btnOpen;
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.CancelButton = this.btnCancel;
            this.ClientSize = new System.Drawing.Size(975, 526);
            this.ControlBox = false;
            this.Controls.Add(label1);
            this.Controls.Add(this.txtObjectName);
            this.Controls.Add(this.listViewSections);
            this.Controls.Add(this.checkReadOnly);
            this.Controls.Add(this.btnCancel);
            this.Controls.Add(this.btnOpen);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.Margin = new System.Windows.Forms.Padding(4, 5, 4, 5);
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "NamedObjectForm";
            this.ShowIcon = false;
            this.ShowInTaskbar = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "Open Named Section";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button btnOpen;
        private System.Windows.Forms.Button btnCancel;
        private System.Windows.Forms.CheckBox checkReadOnly;
        private System.Windows.Forms.ListView listViewSections;
        private System.Windows.Forms.TextBox txtObjectName;
    }
}