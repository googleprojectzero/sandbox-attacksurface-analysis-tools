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
            // btnOpen
            // 
            this.btnOpen.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.btnOpen.Location = new System.Drawing.Point(192, 307);
            this.btnOpen.Name = "btnOpen";
            this.btnOpen.Size = new System.Drawing.Size(75, 23);
            this.btnOpen.TabIndex = 0;
            this.btnOpen.Text = "Open";
            this.btnOpen.UseVisualStyleBackColor = true;
            this.btnOpen.Click += new System.EventHandler(this.btnOpen_Click);
            // 
            // btnCancel
            // 
            this.btnCancel.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.btnCancel.Location = new System.Drawing.Point(365, 307);
            this.btnCancel.Name = "btnCancel";
            this.btnCancel.Size = new System.Drawing.Size(75, 23);
            this.btnCancel.TabIndex = 1;
            this.btnCancel.Text = "Cancel";
            this.btnCancel.UseVisualStyleBackColor = true;
            this.btnCancel.Click += new System.EventHandler(this.btnCancel_Click);
            // 
            // checkReadOnly
            // 
            this.checkReadOnly.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.checkReadOnly.AutoSize = true;
            this.checkReadOnly.Location = new System.Drawing.Point(529, 308);
            this.checkReadOnly.Name = "checkReadOnly";
            this.checkReadOnly.Size = new System.Drawing.Size(76, 17);
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
            this.listViewSections.HeaderStyle = System.Windows.Forms.ColumnHeaderStyle.None;
            this.listViewSections.Location = new System.Drawing.Point(12, 12);
            this.listViewSections.MultiSelect = false;
            this.listViewSections.Name = "listViewSections";
            this.listViewSections.Size = new System.Drawing.Size(626, 262);
            this.listViewSections.TabIndex = 3;
            this.listViewSections.UseCompatibleStateImageBehavior = false;
            this.listViewSections.View = System.Windows.Forms.View.Details;
            this.listViewSections.SelectedIndexChanged += new System.EventHandler(this.listViewSections_SelectedIndexChanged);
            this.listViewSections.MouseDoubleClick += new System.Windows.Forms.MouseEventHandler(this.listViewSections_MouseDoubleClick);
            // 
            // txtObjectName
            // 
            this.txtObjectName.Location = new System.Drawing.Point(56, 280);
            this.txtObjectName.Name = "txtObjectName";
            this.txtObjectName.Size = new System.Drawing.Size(582, 20);
            this.txtObjectName.TabIndex = 4;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new System.Drawing.Point(12, 283);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(38, 13);
            label1.TabIndex = 5;
            label1.Text = "Name:";
            // 
            // NamedSectionForm
            // 
            this.AcceptButton = this.btnOpen;
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.CancelButton = this.btnCancel;
            this.ClientSize = new System.Drawing.Size(650, 342);
            this.Controls.Add(label1);
            this.Controls.Add(this.txtObjectName);
            this.Controls.Add(this.listViewSections);
            this.Controls.Add(this.checkReadOnly);
            this.Controls.Add(this.btnCancel);
            this.Controls.Add(this.btnOpen);
            this.Name = "NamedSectionForm";
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