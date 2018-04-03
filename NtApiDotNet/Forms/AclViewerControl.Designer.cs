namespace NtApiDotNet.Forms
{
    partial class AclViewerControl
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
            System.Windows.Forms.ColumnHeader columnHeaderType;
            System.Windows.Forms.ColumnHeader columnHeaderAccount;
            System.Windows.Forms.ColumnHeader columnHeaderAccess;
            this.listViewAcl = new System.Windows.Forms.ListView();
            this.columnHeaderCondition = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderType = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderAccount = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderAccess = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.SuspendLayout();
            // 
            // columnHeaderType
            // 
            columnHeaderType.Text = "Type";
            // 
            // columnHeaderAccount
            // 
            columnHeaderAccount.Text = "Account";
            // 
            // columnHeaderAccess
            // 
            columnHeaderAccess.Text = "Access";
            // 
            // listViewAcl
            // 
            this.listViewAcl.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeaderType,
            columnHeaderAccount,
            columnHeaderAccess,
            this.columnHeaderCondition});
            this.listViewAcl.Dock = System.Windows.Forms.DockStyle.Fill;
            this.listViewAcl.FullRowSelect = true;
            this.listViewAcl.Location = new System.Drawing.Point(0, 0);
            this.listViewAcl.Name = "listViewAcl";
            this.listViewAcl.Size = new System.Drawing.Size(855, 506);
            this.listViewAcl.TabIndex = 0;
            this.listViewAcl.UseCompatibleStateImageBehavior = false;
            this.listViewAcl.View = System.Windows.Forms.View.Details;
            // 
            // columnHeaderCondition
            // 
            this.columnHeaderCondition.Text = "Condition";
            // 
            // AclViewerControl
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.listViewAcl);
            this.Name = "AclViewerControl";
            this.Size = new System.Drawing.Size(855, 506);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.ListView listViewAcl;
        private System.Windows.Forms.ColumnHeader columnHeaderCondition;
    }
}
