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
            this.components = new System.ComponentModel.Container();
            System.Windows.Forms.ColumnHeader columnHeaderType;
            System.Windows.Forms.ColumnHeader columnHeaderAccount;
            System.Windows.Forms.ColumnHeader columnHeaderAccess;
            System.Windows.Forms.GroupBox groupBoxAclEntries;
            System.Windows.Forms.ColumnHeader columnHeaderFlags;
            System.Windows.Forms.GroupBox groupBoxAccess;
            System.Windows.Forms.ColumnHeader columnHeaderName;
            System.Windows.Forms.ColumnHeader columnHeaderAccessMask;
            this.listViewAcl = new System.Windows.Forms.ListView();
            this.columnHeaderCondition = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderObject = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderInheritedObject = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.contextMenuStripAcl = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.copySIDToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.copyAccountToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.copyConditionToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.copyACESDDLToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.listViewAccess = new System.Windows.Forms.ListView();
            this.tableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
            columnHeaderType = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderAccount = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderAccess = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            groupBoxAclEntries = new System.Windows.Forms.GroupBox();
            columnHeaderFlags = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            groupBoxAccess = new System.Windows.Forms.GroupBox();
            columnHeaderName = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderAccessMask = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            groupBoxAclEntries.SuspendLayout();
            this.contextMenuStripAcl.SuspendLayout();
            groupBoxAccess.SuspendLayout();
            this.tableLayoutPanel.SuspendLayout();
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
            // groupBoxAclEntries
            // 
            groupBoxAclEntries.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            groupBoxAclEntries.Controls.Add(this.listViewAcl);
            groupBoxAclEntries.Location = new System.Drawing.Point(2, 2);
            groupBoxAclEntries.Margin = new System.Windows.Forms.Padding(2);
            groupBoxAclEntries.Name = "groupBoxAclEntries";
            groupBoxAclEntries.Padding = new System.Windows.Forms.Padding(2);
            groupBoxAclEntries.Size = new System.Drawing.Size(342, 201);
            groupBoxAclEntries.TabIndex = 1;
            groupBoxAclEntries.TabStop = false;
            groupBoxAclEntries.Text = "ACL Entries";
            // 
            // listViewAcl
            // 
            this.listViewAcl.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.listViewAcl.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeaderType,
            columnHeaderAccount,
            columnHeaderAccess,
            columnHeaderFlags,
            this.columnHeaderCondition,
            this.columnHeaderObject,
            this.columnHeaderInheritedObject});
            this.listViewAcl.ContextMenuStrip = this.contextMenuStripAcl;
            this.listViewAcl.FullRowSelect = true;
            this.listViewAcl.HeaderStyle = System.Windows.Forms.ColumnHeaderStyle.Nonclickable;
            this.listViewAcl.HideSelection = false;
            this.listViewAcl.Location = new System.Drawing.Point(4, 17);
            this.listViewAcl.Margin = new System.Windows.Forms.Padding(2);
            this.listViewAcl.MultiSelect = false;
            this.listViewAcl.Name = "listViewAcl";
            this.listViewAcl.Size = new System.Drawing.Size(334, 180);
            this.listViewAcl.TabIndex = 0;
            this.listViewAcl.UseCompatibleStateImageBehavior = false;
            this.listViewAcl.View = System.Windows.Forms.View.Details;
            this.listViewAcl.SelectedIndexChanged += new System.EventHandler(this.listViewAcl_SelectedIndexChanged);
            // 
            // columnHeaderFlags
            // 
            columnHeaderFlags.Text = "Flags";
            // 
            // columnHeaderCondition
            // 
            this.columnHeaderCondition.Text = "Condition";
            // 
            // columnHeaderObject
            // 
            this.columnHeaderObject.Text = "Object";
            // 
            // columnHeaderInheritedObject
            // 
            this.columnHeaderInheritedObject.Text = "Inherited Object";
            // 
            // contextMenuStripAcl
            // 
            this.contextMenuStripAcl.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.contextMenuStripAcl.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.copySIDToolStripMenuItem,
            this.copyAccountToolStripMenuItem,
            this.copyConditionToolStripMenuItem,
            this.copyACESDDLToolStripMenuItem});
            this.contextMenuStripAcl.Name = "contextMenuStripAcl";
            this.contextMenuStripAcl.Size = new System.Drawing.Size(159, 92);
            this.contextMenuStripAcl.Opening += new System.ComponentModel.CancelEventHandler(this.contextMenuStripAcl_Opening);
            // 
            // copySIDToolStripMenuItem
            // 
            this.copySIDToolStripMenuItem.Name = "copySIDToolStripMenuItem";
            this.copySIDToolStripMenuItem.Size = new System.Drawing.Size(158, 22);
            this.copySIDToolStripMenuItem.Text = "Copy SID";
            this.copySIDToolStripMenuItem.Click += new System.EventHandler(this.copySIDToolStripMenuItem_Click);
            // 
            // copyAccountToolStripMenuItem
            // 
            this.copyAccountToolStripMenuItem.Name = "copyAccountToolStripMenuItem";
            this.copyAccountToolStripMenuItem.Size = new System.Drawing.Size(158, 22);
            this.copyAccountToolStripMenuItem.Text = "Copy Account";
            this.copyAccountToolStripMenuItem.Click += new System.EventHandler(this.copyAccountToolStripMenuItem_Click);
            // 
            // copyConditionToolStripMenuItem
            // 
            this.copyConditionToolStripMenuItem.Name = "copyConditionToolStripMenuItem";
            this.copyConditionToolStripMenuItem.Size = new System.Drawing.Size(158, 22);
            this.copyConditionToolStripMenuItem.Text = "Copy Condition";
            this.copyConditionToolStripMenuItem.Click += new System.EventHandler(this.copyConditionToolStripMenuItem_Click);
            // 
            // copyACESDDLToolStripMenuItem
            // 
            this.copyACESDDLToolStripMenuItem.Name = "copyACESDDLToolStripMenuItem";
            this.copyACESDDLToolStripMenuItem.Size = new System.Drawing.Size(158, 22);
            this.copyACESDDLToolStripMenuItem.Text = "Copy ACE SDDL";
            this.copyACESDDLToolStripMenuItem.Click += new System.EventHandler(this.copyACESDDLToolStripMenuItem_Click);
            // 
            // groupBoxAccess
            // 
            groupBoxAccess.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            groupBoxAccess.Controls.Add(this.listViewAccess);
            groupBoxAccess.Location = new System.Drawing.Point(2, 207);
            groupBoxAccess.Margin = new System.Windows.Forms.Padding(2);
            groupBoxAccess.Name = "groupBoxAccess";
            groupBoxAccess.Padding = new System.Windows.Forms.Padding(2);
            groupBoxAccess.Size = new System.Drawing.Size(342, 202);
            groupBoxAccess.TabIndex = 2;
            groupBoxAccess.TabStop = false;
            groupBoxAccess.Text = "Specific Access";
            // 
            // listViewAccess
            // 
            this.listViewAccess.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.listViewAccess.CheckBoxes = true;
            this.listViewAccess.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeaderName,
            columnHeaderAccessMask});
            this.listViewAccess.FullRowSelect = true;
            this.listViewAccess.HeaderStyle = System.Windows.Forms.ColumnHeaderStyle.Nonclickable;
            this.listViewAccess.HideSelection = false;
            this.listViewAccess.Location = new System.Drawing.Point(4, 17);
            this.listViewAccess.Margin = new System.Windows.Forms.Padding(2);
            this.listViewAccess.MultiSelect = false;
            this.listViewAccess.Name = "listViewAccess";
            this.listViewAccess.Size = new System.Drawing.Size(334, 181);
            this.listViewAccess.TabIndex = 0;
            this.listViewAccess.UseCompatibleStateImageBehavior = false;
            this.listViewAccess.View = System.Windows.Forms.View.Details;
            this.listViewAccess.ItemCheck += new System.Windows.Forms.ItemCheckEventHandler(this.listViewAccess_ItemCheck);
            // 
            // columnHeaderName
            // 
            columnHeaderName.Text = "Name";
            // 
            // columnHeaderAccessMask
            // 
            columnHeaderAccessMask.Text = "Access Mask";
            // 
            // tableLayoutPanel
            // 
            this.tableLayoutPanel.ColumnCount = 1;
            this.tableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel.Controls.Add(groupBoxAclEntries, 0, 0);
            this.tableLayoutPanel.Controls.Add(groupBoxAccess, 0, 1);
            this.tableLayoutPanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel.Location = new System.Drawing.Point(0, 0);
            this.tableLayoutPanel.Margin = new System.Windows.Forms.Padding(2);
            this.tableLayoutPanel.Name = "tableLayoutPanel";
            this.tableLayoutPanel.RowCount = 2;
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 50F));
            this.tableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 50F));
            this.tableLayoutPanel.Size = new System.Drawing.Size(346, 411);
            this.tableLayoutPanel.TabIndex = 1;
            // 
            // AclViewerControl
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.tableLayoutPanel);
            this.Margin = new System.Windows.Forms.Padding(2);
            this.Name = "AclViewerControl";
            this.Size = new System.Drawing.Size(346, 411);
            groupBoxAclEntries.ResumeLayout(false);
            this.contextMenuStripAcl.ResumeLayout(false);
            groupBoxAccess.ResumeLayout(false);
            this.tableLayoutPanel.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.ListView listViewAcl;
        private System.Windows.Forms.ColumnHeader columnHeaderCondition;
        private System.Windows.Forms.ListView listViewAccess;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel;
        private System.Windows.Forms.ContextMenuStrip contextMenuStripAcl;
        private System.Windows.Forms.ToolStripMenuItem copySIDToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem copyAccountToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem copyConditionToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem copyACESDDLToolStripMenuItem;
        private System.Windows.Forms.ColumnHeader columnHeaderObject;
        private System.Windows.Forms.ColumnHeader columnHeaderInheritedObject;
    }
}
