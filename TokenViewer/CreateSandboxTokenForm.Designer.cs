namespace TokenViewer
{
    partial class CreateSandboxTokenForm
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
            this.components = new System.ComponentModel.Container();
            System.Windows.Forms.ColumnHeader columnHeaderName;
            System.Windows.Forms.ColumnHeader columnHeaderSid;
            System.Windows.Forms.ColumnHeader columnHeaderPrivilege;
            System.Windows.Forms.ColumnHeader columnHeader1;
            System.Windows.Forms.ColumnHeader columnHeader2;
            System.Windows.Forms.ColumnHeader columnHeaderDisplayName;
            System.Windows.Forms.Label lblSandboxType;
            System.Windows.Forms.Label lblPackageSid;
            System.Windows.Forms.ColumnHeader columnHeader3;
            System.Windows.Forms.ColumnHeader columnHeader4;
            this.tabPageDisableSids = new System.Windows.Forms.TabPage();
            this.checkBoxWriteRestricted = new System.Windows.Forms.CheckBox();
            this.checkBoxSandboxInert = new System.Windows.Forms.CheckBox();
            this.checkBoxMakeLuaToken = new System.Windows.Forms.CheckBox();
            this.listViewDisableSids = new System.Windows.Forms.ListView();
            this.contextMenuStripGroups = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.checkAllToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.uncheckAllToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.tabControl = new System.Windows.Forms.TabControl();
            this.tabPageDeletePrivs = new System.Windows.Forms.TabPage();
            this.checkBoxDisableMaxPrivs = new System.Windows.Forms.CheckBox();
            this.listViewDeletePrivs = new System.Windows.Forms.ListView();
            this.contextMenuStripPrivs = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.toolStripMenuItemCheckAllPrivs = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripMenuItemUncheckAllPrivs = new System.Windows.Forms.ToolStripMenuItem();
            this.tabPageRestrictedSids = new System.Windows.Forms.TabPage();
            this.btnAddAllGroups = new System.Windows.Forms.Button();
            this.listViewRestrictedSids = new System.Windows.Forms.ListView();
            this.contextMenuStripRestrictedSids = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.addSidToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.deleteSidToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.selectAllToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.btnCreate = new System.Windows.Forms.Button();
            this.btnCancel = new System.Windows.Forms.Button();
            this.btnCreateNew = new System.Windows.Forms.Button();
            this.comboBoxSandboxType = new System.Windows.Forms.ComboBox();
            this.tabPageAppContainer = new System.Windows.Forms.TabPage();
            this.textBoxPackageSid = new System.Windows.Forms.TextBox();
            this.lblCapabilities = new System.Windows.Forms.Label();
            this.listViewCapabilities = new System.Windows.Forms.ListView();
            columnHeaderName = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderSid = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderPrivilege = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeader1 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeader2 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderDisplayName = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            lblSandboxType = new System.Windows.Forms.Label();
            lblPackageSid = new System.Windows.Forms.Label();
            columnHeader3 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeader4 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.tabPageDisableSids.SuspendLayout();
            this.contextMenuStripGroups.SuspendLayout();
            this.tabControl.SuspendLayout();
            this.tabPageDeletePrivs.SuspendLayout();
            this.contextMenuStripPrivs.SuspendLayout();
            this.tabPageRestrictedSids.SuspendLayout();
            this.contextMenuStripRestrictedSids.SuspendLayout();
            this.tabPageAppContainer.SuspendLayout();
            this.SuspendLayout();
            // 
            // columnHeaderName
            // 
            columnHeaderName.Text = "Name";
            columnHeaderName.Width = 131;
            // 
            // columnHeaderSid
            // 
            columnHeaderSid.Text = "Sid";
            columnHeaderSid.Width = 235;
            // 
            // columnHeaderPrivilege
            // 
            columnHeaderPrivilege.Text = "Privilege";
            columnHeaderPrivilege.Width = 200;
            // 
            // columnHeader1
            // 
            columnHeader1.Text = "Name";
            columnHeader1.Width = 131;
            // 
            // columnHeader2
            // 
            columnHeader2.Text = "Sid";
            columnHeader2.Width = 235;
            // 
            // columnHeaderDisplayName
            // 
            columnHeaderDisplayName.Text = "Display Name";
            columnHeaderDisplayName.Width = 426;
            // 
            // lblSandboxType
            // 
            lblSandboxType.AutoSize = true;
            lblSandboxType.Location = new System.Drawing.Point(12, 8);
            lblSandboxType.Name = "lblSandboxType";
            lblSandboxType.Size = new System.Drawing.Size(79, 13);
            lblSandboxType.TabIndex = 5;
            lblSandboxType.Text = "Sandbox Type:";
            // 
            // tabPageDisableSids
            // 
            this.tabPageDisableSids.Controls.Add(this.checkBoxWriteRestricted);
            this.tabPageDisableSids.Controls.Add(this.checkBoxSandboxInert);
            this.tabPageDisableSids.Controls.Add(this.checkBoxMakeLuaToken);
            this.tabPageDisableSids.Controls.Add(this.listViewDisableSids);
            this.tabPageDisableSids.Location = new System.Drawing.Point(4, 22);
            this.tabPageDisableSids.Name = "tabPageDisableSids";
            this.tabPageDisableSids.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageDisableSids.Size = new System.Drawing.Size(686, 442);
            this.tabPageDisableSids.TabIndex = 0;
            this.tabPageDisableSids.Text = "Disable SIDs";
            this.tabPageDisableSids.UseVisualStyleBackColor = true;
            // 
            // checkBoxWriteRestricted
            // 
            this.checkBoxWriteRestricted.AutoSize = true;
            this.checkBoxWriteRestricted.Location = new System.Drawing.Point(273, 6);
            this.checkBoxWriteRestricted.Name = "checkBoxWriteRestricted";
            this.checkBoxWriteRestricted.Size = new System.Drawing.Size(102, 17);
            this.checkBoxWriteRestricted.TabIndex = 3;
            this.checkBoxWriteRestricted.Text = "Write Restricted";
            this.checkBoxWriteRestricted.UseVisualStyleBackColor = true;
            // 
            // checkBoxSandboxInert
            // 
            this.checkBoxSandboxInert.AutoSize = true;
            this.checkBoxSandboxInert.Location = new System.Drawing.Point(150, 6);
            this.checkBoxSandboxInert.Name = "checkBoxSandboxInert";
            this.checkBoxSandboxInert.Size = new System.Drawing.Size(92, 17);
            this.checkBoxSandboxInert.TabIndex = 2;
            this.checkBoxSandboxInert.Text = "Sandbox Inert";
            this.checkBoxSandboxInert.UseVisualStyleBackColor = true;
            // 
            // checkBoxMakeLuaToken
            // 
            this.checkBoxMakeLuaToken.AutoSize = true;
            this.checkBoxMakeLuaToken.Location = new System.Drawing.Point(7, 6);
            this.checkBoxMakeLuaToken.Name = "checkBoxMakeLuaToken";
            this.checkBoxMakeLuaToken.Size = new System.Drawing.Size(111, 17);
            this.checkBoxMakeLuaToken.TabIndex = 1;
            this.checkBoxMakeLuaToken.Text = "Make LUA Token";
            this.checkBoxMakeLuaToken.UseVisualStyleBackColor = true;
            // 
            // listViewDisableSids
            // 
            this.listViewDisableSids.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.listViewDisableSids.CheckBoxes = true;
            this.listViewDisableSids.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeaderName,
            columnHeaderSid});
            this.listViewDisableSids.ContextMenuStrip = this.contextMenuStripGroups;
            this.listViewDisableSids.FullRowSelect = true;
            this.listViewDisableSids.Location = new System.Drawing.Point(0, 29);
            this.listViewDisableSids.MultiSelect = false;
            this.listViewDisableSids.Name = "listViewDisableSids";
            this.listViewDisableSids.Size = new System.Drawing.Size(683, 410);
            this.listViewDisableSids.TabIndex = 0;
            this.listViewDisableSids.UseCompatibleStateImageBehavior = false;
            this.listViewDisableSids.View = System.Windows.Forms.View.Details;
            // 
            // contextMenuStripGroups
            // 
            this.contextMenuStripGroups.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.checkAllToolStripMenuItem,
            this.uncheckAllToolStripMenuItem});
            this.contextMenuStripGroups.Name = "contextMenuStripGroups";
            this.contextMenuStripGroups.Size = new System.Drawing.Size(138, 48);
            // 
            // checkAllToolStripMenuItem
            // 
            this.checkAllToolStripMenuItem.Name = "checkAllToolStripMenuItem";
            this.checkAllToolStripMenuItem.Size = new System.Drawing.Size(137, 22);
            this.checkAllToolStripMenuItem.Text = "Check All";
            this.checkAllToolStripMenuItem.Click += new System.EventHandler(this.checkAllToolStripMenuItem_Click);
            // 
            // uncheckAllToolStripMenuItem
            // 
            this.uncheckAllToolStripMenuItem.Name = "uncheckAllToolStripMenuItem";
            this.uncheckAllToolStripMenuItem.Size = new System.Drawing.Size(137, 22);
            this.uncheckAllToolStripMenuItem.Text = "Uncheck All";
            this.uncheckAllToolStripMenuItem.Click += new System.EventHandler(this.uncheckAllToolStripMenuItem_Click);
            // 
            // tabControl
            // 
            this.tabControl.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.tabControl.Controls.Add(this.tabPageDisableSids);
            this.tabControl.Controls.Add(this.tabPageDeletePrivs);
            this.tabControl.Controls.Add(this.tabPageRestrictedSids);
            this.tabControl.Controls.Add(this.tabPageAppContainer);
            this.tabControl.Location = new System.Drawing.Point(1, 32);
            this.tabControl.Name = "tabControl";
            this.tabControl.SelectedIndex = 0;
            this.tabControl.Size = new System.Drawing.Size(694, 468);
            this.tabControl.TabIndex = 0;
            // 
            // tabPageDeletePrivs
            // 
            this.tabPageDeletePrivs.Controls.Add(this.checkBoxDisableMaxPrivs);
            this.tabPageDeletePrivs.Controls.Add(this.listViewDeletePrivs);
            this.tabPageDeletePrivs.Location = new System.Drawing.Point(4, 22);
            this.tabPageDeletePrivs.Name = "tabPageDeletePrivs";
            this.tabPageDeletePrivs.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageDeletePrivs.Size = new System.Drawing.Size(661, 442);
            this.tabPageDeletePrivs.TabIndex = 1;
            this.tabPageDeletePrivs.Text = "Delete Privileges";
            this.tabPageDeletePrivs.UseVisualStyleBackColor = true;
            // 
            // checkBoxDisableMaxPrivs
            // 
            this.checkBoxDisableMaxPrivs.AutoSize = true;
            this.checkBoxDisableMaxPrivs.Location = new System.Drawing.Point(6, 6);
            this.checkBoxDisableMaxPrivs.Name = "checkBoxDisableMaxPrivs";
            this.checkBoxDisableMaxPrivs.Size = new System.Drawing.Size(156, 17);
            this.checkBoxDisableMaxPrivs.TabIndex = 1;
            this.checkBoxDisableMaxPrivs.Text = "Disable Maximum Privileges";
            this.checkBoxDisableMaxPrivs.UseVisualStyleBackColor = true;
            // 
            // listViewDeletePrivs
            // 
            this.listViewDeletePrivs.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.listViewDeletePrivs.CheckBoxes = true;
            this.listViewDeletePrivs.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeaderPrivilege,
            columnHeaderDisplayName});
            this.listViewDeletePrivs.ContextMenuStrip = this.contextMenuStripPrivs;
            this.listViewDeletePrivs.FullRowSelect = true;
            this.listViewDeletePrivs.Location = new System.Drawing.Point(0, 26);
            this.listViewDeletePrivs.MultiSelect = false;
            this.listViewDeletePrivs.Name = "listViewDeletePrivs";
            this.listViewDeletePrivs.Size = new System.Drawing.Size(683, 416);
            this.listViewDeletePrivs.TabIndex = 0;
            this.listViewDeletePrivs.UseCompatibleStateImageBehavior = false;
            this.listViewDeletePrivs.View = System.Windows.Forms.View.Details;
            // 
            // contextMenuStripPrivs
            // 
            this.contextMenuStripPrivs.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripMenuItemCheckAllPrivs,
            this.toolStripMenuItemUncheckAllPrivs});
            this.contextMenuStripPrivs.Name = "contextMenuStripGroupsPrivs";
            this.contextMenuStripPrivs.Size = new System.Drawing.Size(138, 48);
            // 
            // toolStripMenuItemCheckAllPrivs
            // 
            this.toolStripMenuItemCheckAllPrivs.Name = "toolStripMenuItemCheckAllPrivs";
            this.toolStripMenuItemCheckAllPrivs.Size = new System.Drawing.Size(137, 22);
            this.toolStripMenuItemCheckAllPrivs.Text = "Check All";
            this.toolStripMenuItemCheckAllPrivs.Click += new System.EventHandler(this.toolStripMenuItemCheckAllPrivs_Click);
            // 
            // toolStripMenuItemUncheckAllPrivs
            // 
            this.toolStripMenuItemUncheckAllPrivs.Name = "toolStripMenuItemUncheckAllPrivs";
            this.toolStripMenuItemUncheckAllPrivs.Size = new System.Drawing.Size(137, 22);
            this.toolStripMenuItemUncheckAllPrivs.Text = "Uncheck All";
            this.toolStripMenuItemUncheckAllPrivs.Click += new System.EventHandler(this.toolStripMenuItemUncheckAllPrivs_Click);
            // 
            // tabPageRestrictedSids
            // 
            this.tabPageRestrictedSids.Controls.Add(this.btnAddAllGroups);
            this.tabPageRestrictedSids.Controls.Add(this.listViewRestrictedSids);
            this.tabPageRestrictedSids.Location = new System.Drawing.Point(4, 22);
            this.tabPageRestrictedSids.Name = "tabPageRestrictedSids";
            this.tabPageRestrictedSids.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageRestrictedSids.Size = new System.Drawing.Size(661, 442);
            this.tabPageRestrictedSids.TabIndex = 2;
            this.tabPageRestrictedSids.Text = "Restricted SIDs";
            this.tabPageRestrictedSids.UseVisualStyleBackColor = true;
            // 
            // btnAddAllGroups
            // 
            this.btnAddAllGroups.Location = new System.Drawing.Point(6, 6);
            this.btnAddAllGroups.Name = "btnAddAllGroups";
            this.btnAddAllGroups.Size = new System.Drawing.Size(107, 23);
            this.btnAddAllGroups.TabIndex = 2;
            this.btnAddAllGroups.Text = "Add All Group SIDs";
            this.btnAddAllGroups.UseVisualStyleBackColor = true;
            this.btnAddAllGroups.Click += new System.EventHandler(this.btnAddAllGroups_Click);
            // 
            // listViewRestrictedSids
            // 
            this.listViewRestrictedSids.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.listViewRestrictedSids.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeader1,
            columnHeader2});
            this.listViewRestrictedSids.ContextMenuStrip = this.contextMenuStripRestrictedSids;
            this.listViewRestrictedSids.FullRowSelect = true;
            this.listViewRestrictedSids.Location = new System.Drawing.Point(3, 34);
            this.listViewRestrictedSids.Name = "listViewRestrictedSids";
            this.listViewRestrictedSids.Size = new System.Drawing.Size(680, 402);
            this.listViewRestrictedSids.TabIndex = 1;
            this.listViewRestrictedSids.UseCompatibleStateImageBehavior = false;
            this.listViewRestrictedSids.View = System.Windows.Forms.View.Details;
            // 
            // contextMenuStripRestrictedSids
            // 
            this.contextMenuStripRestrictedSids.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.addSidToolStripMenuItem,
            this.deleteSidToolStripMenuItem,
            this.selectAllToolStripMenuItem});
            this.contextMenuStripRestrictedSids.Name = "contextMenuStripRestrictedSids";
            this.contextMenuStripRestrictedSids.Size = new System.Drawing.Size(165, 70);
            // 
            // addSidToolStripMenuItem
            // 
            this.addSidToolStripMenuItem.Name = "addSidToolStripMenuItem";
            this.addSidToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.Insert;
            this.addSidToolStripMenuItem.Size = new System.Drawing.Size(164, 22);
            this.addSidToolStripMenuItem.Text = "Add Sid";
            this.addSidToolStripMenuItem.Click += new System.EventHandler(this.addSidToolStripMenuItem_Click);
            // 
            // deleteSidToolStripMenuItem
            // 
            this.deleteSidToolStripMenuItem.Name = "deleteSidToolStripMenuItem";
            this.deleteSidToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.Delete;
            this.deleteSidToolStripMenuItem.Size = new System.Drawing.Size(164, 22);
            this.deleteSidToolStripMenuItem.Text = "Delete Sid";
            this.deleteSidToolStripMenuItem.Click += new System.EventHandler(this.deleteSidToolStripMenuItem_Click);
            // 
            // selectAllToolStripMenuItem
            // 
            this.selectAllToolStripMenuItem.Name = "selectAllToolStripMenuItem";
            this.selectAllToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.A)));
            this.selectAllToolStripMenuItem.Size = new System.Drawing.Size(164, 22);
            this.selectAllToolStripMenuItem.Text = "Select All";
            this.selectAllToolStripMenuItem.Click += new System.EventHandler(this.selectAllToolStripMenuItem_Click);
            // 
            // btnCreate
            // 
            this.btnCreate.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.btnCreate.Location = new System.Drawing.Point(172, 506);
            this.btnCreate.Name = "btnCreate";
            this.btnCreate.Size = new System.Drawing.Size(75, 23);
            this.btnCreate.TabIndex = 1;
            this.btnCreate.Text = "Create";
            this.btnCreate.UseVisualStyleBackColor = true;
            this.btnCreate.Click += new System.EventHandler(this.btnCreate_Click);
            // 
            // btnCancel
            // 
            this.btnCancel.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.btnCancel.Location = new System.Drawing.Point(410, 506);
            this.btnCancel.Name = "btnCancel";
            this.btnCancel.Size = new System.Drawing.Size(75, 23);
            this.btnCancel.TabIndex = 2;
            this.btnCancel.Text = "Cancel";
            this.btnCancel.UseVisualStyleBackColor = true;
            // 
            // btnCreateNew
            // 
            this.btnCreateNew.Location = new System.Drawing.Point(290, 506);
            this.btnCreateNew.Name = "btnCreateNew";
            this.btnCreateNew.Size = new System.Drawing.Size(75, 23);
            this.btnCreateNew.TabIndex = 3;
            this.btnCreateNew.Text = "Create New";
            this.btnCreateNew.UseVisualStyleBackColor = true;
            this.btnCreateNew.Click += new System.EventHandler(this.btnCreateNew_Click);
            // 
            // comboBoxSandboxType
            // 
            this.comboBoxSandboxType.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBoxSandboxType.FormattingEnabled = true;
            this.comboBoxSandboxType.Location = new System.Drawing.Point(97, 5);
            this.comboBoxSandboxType.Name = "comboBoxSandboxType";
            this.comboBoxSandboxType.Size = new System.Drawing.Size(223, 21);
            this.comboBoxSandboxType.TabIndex = 4;
            this.comboBoxSandboxType.SelectedIndexChanged += new System.EventHandler(this.comboBoxSandboxType_SelectedIndexChanged);
            // 
            // tabPageAppContainer
            // 
            this.tabPageAppContainer.Controls.Add(this.listViewCapabilities);
            this.tabPageAppContainer.Controls.Add(this.lblCapabilities);
            this.tabPageAppContainer.Controls.Add(this.textBoxPackageSid);
            this.tabPageAppContainer.Controls.Add(lblPackageSid);
            this.tabPageAppContainer.Location = new System.Drawing.Point(4, 22);
            this.tabPageAppContainer.Name = "tabPageAppContainer";
            this.tabPageAppContainer.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageAppContainer.Size = new System.Drawing.Size(686, 442);
            this.tabPageAppContainer.TabIndex = 3;
            this.tabPageAppContainer.Text = "AppContainer";
            this.tabPageAppContainer.UseVisualStyleBackColor = true;
            // 
            // lblPackageSid
            // 
            lblPackageSid.AutoSize = true;
            lblPackageSid.Location = new System.Drawing.Point(7, 9);
            lblPackageSid.Name = "lblPackageSid";
            lblPackageSid.Size = new System.Drawing.Size(104, 13);
            lblPackageSid.TabIndex = 0;
            lblPackageSid.Text = "Package Sid/Name:";
            // 
            // textBoxPackageSid
            // 
            this.textBoxPackageSid.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.textBoxPackageSid.Location = new System.Drawing.Point(117, 6);
            this.textBoxPackageSid.Name = "textBoxPackageSid";
            this.textBoxPackageSid.Size = new System.Drawing.Size(563, 20);
            this.textBoxPackageSid.TabIndex = 1;
            // 
            // lblCapabilities
            // 
            this.lblCapabilities.AutoSize = true;
            this.lblCapabilities.Location = new System.Drawing.Point(7, 37);
            this.lblCapabilities.Name = "lblCapabilities";
            this.lblCapabilities.Size = new System.Drawing.Size(63, 13);
            this.lblCapabilities.TabIndex = 3;
            this.lblCapabilities.Text = "Capabilities:";
            // 
            // listViewCapabilities
            // 
            this.listViewCapabilities.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.listViewCapabilities.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeader3,
            columnHeader4});
            this.listViewCapabilities.ContextMenuStrip = this.contextMenuStripRestrictedSids;
            this.listViewCapabilities.FullRowSelect = true;
            this.listViewCapabilities.Location = new System.Drawing.Point(3, 55);
            this.listViewCapabilities.Name = "listViewCapabilities";
            this.listViewCapabilities.Size = new System.Drawing.Size(705, 379);
            this.listViewCapabilities.TabIndex = 4;
            this.listViewCapabilities.UseCompatibleStateImageBehavior = false;
            this.listViewCapabilities.View = System.Windows.Forms.View.Details;
            // 
            // columnHeader3
            // 
            columnHeader3.Text = "Name";
            columnHeader3.Width = 131;
            // 
            // columnHeader4
            // 
            columnHeader4.Text = "Sid";
            columnHeader4.Width = 235;
            // 
            // CreateSandboxTokenForm
            // 
            this.AcceptButton = this.btnCreate;
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.CancelButton = this.btnCancel;
            this.ClientSize = new System.Drawing.Size(697, 532);
            this.Controls.Add(lblSandboxType);
            this.Controls.Add(this.comboBoxSandboxType);
            this.Controls.Add(this.tabControl);
            this.Controls.Add(this.btnCreateNew);
            this.Controls.Add(this.btnCancel);
            this.Controls.Add(this.btnCreate);
            this.Name = "CreateSandboxTokenForm";
            this.Text = "Create Restricted Token";
            this.tabPageDisableSids.ResumeLayout(false);
            this.tabPageDisableSids.PerformLayout();
            this.contextMenuStripGroups.ResumeLayout(false);
            this.tabControl.ResumeLayout(false);
            this.tabPageDeletePrivs.ResumeLayout(false);
            this.tabPageDeletePrivs.PerformLayout();
            this.contextMenuStripPrivs.ResumeLayout(false);
            this.tabPageRestrictedSids.ResumeLayout(false);
            this.contextMenuStripRestrictedSids.ResumeLayout(false);
            this.tabPageAppContainer.ResumeLayout(false);
            this.tabPageAppContainer.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TabControl tabControl;
        private System.Windows.Forms.TabPage tabPageDeletePrivs;
        private System.Windows.Forms.Button btnCreate;
        private System.Windows.Forms.Button btnCancel;
        private System.Windows.Forms.ListView listViewDisableSids;
        private System.Windows.Forms.ListView listViewDeletePrivs;
        private System.Windows.Forms.CheckBox checkBoxDisableMaxPrivs;
        private System.Windows.Forms.TabPage tabPageRestrictedSids;
        private System.Windows.Forms.ListView listViewRestrictedSids;
        private System.Windows.Forms.Button btnAddAllGroups;
        private System.Windows.Forms.CheckBox checkBoxWriteRestricted;
        private System.Windows.Forms.CheckBox checkBoxSandboxInert;
        private System.Windows.Forms.CheckBox checkBoxMakeLuaToken;
        private System.Windows.Forms.ContextMenuStrip contextMenuStripGroups;
        private System.Windows.Forms.ToolStripMenuItem checkAllToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem uncheckAllToolStripMenuItem;
        private System.Windows.Forms.ContextMenuStrip contextMenuStripPrivs;
        private System.Windows.Forms.ToolStripMenuItem toolStripMenuItemCheckAllPrivs;
        private System.Windows.Forms.ToolStripMenuItem toolStripMenuItemUncheckAllPrivs;
        private System.Windows.Forms.ContextMenuStrip contextMenuStripRestrictedSids;
        private System.Windows.Forms.ToolStripMenuItem addSidToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem deleteSidToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem selectAllToolStripMenuItem;
        private System.Windows.Forms.Button btnCreateNew;
        private System.Windows.Forms.ComboBox comboBoxSandboxType;
        private System.Windows.Forms.TabPage tabPageDisableSids;
        private System.Windows.Forms.TabPage tabPageAppContainer;
        private System.Windows.Forms.TextBox textBoxPackageSid;
        private System.Windows.Forms.Label lblCapabilities;
        private System.Windows.Forms.ListView listViewCapabilities;
    }
}