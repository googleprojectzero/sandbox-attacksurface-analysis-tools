namespace TokenViewer
{
    partial class TokenForm
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
            System.Windows.Forms.TabPage tabPageMain;
            System.Windows.Forms.Label label7;
            System.Windows.Forms.Label label6;
            System.Windows.Forms.GroupBox groupBoxToken;
            System.Windows.Forms.Label label25;
            System.Windows.Forms.Label label13;
            System.Windows.Forms.Label label8;
            System.Windows.Forms.Label label5;
            System.Windows.Forms.Label lblTokenType;
            System.Windows.Forms.Label label4;
            System.Windows.Forms.Label lblImpLevel;
            System.Windows.Forms.Label label3;
            System.Windows.Forms.Label label1;
            System.Windows.Forms.Label label2;
            System.Windows.Forms.TabPage tabPageGroups;
            System.Windows.Forms.ColumnHeader columnHeaderName;
            System.Windows.Forms.ColumnHeader columnHeaderFlags;
            System.Windows.Forms.TabPage tabPageDefaultDacl;
            System.Windows.Forms.ColumnHeader columnHeaderGroup;
            System.Windows.Forms.ColumnHeader columnHeaderAccess;
            System.Windows.Forms.ColumnHeader columnHeaderDaclFlags;
            System.Windows.Forms.ColumnHeader columnHeaderDaclType;
            System.Windows.Forms.Label label10;
            System.Windows.Forms.Label label9;
            System.Windows.Forms.Label label11;
            System.Windows.Forms.Label label12;
            System.Windows.Forms.GroupBox groupBoxDuplicate;
            System.Windows.Forms.Label lblILForDup;
            System.Windows.Forms.Label label15;
            System.Windows.Forms.Label label14;
            System.Windows.Forms.GroupBox groupBox1;
            System.Windows.Forms.Label label16;
            System.Windows.Forms.GroupBox groupBox2;
            System.Windows.Forms.Label label26;
            System.Windows.Forms.Label label22;
            System.Windows.Forms.Label label20;
            System.Windows.Forms.Label label19;
            System.Windows.Forms.Label label18;
            System.Windows.Forms.Label label17;
            System.Windows.Forms.GroupBox groupBoxSafer;
            System.Windows.Forms.Label label21;
            System.Windows.Forms.GroupBox groupBox4;
            System.Windows.Forms.Label label24;
            System.Windows.Forms.Label label23;
            System.Windows.Forms.ColumnHeader columnHeader5;
            System.Windows.Forms.ColumnHeader columnHeader6;
            System.Windows.Forms.Label label27;
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(TokenForm));
            this.groupBoxSource = new System.Windows.Forms.GroupBox();
            this.txtSourceId = new System.Windows.Forms.TextBox();
            this.txtSourceName = new System.Windows.Forms.TextBox();
            this.txtIsElevated = new System.Windows.Forms.TextBox();
            this.btnSetIL = new System.Windows.Forms.Button();
            this.comboBoxIL = new System.Windows.Forms.ComboBox();
            this.txtOriginLoginId = new System.Windows.Forms.TextBox();
            this.btnLinkedToken = new System.Windows.Forms.Button();
            this.txtElevationType = new System.Windows.Forms.TextBox();
            this.lblUsername = new System.Windows.Forms.Label();
            this.txtSessionId = new System.Windows.Forms.TextBox();
            this.txtUsername = new System.Windows.Forms.TextBox();
            this.lblUserSid = new System.Windows.Forms.Label();
            this.txtUserSid = new System.Windows.Forms.TextBox();
            this.txtTokenType = new System.Windows.Forms.TextBox();
            this.txtModifiedId = new System.Windows.Forms.TextBox();
            this.txtImpLevel = new System.Windows.Forms.TextBox();
            this.txtAuthId = new System.Windows.Forms.TextBox();
            this.txtTokenId = new System.Windows.Forms.TextBox();
            this.btnPermissions = new System.Windows.Forms.Button();
            this.listViewGroups = new System.Windows.Forms.ListView();
            this.contextMenuStripGroups = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.enableGroupToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.selectAllGroupsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.listViewDefDacl = new System.Windows.Forms.ListView();
            this.txtPrimaryGroup = new System.Windows.Forms.TextBox();
            this.txtOwner = new System.Windows.Forms.TextBox();
            this.btnImpersonate = new System.Windows.Forms.Button();
            this.comboBoxILForDup = new System.Windows.Forms.ComboBox();
            this.btnDuplicate = new System.Windows.Forms.Button();
            this.comboBoxImpLevel = new System.Windows.Forms.ComboBox();
            this.comboBoxTokenType = new System.Windows.Forms.ComboBox();
            this.checkBoxUseNetLogon = new System.Windows.Forms.CheckBox();
            this.checkBoxUseWmi = new System.Windows.Forms.CheckBox();
            this.checkBoxMakeInteractive = new System.Windows.Forms.CheckBox();
            this.btnCreateProcess = new System.Windows.Forms.Button();
            this.txtCommandLine = new System.Windows.Forms.TextBox();
            this.btnToggleVirtualizationEnabled = new System.Windows.Forms.Button();
            this.txtHandleAccess = new System.Windows.Forms.TextBox();
            this.btnToggleUIAccess = new System.Windows.Forms.Button();
            this.treeViewSecurityAttributes = new System.Windows.Forms.TreeView();
            this.llbSecurityAttributes = new System.Windows.Forms.Label();
            this.txtMandatoryILPolicy = new System.Windows.Forms.TextBox();
            this.txtVirtualizationEnabled = new System.Windows.Forms.TextBox();
            this.txtVirtualizationAllowed = new System.Windows.Forms.TextBox();
            this.txtSandboxInert = new System.Windows.Forms.TextBox();
            this.txtUIAccess = new System.Windows.Forms.TextBox();
            this.btnCreateSandbox = new System.Windows.Forms.Button();
            this.comboBoxSaferLevel = new System.Windows.Forms.ComboBox();
            this.checkBoxSaferMakeInert = new System.Windows.Forms.CheckBox();
            this.btnComputeSafer = new System.Windows.Forms.Button();
            this.btnCreate = new System.Windows.Forms.Button();
            this.btnBrowse = new System.Windows.Forms.Button();
            this.txtFileContents = new System.Windows.Forms.TextBox();
            this.txtFilePath = new System.Windows.Forms.TextBox();
            this.tabControlMain = new System.Windows.Forms.TabControl();
            this.tabPagePrivs = new System.Windows.Forms.TabPage();
            this.listViewPrivs = new System.Windows.Forms.ListView();
            this.contextMenuStripPrivileges = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.enablePrivilegeToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.removePrivilegeToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.selectAllPrivsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.tabPageRestricted = new System.Windows.Forms.TabPage();
            this.listViewRestrictedSids = new System.Windows.Forms.ListView();
            this.columnHeader1 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader2 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.tabPageAppContainer = new System.Windows.Forms.TabPage();
            this.txtACNumber = new System.Windows.Forms.TextBox();
            this.listViewCapabilities = new System.Windows.Forms.ListView();
            this.columnHeader3 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader4 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.txtPackageName = new System.Windows.Forms.TextBox();
            this.tabPageMisc = new System.Windows.Forms.TabPage();
            this.tabPageOperations = new System.Windows.Forms.TabPage();
            this.toolTip = new System.Windows.Forms.ToolTip(this.components);
            this.txtPackageSid = new System.Windows.Forms.TextBox();
            tabPageMain = new System.Windows.Forms.TabPage();
            label7 = new System.Windows.Forms.Label();
            label6 = new System.Windows.Forms.Label();
            groupBoxToken = new System.Windows.Forms.GroupBox();
            label25 = new System.Windows.Forms.Label();
            label13 = new System.Windows.Forms.Label();
            label8 = new System.Windows.Forms.Label();
            label5 = new System.Windows.Forms.Label();
            lblTokenType = new System.Windows.Forms.Label();
            label4 = new System.Windows.Forms.Label();
            lblImpLevel = new System.Windows.Forms.Label();
            label3 = new System.Windows.Forms.Label();
            label1 = new System.Windows.Forms.Label();
            label2 = new System.Windows.Forms.Label();
            tabPageGroups = new System.Windows.Forms.TabPage();
            columnHeaderName = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderFlags = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            tabPageDefaultDacl = new System.Windows.Forms.TabPage();
            columnHeaderGroup = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderAccess = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderDaclFlags = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderDaclType = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            label10 = new System.Windows.Forms.Label();
            label9 = new System.Windows.Forms.Label();
            label11 = new System.Windows.Forms.Label();
            label12 = new System.Windows.Forms.Label();
            groupBoxDuplicate = new System.Windows.Forms.GroupBox();
            lblILForDup = new System.Windows.Forms.Label();
            label15 = new System.Windows.Forms.Label();
            label14 = new System.Windows.Forms.Label();
            groupBox1 = new System.Windows.Forms.GroupBox();
            label16 = new System.Windows.Forms.Label();
            groupBox2 = new System.Windows.Forms.GroupBox();
            label26 = new System.Windows.Forms.Label();
            label22 = new System.Windows.Forms.Label();
            label20 = new System.Windows.Forms.Label();
            label19 = new System.Windows.Forms.Label();
            label18 = new System.Windows.Forms.Label();
            label17 = new System.Windows.Forms.Label();
            groupBoxSafer = new System.Windows.Forms.GroupBox();
            label21 = new System.Windows.Forms.Label();
            groupBox4 = new System.Windows.Forms.GroupBox();
            label24 = new System.Windows.Forms.Label();
            label23 = new System.Windows.Forms.Label();
            columnHeader5 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeader6 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            label27 = new System.Windows.Forms.Label();
            tabPageMain.SuspendLayout();
            this.groupBoxSource.SuspendLayout();
            groupBoxToken.SuspendLayout();
            tabPageGroups.SuspendLayout();
            this.contextMenuStripGroups.SuspendLayout();
            tabPageDefaultDacl.SuspendLayout();
            groupBoxDuplicate.SuspendLayout();
            groupBox1.SuspendLayout();
            groupBox2.SuspendLayout();
            groupBoxSafer.SuspendLayout();
            groupBox4.SuspendLayout();
            this.tabControlMain.SuspendLayout();
            this.tabPagePrivs.SuspendLayout();
            this.contextMenuStripPrivileges.SuspendLayout();
            this.tabPageRestricted.SuspendLayout();
            this.tabPageAppContainer.SuspendLayout();
            this.tabPageMisc.SuspendLayout();
            this.tabPageOperations.SuspendLayout();
            this.SuspendLayout();
            // 
            // tabPageMain
            // 
            tabPageMain.Controls.Add(this.groupBoxSource);
            tabPageMain.Controls.Add(groupBoxToken);
            tabPageMain.Controls.Add(this.btnPermissions);
            tabPageMain.Location = new System.Drawing.Point(4, 25);
            tabPageMain.Margin = new System.Windows.Forms.Padding(4);
            tabPageMain.Name = "tabPageMain";
            tabPageMain.Padding = new System.Windows.Forms.Padding(4);
            tabPageMain.Size = new System.Drawing.Size(625, 565);
            tabPageMain.TabIndex = 0;
            tabPageMain.Text = "Main Details";
            tabPageMain.UseVisualStyleBackColor = true;
            // 
            // groupBoxSource
            // 
            this.groupBoxSource.Controls.Add(this.txtSourceId);
            this.groupBoxSource.Controls.Add(label7);
            this.groupBoxSource.Controls.Add(this.txtSourceName);
            this.groupBoxSource.Controls.Add(label6);
            this.groupBoxSource.Location = new System.Drawing.Point(8, 426);
            this.groupBoxSource.Margin = new System.Windows.Forms.Padding(4);
            this.groupBoxSource.Name = "groupBoxSource";
            this.groupBoxSource.Padding = new System.Windows.Forms.Padding(4);
            this.groupBoxSource.Size = new System.Drawing.Size(604, 94);
            this.groupBoxSource.TabIndex = 20;
            this.groupBoxSource.TabStop = false;
            this.groupBoxSource.Text = "Source";
            // 
            // txtSourceId
            // 
            this.txtSourceId.Location = new System.Drawing.Point(153, 55);
            this.txtSourceId.Margin = new System.Windows.Forms.Padding(4);
            this.txtSourceId.Name = "txtSourceId";
            this.txtSourceId.ReadOnly = true;
            this.txtSourceId.Size = new System.Drawing.Size(188, 22);
            this.txtSourceId.TabIndex = 22;
            // 
            // label7
            // 
            label7.AutoSize = true;
            label7.Location = new System.Drawing.Point(11, 59);
            label7.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label7.Name = "label7";
            label7.Size = new System.Drawing.Size(23, 17);
            label7.TabIndex = 21;
            label7.Text = "Id:";
            // 
            // txtSourceName
            // 
            this.txtSourceName.Location = new System.Drawing.Point(153, 23);
            this.txtSourceName.Margin = new System.Windows.Forms.Padding(4);
            this.txtSourceName.Name = "txtSourceName";
            this.txtSourceName.ReadOnly = true;
            this.txtSourceName.Size = new System.Drawing.Size(188, 22);
            this.txtSourceName.TabIndex = 20;
            // 
            // label6
            // 
            label6.AutoSize = true;
            label6.Location = new System.Drawing.Point(11, 27);
            label6.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label6.Name = "label6";
            label6.Size = new System.Drawing.Size(49, 17);
            label6.TabIndex = 19;
            label6.Text = "Name:";
            // 
            // groupBoxToken
            // 
            groupBoxToken.Controls.Add(this.txtIsElevated);
            groupBoxToken.Controls.Add(label25);
            groupBoxToken.Controls.Add(this.btnSetIL);
            groupBoxToken.Controls.Add(this.comboBoxIL);
            groupBoxToken.Controls.Add(this.txtOriginLoginId);
            groupBoxToken.Controls.Add(label13);
            groupBoxToken.Controls.Add(this.btnLinkedToken);
            groupBoxToken.Controls.Add(this.txtElevationType);
            groupBoxToken.Controls.Add(label8);
            groupBoxToken.Controls.Add(this.lblUsername);
            groupBoxToken.Controls.Add(this.txtSessionId);
            groupBoxToken.Controls.Add(this.txtUsername);
            groupBoxToken.Controls.Add(label5);
            groupBoxToken.Controls.Add(this.lblUserSid);
            groupBoxToken.Controls.Add(this.txtUserSid);
            groupBoxToken.Controls.Add(lblTokenType);
            groupBoxToken.Controls.Add(label4);
            groupBoxToken.Controls.Add(this.txtTokenType);
            groupBoxToken.Controls.Add(this.txtModifiedId);
            groupBoxToken.Controls.Add(lblImpLevel);
            groupBoxToken.Controls.Add(label3);
            groupBoxToken.Controls.Add(this.txtImpLevel);
            groupBoxToken.Controls.Add(this.txtAuthId);
            groupBoxToken.Controls.Add(label1);
            groupBoxToken.Controls.Add(label2);
            groupBoxToken.Controls.Add(this.txtTokenId);
            groupBoxToken.Location = new System.Drawing.Point(8, 7);
            groupBoxToken.Margin = new System.Windows.Forms.Padding(4);
            groupBoxToken.Name = "groupBoxToken";
            groupBoxToken.Padding = new System.Windows.Forms.Padding(4);
            groupBoxToken.Size = new System.Drawing.Size(604, 410);
            groupBoxToken.TabIndex = 19;
            groupBoxToken.TabStop = false;
            groupBoxToken.Text = "Token";
            // 
            // txtIsElevated
            // 
            this.txtIsElevated.Location = new System.Drawing.Point(153, 373);
            this.txtIsElevated.Margin = new System.Windows.Forms.Padding(4);
            this.txtIsElevated.Name = "txtIsElevated";
            this.txtIsElevated.ReadOnly = true;
            this.txtIsElevated.Size = new System.Drawing.Size(188, 22);
            this.txtIsElevated.TabIndex = 27;
            // 
            // label25
            // 
            label25.AutoSize = true;
            label25.Location = new System.Drawing.Point(11, 377);
            label25.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label25.Name = "label25";
            label25.Size = new System.Drawing.Size(81, 17);
            label25.TabIndex = 26;
            label25.Text = "Is Elevated:";
            // 
            // btnSetIL
            // 
            this.btnSetIL.Enabled = false;
            this.btnSetIL.Location = new System.Drawing.Point(384, 273);
            this.btnSetIL.Margin = new System.Windows.Forms.Padding(4);
            this.btnSetIL.Name = "btnSetIL";
            this.btnSetIL.Size = new System.Drawing.Size(135, 28);
            this.btnSetIL.TabIndex = 25;
            this.btnSetIL.Text = "Set Integrity Level";
            this.btnSetIL.UseVisualStyleBackColor = true;
            this.btnSetIL.Click += new System.EventHandler(this.btnSetIL_Click);
            // 
            // comboBoxIL
            // 
            this.comboBoxIL.FormattingEnabled = true;
            this.comboBoxIL.Location = new System.Drawing.Point(153, 276);
            this.comboBoxIL.Margin = new System.Windows.Forms.Padding(4);
            this.comboBoxIL.Name = "comboBoxIL";
            this.comboBoxIL.Size = new System.Drawing.Size(188, 24);
            this.comboBoxIL.TabIndex = 24;
            this.comboBoxIL.SelectedIndexChanged += new System.EventHandler(this.comboBoxIL_SelectedIndexChanged);
            this.comboBoxIL.TextUpdate += new System.EventHandler(this.comboBoxIL_TextUpdate);
            // 
            // txtOriginLoginId
            // 
            this.txtOriginLoginId.Location = new System.Drawing.Point(153, 210);
            this.txtOriginLoginId.Margin = new System.Windows.Forms.Padding(4);
            this.txtOriginLoginId.Name = "txtOriginLoginId";
            this.txtOriginLoginId.ReadOnly = true;
            this.txtOriginLoginId.Size = new System.Drawing.Size(188, 22);
            this.txtOriginLoginId.TabIndex = 23;
            // 
            // label13
            // 
            label13.AutoSize = true;
            label13.Location = new System.Drawing.Point(11, 214);
            label13.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label13.Name = "label13";
            label13.Size = new System.Drawing.Size(106, 17);
            label13.TabIndex = 22;
            label13.Text = "Origin Login ID:";
            // 
            // btnLinkedToken
            // 
            this.btnLinkedToken.Location = new System.Drawing.Point(384, 338);
            this.btnLinkedToken.Margin = new System.Windows.Forms.Padding(4);
            this.btnLinkedToken.Name = "btnLinkedToken";
            this.btnLinkedToken.Size = new System.Drawing.Size(135, 28);
            this.btnLinkedToken.TabIndex = 21;
            this.btnLinkedToken.Text = "Linked Token";
            this.btnLinkedToken.UseVisualStyleBackColor = true;
            this.btnLinkedToken.Click += new System.EventHandler(this.btnLinkedToken_Click);
            // 
            // txtElevationType
            // 
            this.txtElevationType.Location = new System.Drawing.Point(153, 341);
            this.txtElevationType.Margin = new System.Windows.Forms.Padding(4);
            this.txtElevationType.Name = "txtElevationType";
            this.txtElevationType.ReadOnly = true;
            this.txtElevationType.Size = new System.Drawing.Size(188, 22);
            this.txtElevationType.TabIndex = 20;
            // 
            // label8
            // 
            label8.AutoSize = true;
            label8.Location = new System.Drawing.Point(11, 345);
            label8.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label8.Name = "label8";
            label8.Size = new System.Drawing.Size(106, 17);
            label8.TabIndex = 19;
            label8.Text = "Elevation Type:";
            // 
            // lblUsername
            // 
            this.lblUsername.AutoSize = true;
            this.lblUsername.Location = new System.Drawing.Point(8, 20);
            this.lblUsername.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblUsername.Name = "lblUsername";
            this.lblUsername.Size = new System.Drawing.Size(42, 17);
            this.lblUsername.TabIndex = 0;
            this.lblUsername.Text = "User:";
            // 
            // txtSessionId
            // 
            this.txtSessionId.Location = new System.Drawing.Point(153, 309);
            this.txtSessionId.Margin = new System.Windows.Forms.Padding(4);
            this.txtSessionId.Name = "txtSessionId";
            this.txtSessionId.ReadOnly = true;
            this.txtSessionId.Size = new System.Drawing.Size(188, 22);
            this.txtSessionId.TabIndex = 18;
            // 
            // txtUsername
            // 
            this.txtUsername.Location = new System.Drawing.Point(153, 20);
            this.txtUsername.Margin = new System.Windows.Forms.Padding(4);
            this.txtUsername.Name = "txtUsername";
            this.txtUsername.ReadOnly = true;
            this.txtUsername.Size = new System.Drawing.Size(355, 22);
            this.txtUsername.TabIndex = 1;
            // 
            // label5
            // 
            label5.AutoSize = true;
            label5.Location = new System.Drawing.Point(11, 313);
            label5.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label5.Name = "label5";
            label5.Size = new System.Drawing.Size(79, 17);
            label5.TabIndex = 17;
            label5.Text = "Session ID:";
            // 
            // lblUserSid
            // 
            this.lblUserSid.AutoSize = true;
            this.lblUserSid.Location = new System.Drawing.Point(8, 54);
            this.lblUserSid.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblUserSid.Name = "lblUserSid";
            this.lblUserSid.Size = new System.Drawing.Size(68, 17);
            this.lblUserSid.TabIndex = 2;
            this.lblUserSid.Text = "User SID:";
            // 
            // txtUserSid
            // 
            this.txtUserSid.Location = new System.Drawing.Point(153, 52);
            this.txtUserSid.Margin = new System.Windows.Forms.Padding(4);
            this.txtUserSid.Name = "txtUserSid";
            this.txtUserSid.ReadOnly = true;
            this.txtUserSid.Size = new System.Drawing.Size(355, 22);
            this.txtUserSid.TabIndex = 3;
            // 
            // lblTokenType
            // 
            lblTokenType.AutoSize = true;
            lblTokenType.Location = new System.Drawing.Point(11, 87);
            lblTokenType.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            lblTokenType.Name = "lblTokenType";
            lblTokenType.Size = new System.Drawing.Size(88, 17);
            lblTokenType.TabIndex = 4;
            lblTokenType.Text = "Token Type:";
            // 
            // label4
            // 
            label4.AutoSize = true;
            label4.Location = new System.Drawing.Point(11, 279);
            label4.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label4.Name = "label4";
            label4.Size = new System.Drawing.Size(100, 17);
            label4.TabIndex = 14;
            label4.Text = "Integrity Level:";
            // 
            // txtTokenType
            // 
            this.txtTokenType.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(128)))), ((int)(((byte)(255)))), ((int)(((byte)(128)))));
            this.txtTokenType.Location = new System.Drawing.Point(153, 84);
            this.txtTokenType.Margin = new System.Windows.Forms.Padding(4);
            this.txtTokenType.Name = "txtTokenType";
            this.txtTokenType.ReadOnly = true;
            this.txtTokenType.Size = new System.Drawing.Size(188, 22);
            this.txtTokenType.TabIndex = 5;
            // 
            // txtModifiedId
            // 
            this.txtModifiedId.Location = new System.Drawing.Point(153, 244);
            this.txtModifiedId.Margin = new System.Windows.Forms.Padding(4);
            this.txtModifiedId.Name = "txtModifiedId";
            this.txtModifiedId.ReadOnly = true;
            this.txtModifiedId.Size = new System.Drawing.Size(188, 22);
            this.txtModifiedId.TabIndex = 13;
            // 
            // lblImpLevel
            // 
            lblImpLevel.AutoSize = true;
            lblImpLevel.Location = new System.Drawing.Point(11, 118);
            lblImpLevel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            lblImpLevel.Name = "lblImpLevel";
            lblImpLevel.Size = new System.Drawing.Size(139, 17);
            lblImpLevel.TabIndex = 6;
            lblImpLevel.Text = "Impersonation Level:";
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new System.Drawing.Point(11, 247);
            label3.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label3.Name = "label3";
            label3.Size = new System.Drawing.Size(82, 17);
            label3.TabIndex = 12;
            label3.Text = "Modified ID:";
            // 
            // txtImpLevel
            // 
            this.txtImpLevel.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(192)))), ((int)(((byte)(128)))));
            this.txtImpLevel.Location = new System.Drawing.Point(153, 114);
            this.txtImpLevel.Margin = new System.Windows.Forms.Padding(4);
            this.txtImpLevel.Name = "txtImpLevel";
            this.txtImpLevel.ReadOnly = true;
            this.txtImpLevel.Size = new System.Drawing.Size(188, 22);
            this.txtImpLevel.TabIndex = 7;
            // 
            // txtAuthId
            // 
            this.txtAuthId.Location = new System.Drawing.Point(153, 178);
            this.txtAuthId.Margin = new System.Windows.Forms.Padding(4);
            this.txtAuthId.Name = "txtAuthId";
            this.txtAuthId.ReadOnly = true;
            this.txtAuthId.Size = new System.Drawing.Size(188, 22);
            this.txtAuthId.TabIndex = 11;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new System.Drawing.Point(11, 150);
            label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(69, 17);
            label1.TabIndex = 8;
            label1.Text = "Token ID:";
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new System.Drawing.Point(11, 182);
            label2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label2.Name = "label2";
            label2.Size = new System.Drawing.Size(119, 17);
            label2.TabIndex = 10;
            label2.Text = "Authentication ID:";
            // 
            // txtTokenId
            // 
            this.txtTokenId.Location = new System.Drawing.Point(153, 146);
            this.txtTokenId.Margin = new System.Windows.Forms.Padding(4);
            this.txtTokenId.Name = "txtTokenId";
            this.txtTokenId.ReadOnly = true;
            this.txtTokenId.Size = new System.Drawing.Size(188, 22);
            this.txtTokenId.TabIndex = 9;
            // 
            // btnPermissions
            // 
            this.btnPermissions.Location = new System.Drawing.Point(4, 527);
            this.btnPermissions.Margin = new System.Windows.Forms.Padding(4);
            this.btnPermissions.Name = "btnPermissions";
            this.btnPermissions.Size = new System.Drawing.Size(100, 28);
            this.btnPermissions.TabIndex = 16;
            this.btnPermissions.Text = "Permissions";
            this.btnPermissions.UseVisualStyleBackColor = true;
            this.btnPermissions.Click += new System.EventHandler(this.btnPermissions_Click);
            // 
            // tabPageGroups
            // 
            tabPageGroups.Controls.Add(this.listViewGroups);
            tabPageGroups.Location = new System.Drawing.Point(4, 25);
            tabPageGroups.Margin = new System.Windows.Forms.Padding(4);
            tabPageGroups.Name = "tabPageGroups";
            tabPageGroups.Padding = new System.Windows.Forms.Padding(4);
            tabPageGroups.Size = new System.Drawing.Size(625, 565);
            tabPageGroups.TabIndex = 1;
            tabPageGroups.Text = "Groups";
            tabPageGroups.UseVisualStyleBackColor = true;
            // 
            // listViewGroups
            // 
            this.listViewGroups.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeaderName,
            columnHeaderFlags});
            this.listViewGroups.ContextMenuStrip = this.contextMenuStripGroups;
            this.listViewGroups.Dock = System.Windows.Forms.DockStyle.Fill;
            this.listViewGroups.FullRowSelect = true;
            this.listViewGroups.Location = new System.Drawing.Point(4, 4);
            this.listViewGroups.Margin = new System.Windows.Forms.Padding(4);
            this.listViewGroups.Name = "listViewGroups";
            this.listViewGroups.Size = new System.Drawing.Size(617, 557);
            this.listViewGroups.TabIndex = 0;
            this.listViewGroups.UseCompatibleStateImageBehavior = false;
            this.listViewGroups.View = System.Windows.Forms.View.Details;
            this.listViewGroups.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.listView_ColumnClick);
            // 
            // columnHeaderName
            // 
            columnHeaderName.Text = "Name";
            columnHeaderName.Width = 210;
            // 
            // columnHeaderFlags
            // 
            columnHeaderFlags.Text = "Flags";
            columnHeaderFlags.Width = 194;
            // 
            // contextMenuStripGroups
            // 
            this.contextMenuStripGroups.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.contextMenuStripGroups.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.enableGroupToolStripMenuItem,
            this.selectAllGroupsToolStripMenuItem});
            this.contextMenuStripGroups.Name = "contextMenuStripGroups";
            this.contextMenuStripGroups.Size = new System.Drawing.Size(193, 52);
            this.contextMenuStripGroups.Opening += new System.ComponentModel.CancelEventHandler(this.contextMenuStripGroups_Opening);
            // 
            // enableGroupToolStripMenuItem
            // 
            this.enableGroupToolStripMenuItem.Name = "enableGroupToolStripMenuItem";
            this.enableGroupToolStripMenuItem.Size = new System.Drawing.Size(192, 24);
            this.enableGroupToolStripMenuItem.Text = "Enable Group";
            this.enableGroupToolStripMenuItem.Click += new System.EventHandler(this.enableGroupToolStripMenuItem_Click);
            // 
            // selectAllGroupsToolStripMenuItem
            // 
            this.selectAllGroupsToolStripMenuItem.Name = "selectAllGroupsToolStripMenuItem";
            this.selectAllGroupsToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.A)));
            this.selectAllGroupsToolStripMenuItem.Size = new System.Drawing.Size(192, 24);
            this.selectAllGroupsToolStripMenuItem.Text = "Select All";
            this.selectAllGroupsToolStripMenuItem.Click += new System.EventHandler(this.selectAllGroupsToolStripMenuItem_Click);
            // 
            // tabPageDefaultDacl
            // 
            tabPageDefaultDacl.Controls.Add(this.listViewDefDacl);
            tabPageDefaultDacl.Controls.Add(label10);
            tabPageDefaultDacl.Controls.Add(this.txtPrimaryGroup);
            tabPageDefaultDacl.Controls.Add(label9);
            tabPageDefaultDacl.Controls.Add(this.txtOwner);
            tabPageDefaultDacl.Location = new System.Drawing.Point(4, 25);
            tabPageDefaultDacl.Margin = new System.Windows.Forms.Padding(4);
            tabPageDefaultDacl.Name = "tabPageDefaultDacl";
            tabPageDefaultDacl.Padding = new System.Windows.Forms.Padding(4);
            tabPageDefaultDacl.Size = new System.Drawing.Size(625, 565);
            tabPageDefaultDacl.TabIndex = 2;
            tabPageDefaultDacl.Text = "Default Dacl";
            tabPageDefaultDacl.UseVisualStyleBackColor = true;
            // 
            // listViewDefDacl
            // 
            this.listViewDefDacl.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.listViewDefDacl.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeaderGroup,
            columnHeaderAccess,
            columnHeaderDaclFlags,
            columnHeaderDaclType});
            this.listViewDefDacl.FullRowSelect = true;
            this.listViewDefDacl.Location = new System.Drawing.Point(4, 85);
            this.listViewDefDacl.Margin = new System.Windows.Forms.Padding(4);
            this.listViewDefDacl.Name = "listViewDefDacl";
            this.listViewDefDacl.Size = new System.Drawing.Size(613, 466);
            this.listViewDefDacl.TabIndex = 10;
            this.listViewDefDacl.UseCompatibleStateImageBehavior = false;
            this.listViewDefDacl.View = System.Windows.Forms.View.Details;
            // 
            // columnHeaderGroup
            // 
            columnHeaderGroup.Text = "Group";
            columnHeaderGroup.Width = 160;
            // 
            // columnHeaderAccess
            // 
            columnHeaderAccess.Text = "Access";
            columnHeaderAccess.Width = 83;
            // 
            // columnHeaderDaclFlags
            // 
            columnHeaderDaclFlags.Text = "Flags";
            columnHeaderDaclFlags.Width = 103;
            // 
            // columnHeaderDaclType
            // 
            columnHeaderDaclType.Text = "Type";
            // 
            // label10
            // 
            label10.AutoSize = true;
            label10.Location = new System.Drawing.Point(29, 49);
            label10.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label10.Name = "label10";
            label10.Size = new System.Drawing.Size(104, 17);
            label10.TabIndex = 8;
            label10.Text = "Primary Group:";
            // 
            // txtPrimaryGroup
            // 
            this.txtPrimaryGroup.Location = new System.Drawing.Point(175, 49);
            this.txtPrimaryGroup.Margin = new System.Windows.Forms.Padding(4);
            this.txtPrimaryGroup.Name = "txtPrimaryGroup";
            this.txtPrimaryGroup.ReadOnly = true;
            this.txtPrimaryGroup.Size = new System.Drawing.Size(355, 22);
            this.txtPrimaryGroup.TabIndex = 9;
            // 
            // label9
            // 
            label9.AutoSize = true;
            label9.Location = new System.Drawing.Point(29, 17);
            label9.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label9.Name = "label9";
            label9.Size = new System.Drawing.Size(102, 17);
            label9.TabIndex = 6;
            label9.Text = "Default Owner:";
            // 
            // txtOwner
            // 
            this.txtOwner.Location = new System.Drawing.Point(175, 17);
            this.txtOwner.Margin = new System.Windows.Forms.Padding(4);
            this.txtOwner.Name = "txtOwner";
            this.txtOwner.ReadOnly = true;
            this.txtOwner.Size = new System.Drawing.Size(355, 22);
            this.txtOwner.TabIndex = 7;
            // 
            // label11
            // 
            label11.AutoSize = true;
            label11.Location = new System.Drawing.Point(29, 17);
            label11.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label11.Name = "label11";
            label11.Size = new System.Drawing.Size(108, 17);
            label11.TabIndex = 8;
            label11.Text = "Package Name:";
            // 
            // label12
            // 
            label12.AutoSize = true;
            label12.Location = new System.Drawing.Point(29, 82);
            label12.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label12.Name = "label12";
            label12.Size = new System.Drawing.Size(156, 17);
            label12.TabIndex = 11;
            label12.Text = "App Container Number:";
            // 
            // groupBoxDuplicate
            // 
            groupBoxDuplicate.Controls.Add(this.btnImpersonate);
            groupBoxDuplicate.Controls.Add(lblILForDup);
            groupBoxDuplicate.Controls.Add(this.comboBoxILForDup);
            groupBoxDuplicate.Controls.Add(this.btnDuplicate);
            groupBoxDuplicate.Controls.Add(label15);
            groupBoxDuplicate.Controls.Add(this.comboBoxImpLevel);
            groupBoxDuplicate.Controls.Add(label14);
            groupBoxDuplicate.Controls.Add(this.comboBoxTokenType);
            groupBoxDuplicate.Location = new System.Drawing.Point(4, 7);
            groupBoxDuplicate.Margin = new System.Windows.Forms.Padding(4);
            groupBoxDuplicate.Name = "groupBoxDuplicate";
            groupBoxDuplicate.Padding = new System.Windows.Forms.Padding(4);
            groupBoxDuplicate.Size = new System.Drawing.Size(608, 143);
            groupBoxDuplicate.TabIndex = 0;
            groupBoxDuplicate.TabStop = false;
            groupBoxDuplicate.Text = "Duplicate Token";
            // 
            // btnImpersonate
            // 
            this.btnImpersonate.Location = new System.Drawing.Point(451, 94);
            this.btnImpersonate.Margin = new System.Windows.Forms.Padding(4);
            this.btnImpersonate.Name = "btnImpersonate";
            this.btnImpersonate.Size = new System.Drawing.Size(100, 28);
            this.btnImpersonate.TabIndex = 7;
            this.btnImpersonate.Text = "Round-Trip";
            this.toolTip.SetToolTip(this.btnImpersonate, "This impersonates the token then reads it back from the thread");
            this.btnImpersonate.UseVisualStyleBackColor = true;
            this.btnImpersonate.Click += new System.EventHandler(this.btnImpersonate_Click);
            // 
            // lblILForDup
            // 
            lblILForDup.AutoSize = true;
            lblILForDup.Location = new System.Drawing.Point(345, 31);
            lblILForDup.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            lblILForDup.Name = "lblILForDup";
            lblILForDup.Size = new System.Drawing.Size(67, 17);
            lblILForDup.TabIndex = 6;
            lblILForDup.Text = "Token IL:";
            // 
            // comboBoxILForDup
            // 
            this.comboBoxILForDup.FormattingEnabled = true;
            this.comboBoxILForDup.Location = new System.Drawing.Point(423, 27);
            this.comboBoxILForDup.Margin = new System.Windows.Forms.Padding(4);
            this.comboBoxILForDup.Name = "comboBoxILForDup";
            this.comboBoxILForDup.Size = new System.Drawing.Size(160, 24);
            this.comboBoxILForDup.TabIndex = 5;
            // 
            // btnDuplicate
            // 
            this.btnDuplicate.Location = new System.Drawing.Point(12, 94);
            this.btnDuplicate.Margin = new System.Windows.Forms.Padding(4);
            this.btnDuplicate.Name = "btnDuplicate";
            this.btnDuplicate.Size = new System.Drawing.Size(100, 28);
            this.btnDuplicate.TabIndex = 4;
            this.btnDuplicate.Text = "Duplicate";
            this.btnDuplicate.UseVisualStyleBackColor = true;
            this.btnDuplicate.Click += new System.EventHandler(this.btnDuplicate_Click);
            // 
            // label15
            // 
            label15.AutoSize = true;
            label15.Location = new System.Drawing.Point(8, 60);
            label15.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label15.Name = "label15";
            label15.Size = new System.Drawing.Size(139, 17);
            label15.TabIndex = 3;
            label15.Text = "Impersonation Level:";
            // 
            // comboBoxImpLevel
            // 
            this.comboBoxImpLevel.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBoxImpLevel.FormattingEnabled = true;
            this.comboBoxImpLevel.Location = new System.Drawing.Point(156, 57);
            this.comboBoxImpLevel.Margin = new System.Windows.Forms.Padding(4);
            this.comboBoxImpLevel.Name = "comboBoxImpLevel";
            this.comboBoxImpLevel.Size = new System.Drawing.Size(160, 24);
            this.comboBoxImpLevel.TabIndex = 2;
            // 
            // label14
            // 
            label14.AutoSize = true;
            label14.Location = new System.Drawing.Point(8, 27);
            label14.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label14.Name = "label14";
            label14.Size = new System.Drawing.Size(88, 17);
            label14.TabIndex = 1;
            label14.Text = "Token Type:";
            // 
            // comboBoxTokenType
            // 
            this.comboBoxTokenType.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBoxTokenType.FormattingEnabled = true;
            this.comboBoxTokenType.Location = new System.Drawing.Point(156, 23);
            this.comboBoxTokenType.Margin = new System.Windows.Forms.Padding(4);
            this.comboBoxTokenType.Name = "comboBoxTokenType";
            this.comboBoxTokenType.Size = new System.Drawing.Size(160, 24);
            this.comboBoxTokenType.TabIndex = 0;
            this.comboBoxTokenType.SelectedIndexChanged += new System.EventHandler(this.comboBoxTokenType_SelectedIndexChanged);
            // 
            // groupBox1
            // 
            groupBox1.Controls.Add(this.checkBoxUseNetLogon);
            groupBox1.Controls.Add(this.checkBoxUseWmi);
            groupBox1.Controls.Add(this.checkBoxMakeInteractive);
            groupBox1.Controls.Add(this.btnCreateProcess);
            groupBox1.Controls.Add(this.txtCommandLine);
            groupBox1.Controls.Add(label16);
            groupBox1.Location = new System.Drawing.Point(4, 158);
            groupBox1.Margin = new System.Windows.Forms.Padding(4);
            groupBox1.Name = "groupBox1";
            groupBox1.Padding = new System.Windows.Forms.Padding(4);
            groupBox1.Size = new System.Drawing.Size(608, 112);
            groupBox1.TabIndex = 1;
            groupBox1.TabStop = false;
            groupBox1.Text = "Create Process";
            // 
            // checkBoxUseNetLogon
            // 
            this.checkBoxUseNetLogon.AutoSize = true;
            this.checkBoxUseNetLogon.Location = new System.Drawing.Point(372, 73);
            this.checkBoxUseNetLogon.Margin = new System.Windows.Forms.Padding(4);
            this.checkBoxUseNetLogon.Name = "checkBoxUseNetLogon";
            this.checkBoxUseNetLogon.Size = new System.Drawing.Size(125, 21);
            this.checkBoxUseNetLogon.TabIndex = 5;
            this.checkBoxUseNetLogon.Text = "Use Net Logon";
            this.checkBoxUseNetLogon.UseVisualStyleBackColor = true;
            // 
            // checkBoxUseWmi
            // 
            this.checkBoxUseWmi.AutoSize = true;
            this.checkBoxUseWmi.Location = new System.Drawing.Point(269, 73);
            this.checkBoxUseWmi.Margin = new System.Windows.Forms.Padding(4);
            this.checkBoxUseWmi.Name = "checkBoxUseWmi";
            this.checkBoxUseWmi.Size = new System.Drawing.Size(86, 21);
            this.checkBoxUseWmi.TabIndex = 4;
            this.checkBoxUseWmi.Text = "Use WMI";
            this.checkBoxUseWmi.UseVisualStyleBackColor = true;
            // 
            // checkBoxMakeInteractive
            // 
            this.checkBoxMakeInteractive.AutoSize = true;
            this.checkBoxMakeInteractive.Location = new System.Drawing.Point(120, 73);
            this.checkBoxMakeInteractive.Margin = new System.Windows.Forms.Padding(4);
            this.checkBoxMakeInteractive.Name = "checkBoxMakeInteractive";
            this.checkBoxMakeInteractive.Size = new System.Drawing.Size(133, 21);
            this.checkBoxMakeInteractive.TabIndex = 3;
            this.checkBoxMakeInteractive.Text = "Make Interactive";
            this.checkBoxMakeInteractive.UseVisualStyleBackColor = true;
            // 
            // btnCreateProcess
            // 
            this.btnCreateProcess.Location = new System.Drawing.Point(12, 68);
            this.btnCreateProcess.Margin = new System.Windows.Forms.Padding(4);
            this.btnCreateProcess.Name = "btnCreateProcess";
            this.btnCreateProcess.Size = new System.Drawing.Size(100, 28);
            this.btnCreateProcess.TabIndex = 2;
            this.btnCreateProcess.Text = "Create";
            this.btnCreateProcess.UseVisualStyleBackColor = true;
            this.btnCreateProcess.Click += new System.EventHandler(this.btnCreateProcess_Click);
            // 
            // txtCommandLine
            // 
            this.txtCommandLine.Location = new System.Drawing.Point(123, 27);
            this.txtCommandLine.Margin = new System.Windows.Forms.Padding(4);
            this.txtCommandLine.Name = "txtCommandLine";
            this.txtCommandLine.Size = new System.Drawing.Size(409, 22);
            this.txtCommandLine.TabIndex = 1;
            this.txtCommandLine.Text = "cmd.exe";
            // 
            // label16
            // 
            label16.AutoSize = true;
            label16.Location = new System.Drawing.Point(8, 31);
            label16.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label16.Name = "label16";
            label16.Size = new System.Drawing.Size(106, 17);
            label16.TabIndex = 0;
            label16.Text = "Command Line:";
            // 
            // groupBox2
            // 
            groupBox2.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            groupBox2.Controls.Add(this.btnToggleVirtualizationEnabled);
            groupBox2.Controls.Add(label26);
            groupBox2.Controls.Add(this.txtHandleAccess);
            groupBox2.Controls.Add(this.btnToggleUIAccess);
            groupBox2.Controls.Add(this.treeViewSecurityAttributes);
            groupBox2.Controls.Add(this.llbSecurityAttributes);
            groupBox2.Controls.Add(label22);
            groupBox2.Controls.Add(this.txtMandatoryILPolicy);
            groupBox2.Controls.Add(label20);
            groupBox2.Controls.Add(this.txtVirtualizationEnabled);
            groupBox2.Controls.Add(label19);
            groupBox2.Controls.Add(this.txtVirtualizationAllowed);
            groupBox2.Controls.Add(label18);
            groupBox2.Controls.Add(this.txtSandboxInert);
            groupBox2.Controls.Add(label17);
            groupBox2.Controls.Add(this.txtUIAccess);
            groupBox2.Location = new System.Drawing.Point(11, 7);
            groupBox2.Margin = new System.Windows.Forms.Padding(4);
            groupBox2.Name = "groupBox2";
            groupBox2.Padding = new System.Windows.Forms.Padding(4);
            groupBox2.Size = new System.Drawing.Size(601, 437);
            groupBox2.TabIndex = 0;
            groupBox2.TabStop = false;
            groupBox2.Text = "Additional Properties";
            // 
            // btnToggleVirtualizationEnabled
            // 
            this.btnToggleVirtualizationEnabled.Location = new System.Drawing.Point(313, 111);
            this.btnToggleVirtualizationEnabled.Margin = new System.Windows.Forms.Padding(4);
            this.btnToggleVirtualizationEnabled.Name = "btnToggleVirtualizationEnabled";
            this.btnToggleVirtualizationEnabled.Size = new System.Drawing.Size(100, 28);
            this.btnToggleVirtualizationEnabled.TabIndex = 21;
            this.btnToggleVirtualizationEnabled.Text = "Toggle";
            this.btnToggleVirtualizationEnabled.UseVisualStyleBackColor = true;
            this.btnToggleVirtualizationEnabled.Click += new System.EventHandler(this.btnToggleVirtualizationEnabled_Click);
            // 
            // label26
            // 
            label26.AutoSize = true;
            label26.Location = new System.Drawing.Point(8, 185);
            label26.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label26.Name = "label26";
            label26.Size = new System.Drawing.Size(106, 17);
            label26.TabIndex = 19;
            label26.Text = "Handle Access:";
            // 
            // txtHandleAccess
            // 
            this.txtHandleAccess.Location = new System.Drawing.Point(161, 181);
            this.txtHandleAccess.Margin = new System.Windows.Forms.Padding(4);
            this.txtHandleAccess.Name = "txtHandleAccess";
            this.txtHandleAccess.ReadOnly = true;
            this.txtHandleAccess.Size = new System.Drawing.Size(288, 22);
            this.txtHandleAccess.TabIndex = 20;
            // 
            // btnToggleUIAccess
            // 
            this.btnToggleUIAccess.Location = new System.Drawing.Point(313, 14);
            this.btnToggleUIAccess.Margin = new System.Windows.Forms.Padding(4);
            this.btnToggleUIAccess.Name = "btnToggleUIAccess";
            this.btnToggleUIAccess.Size = new System.Drawing.Size(100, 28);
            this.btnToggleUIAccess.TabIndex = 18;
            this.btnToggleUIAccess.Text = "Toggle";
            this.btnToggleUIAccess.UseVisualStyleBackColor = true;
            this.btnToggleUIAccess.Click += new System.EventHandler(this.btnToggleUIAccess_Click);
            // 
            // treeViewSecurityAttributes
            // 
            this.treeViewSecurityAttributes.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.treeViewSecurityAttributes.Location = new System.Drawing.Point(12, 236);
            this.treeViewSecurityAttributes.Margin = new System.Windows.Forms.Padding(4);
            this.treeViewSecurityAttributes.Name = "treeViewSecurityAttributes";
            this.treeViewSecurityAttributes.Size = new System.Drawing.Size(527, 176);
            this.treeViewSecurityAttributes.TabIndex = 17;
            // 
            // llbSecurityAttributes
            // 
            this.llbSecurityAttributes.AutoSize = true;
            this.llbSecurityAttributes.Location = new System.Drawing.Point(8, 217);
            this.llbSecurityAttributes.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.llbSecurityAttributes.Name = "llbSecurityAttributes";
            this.llbSecurityAttributes.Size = new System.Drawing.Size(127, 17);
            this.llbSecurityAttributes.TabIndex = 16;
            this.llbSecurityAttributes.Text = "Security Attributes:";
            // 
            // label22
            // 
            label22.AutoSize = true;
            label22.Location = new System.Drawing.Point(8, 149);
            label22.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label22.Name = "label22";
            label22.Size = new System.Drawing.Size(135, 17);
            label22.TabIndex = 14;
            label22.Text = "Mandatory IL Policy:";
            // 
            // txtMandatoryILPolicy
            // 
            this.txtMandatoryILPolicy.Location = new System.Drawing.Point(161, 145);
            this.txtMandatoryILPolicy.Margin = new System.Windows.Forms.Padding(4);
            this.txtMandatoryILPolicy.Name = "txtMandatoryILPolicy";
            this.txtMandatoryILPolicy.ReadOnly = true;
            this.txtMandatoryILPolicy.Size = new System.Drawing.Size(288, 22);
            this.txtMandatoryILPolicy.TabIndex = 15;
            // 
            // label20
            // 
            label20.AutoSize = true;
            label20.Location = new System.Drawing.Point(8, 117);
            label20.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label20.Name = "label20";
            label20.Size = new System.Drawing.Size(149, 17);
            label20.TabIndex = 12;
            label20.Text = "Virtualization Enabled:";
            // 
            // txtVirtualizationEnabled
            // 
            this.txtVirtualizationEnabled.Location = new System.Drawing.Point(161, 113);
            this.txtVirtualizationEnabled.Margin = new System.Windows.Forms.Padding(4);
            this.txtVirtualizationEnabled.Name = "txtVirtualizationEnabled";
            this.txtVirtualizationEnabled.ReadOnly = true;
            this.txtVirtualizationEnabled.Size = new System.Drawing.Size(143, 22);
            this.txtVirtualizationEnabled.TabIndex = 13;
            // 
            // label19
            // 
            label19.AutoSize = true;
            label19.Location = new System.Drawing.Point(8, 85);
            label19.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label19.Name = "label19";
            label19.Size = new System.Drawing.Size(145, 17);
            label19.TabIndex = 10;
            label19.Text = "Virtualization Allowed:";
            // 
            // txtVirtualizationAllowed
            // 
            this.txtVirtualizationAllowed.Location = new System.Drawing.Point(161, 81);
            this.txtVirtualizationAllowed.Margin = new System.Windows.Forms.Padding(4);
            this.txtVirtualizationAllowed.Name = "txtVirtualizationAllowed";
            this.txtVirtualizationAllowed.ReadOnly = true;
            this.txtVirtualizationAllowed.Size = new System.Drawing.Size(143, 22);
            this.txtVirtualizationAllowed.TabIndex = 11;
            // 
            // label18
            // 
            label18.AutoSize = true;
            label18.Location = new System.Drawing.Point(8, 53);
            label18.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label18.Name = "label18";
            label18.Size = new System.Drawing.Size(99, 17);
            label18.TabIndex = 8;
            label18.Text = "Sandbox Inert:";
            // 
            // txtSandboxInert
            // 
            this.txtSandboxInert.Location = new System.Drawing.Point(161, 48);
            this.txtSandboxInert.Margin = new System.Windows.Forms.Padding(4);
            this.txtSandboxInert.Name = "txtSandboxInert";
            this.txtSandboxInert.ReadOnly = true;
            this.txtSandboxInert.Size = new System.Drawing.Size(143, 22);
            this.txtSandboxInert.TabIndex = 9;
            // 
            // label17
            // 
            label17.AutoSize = true;
            label17.Location = new System.Drawing.Point(8, 20);
            label17.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label17.Name = "label17";
            label17.Size = new System.Drawing.Size(74, 17);
            label17.TabIndex = 6;
            label17.Text = "UI Access:";
            // 
            // txtUIAccess
            // 
            this.txtUIAccess.Location = new System.Drawing.Point(161, 16);
            this.txtUIAccess.Margin = new System.Windows.Forms.Padding(4);
            this.txtUIAccess.Name = "txtUIAccess";
            this.txtUIAccess.ReadOnly = true;
            this.txtUIAccess.Size = new System.Drawing.Size(143, 22);
            this.txtUIAccess.TabIndex = 7;
            // 
            // groupBoxSafer
            // 
            groupBoxSafer.Controls.Add(this.btnCreateSandbox);
            groupBoxSafer.Controls.Add(label21);
            groupBoxSafer.Controls.Add(this.comboBoxSaferLevel);
            groupBoxSafer.Controls.Add(this.checkBoxSaferMakeInert);
            groupBoxSafer.Controls.Add(this.btnComputeSafer);
            groupBoxSafer.Location = new System.Drawing.Point(4, 277);
            groupBoxSafer.Margin = new System.Windows.Forms.Padding(4);
            groupBoxSafer.Name = "groupBoxSafer";
            groupBoxSafer.Padding = new System.Windows.Forms.Padding(4);
            groupBoxSafer.Size = new System.Drawing.Size(611, 111);
            groupBoxSafer.TabIndex = 2;
            groupBoxSafer.TabStop = false;
            groupBoxSafer.Text = "Restricted Tokens";
            // 
            // btnCreateSandbox
            // 
            this.btnCreateSandbox.Location = new System.Drawing.Point(469, 69);
            this.btnCreateSandbox.Margin = new System.Windows.Forms.Padding(4);
            this.btnCreateSandbox.Name = "btnCreateSandbox";
            this.btnCreateSandbox.Size = new System.Drawing.Size(133, 28);
            this.btnCreateSandbox.TabIndex = 8;
            this.btnCreateSandbox.Text = "Create Sandbox";
            this.btnCreateSandbox.UseVisualStyleBackColor = true;
            this.btnCreateSandbox.Click += new System.EventHandler(this.btnCreateSandbox_Click);
            // 
            // label21
            // 
            label21.AutoSize = true;
            label21.Location = new System.Drawing.Point(11, 38);
            label21.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label21.Name = "label21";
            label21.Size = new System.Drawing.Size(84, 17);
            label21.TabIndex = 6;
            label21.Text = "Safer Level:";
            // 
            // comboBoxSaferLevel
            // 
            this.comboBoxSaferLevel.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBoxSaferLevel.FormattingEnabled = true;
            this.comboBoxSaferLevel.Location = new System.Drawing.Point(135, 34);
            this.comboBoxSaferLevel.Margin = new System.Windows.Forms.Padding(4);
            this.comboBoxSaferLevel.Name = "comboBoxSaferLevel";
            this.comboBoxSaferLevel.Size = new System.Drawing.Size(160, 24);
            this.comboBoxSaferLevel.TabIndex = 5;
            // 
            // checkBoxSaferMakeInert
            // 
            this.checkBoxSaferMakeInert.AutoSize = true;
            this.checkBoxSaferMakeInert.Location = new System.Drawing.Point(319, 39);
            this.checkBoxSaferMakeInert.Margin = new System.Windows.Forms.Padding(4);
            this.checkBoxSaferMakeInert.Name = "checkBoxSaferMakeInert";
            this.checkBoxSaferMakeInert.Size = new System.Drawing.Size(96, 21);
            this.checkBoxSaferMakeInert.TabIndex = 4;
            this.checkBoxSaferMakeInert.Text = "Make Inert";
            this.checkBoxSaferMakeInert.UseVisualStyleBackColor = true;
            // 
            // btnComputeSafer
            // 
            this.btnComputeSafer.Location = new System.Drawing.Point(12, 69);
            this.btnComputeSafer.Margin = new System.Windows.Forms.Padding(4);
            this.btnComputeSafer.Name = "btnComputeSafer";
            this.btnComputeSafer.Size = new System.Drawing.Size(100, 28);
            this.btnComputeSafer.TabIndex = 3;
            this.btnComputeSafer.Text = "Create Safer";
            this.btnComputeSafer.UseVisualStyleBackColor = true;
            this.btnComputeSafer.Click += new System.EventHandler(this.btnComputeSafer_Click);
            // 
            // groupBox4
            // 
            groupBox4.Controls.Add(this.btnCreate);
            groupBox4.Controls.Add(this.btnBrowse);
            groupBox4.Controls.Add(label24);
            groupBox4.Controls.Add(this.txtFileContents);
            groupBox4.Controls.Add(this.txtFilePath);
            groupBox4.Controls.Add(label23);
            groupBox4.Location = new System.Drawing.Point(4, 395);
            groupBox4.Margin = new System.Windows.Forms.Padding(4);
            groupBox4.Name = "groupBox4";
            groupBox4.Padding = new System.Windows.Forms.Padding(4);
            groupBox4.Size = new System.Drawing.Size(608, 123);
            groupBox4.TabIndex = 3;
            groupBox4.TabStop = false;
            groupBox4.Text = "Impersonate and Create File";
            // 
            // btnCreate
            // 
            this.btnCreate.Location = new System.Drawing.Point(484, 66);
            this.btnCreate.Margin = new System.Windows.Forms.Padding(4);
            this.btnCreate.Name = "btnCreate";
            this.btnCreate.Size = new System.Drawing.Size(100, 28);
            this.btnCreate.TabIndex = 5;
            this.btnCreate.Text = "Create";
            this.btnCreate.UseVisualStyleBackColor = true;
            this.btnCreate.Click += new System.EventHandler(this.btnCreate_Click);
            // 
            // btnBrowse
            // 
            this.btnBrowse.Location = new System.Drawing.Point(484, 20);
            this.btnBrowse.Margin = new System.Windows.Forms.Padding(4);
            this.btnBrowse.Name = "btnBrowse";
            this.btnBrowse.Size = new System.Drawing.Size(100, 28);
            this.btnBrowse.TabIndex = 4;
            this.btnBrowse.Text = "Browse";
            this.btnBrowse.UseVisualStyleBackColor = true;
            this.btnBrowse.Click += new System.EventHandler(this.btnBrowse_Click);
            // 
            // label24
            // 
            label24.AutoSize = true;
            label24.Location = new System.Drawing.Point(11, 55);
            label24.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label24.Name = "label24";
            label24.Size = new System.Drawing.Size(68, 17);
            label24.TabIndex = 3;
            label24.Text = "Contents:";
            // 
            // txtFileContents
            // 
            this.txtFileContents.Location = new System.Drawing.Point(87, 52);
            this.txtFileContents.Margin = new System.Windows.Forms.Padding(4);
            this.txtFileContents.Multiline = true;
            this.txtFileContents.Name = "txtFileContents";
            this.txtFileContents.Size = new System.Drawing.Size(372, 63);
            this.txtFileContents.TabIndex = 2;
            this.txtFileContents.Text = "Hello World!";
            // 
            // txtFilePath
            // 
            this.txtFilePath.Location = new System.Drawing.Point(87, 20);
            this.txtFilePath.Margin = new System.Windows.Forms.Padding(4);
            this.txtFilePath.Name = "txtFilePath";
            this.txtFilePath.Size = new System.Drawing.Size(372, 22);
            this.txtFilePath.TabIndex = 1;
            this.txtFilePath.Text = "c:\\windows\\test.txt";
            // 
            // label23
            // 
            label23.AutoSize = true;
            label23.Location = new System.Drawing.Point(11, 23);
            label23.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label23.Name = "label23";
            label23.Size = new System.Drawing.Size(67, 17);
            label23.TabIndex = 0;
            label23.Text = "File Path:";
            // 
            // columnHeader5
            // 
            columnHeader5.Text = "Name";
            columnHeader5.Width = 210;
            // 
            // columnHeader6
            // 
            columnHeader6.Text = "Flags";
            columnHeader6.Width = 194;
            // 
            // tabControlMain
            // 
            this.tabControlMain.Controls.Add(tabPageMain);
            this.tabControlMain.Controls.Add(tabPageGroups);
            this.tabControlMain.Controls.Add(this.tabPagePrivs);
            this.tabControlMain.Controls.Add(this.tabPageRestricted);
            this.tabControlMain.Controls.Add(this.tabPageAppContainer);
            this.tabControlMain.Controls.Add(tabPageDefaultDacl);
            this.tabControlMain.Controls.Add(this.tabPageMisc);
            this.tabControlMain.Controls.Add(this.tabPageOperations);
            this.tabControlMain.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tabControlMain.Location = new System.Drawing.Point(0, 0);
            this.tabControlMain.Margin = new System.Windows.Forms.Padding(4);
            this.tabControlMain.Name = "tabControlMain";
            this.tabControlMain.SelectedIndex = 0;
            this.tabControlMain.Size = new System.Drawing.Size(633, 594);
            this.tabControlMain.TabIndex = 0;
            // 
            // tabPagePrivs
            // 
            this.tabPagePrivs.Controls.Add(this.listViewPrivs);
            this.tabPagePrivs.Location = new System.Drawing.Point(4, 25);
            this.tabPagePrivs.Margin = new System.Windows.Forms.Padding(4);
            this.tabPagePrivs.Name = "tabPagePrivs";
            this.tabPagePrivs.Padding = new System.Windows.Forms.Padding(4);
            this.tabPagePrivs.Size = new System.Drawing.Size(625, 565);
            this.tabPagePrivs.TabIndex = 7;
            this.tabPagePrivs.Text = "Privileges";
            this.tabPagePrivs.UseVisualStyleBackColor = true;
            // 
            // listViewPrivs
            // 
            this.listViewPrivs.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeader5,
            columnHeader6});
            this.listViewPrivs.ContextMenuStrip = this.contextMenuStripPrivileges;
            this.listViewPrivs.Dock = System.Windows.Forms.DockStyle.Fill;
            this.listViewPrivs.FullRowSelect = true;
            this.listViewPrivs.Location = new System.Drawing.Point(4, 4);
            this.listViewPrivs.Margin = new System.Windows.Forms.Padding(4);
            this.listViewPrivs.Name = "listViewPrivs";
            this.listViewPrivs.Size = new System.Drawing.Size(617, 557);
            this.listViewPrivs.TabIndex = 1;
            this.listViewPrivs.UseCompatibleStateImageBehavior = false;
            this.listViewPrivs.View = System.Windows.Forms.View.Details;
            this.listViewPrivs.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.listView_ColumnClick);
            // 
            // contextMenuStripPrivileges
            // 
            this.contextMenuStripPrivileges.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.contextMenuStripPrivileges.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.enablePrivilegeToolStripMenuItem,
            this.removePrivilegeToolStripMenuItem,
            this.selectAllPrivsToolStripMenuItem});
            this.contextMenuStripPrivileges.Name = "contextMenuStripPrivileges";
            this.contextMenuStripPrivileges.Size = new System.Drawing.Size(194, 76);
            this.contextMenuStripPrivileges.Opening += new System.ComponentModel.CancelEventHandler(this.contextMenuStripPrivileges_Opening);
            // 
            // enablePrivilegeToolStripMenuItem
            // 
            this.enablePrivilegeToolStripMenuItem.Name = "enablePrivilegeToolStripMenuItem";
            this.enablePrivilegeToolStripMenuItem.Size = new System.Drawing.Size(193, 24);
            this.enablePrivilegeToolStripMenuItem.Text = "Enable Privilege";
            this.enablePrivilegeToolStripMenuItem.Click += new System.EventHandler(this.enablePrivilegeToolStripMenuItem_Click);
            // 
            // removePrivilegeToolStripMenuItem
            // 
            this.removePrivilegeToolStripMenuItem.Name = "removePrivilegeToolStripMenuItem";
            this.removePrivilegeToolStripMenuItem.Size = new System.Drawing.Size(193, 24);
            this.removePrivilegeToolStripMenuItem.Text = "Remove Privilege";
            this.removePrivilegeToolStripMenuItem.Click += new System.EventHandler(this.removePrivilegeToolStripMenuItem_Click);
            // 
            // selectAllPrivsToolStripMenuItem
            // 
            this.selectAllPrivsToolStripMenuItem.Name = "selectAllPrivsToolStripMenuItem";
            this.selectAllPrivsToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.A)));
            this.selectAllPrivsToolStripMenuItem.Size = new System.Drawing.Size(193, 24);
            this.selectAllPrivsToolStripMenuItem.Text = "Select All";
            this.selectAllPrivsToolStripMenuItem.Click += new System.EventHandler(this.selectAllToolStripMenuItem_Click);
            // 
            // tabPageRestricted
            // 
            this.tabPageRestricted.Controls.Add(this.listViewRestrictedSids);
            this.tabPageRestricted.Location = new System.Drawing.Point(4, 25);
            this.tabPageRestricted.Margin = new System.Windows.Forms.Padding(4);
            this.tabPageRestricted.Name = "tabPageRestricted";
            this.tabPageRestricted.Padding = new System.Windows.Forms.Padding(4);
            this.tabPageRestricted.Size = new System.Drawing.Size(625, 565);
            this.tabPageRestricted.TabIndex = 3;
            this.tabPageRestricted.Text = "Restricted SIDs";
            this.tabPageRestricted.UseVisualStyleBackColor = true;
            // 
            // listViewRestrictedSids
            // 
            this.listViewRestrictedSids.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader1,
            this.columnHeader2});
            this.listViewRestrictedSids.Dock = System.Windows.Forms.DockStyle.Fill;
            this.listViewRestrictedSids.FullRowSelect = true;
            this.listViewRestrictedSids.Location = new System.Drawing.Point(4, 4);
            this.listViewRestrictedSids.Margin = new System.Windows.Forms.Padding(4);
            this.listViewRestrictedSids.Name = "listViewRestrictedSids";
            this.listViewRestrictedSids.Size = new System.Drawing.Size(617, 557);
            this.listViewRestrictedSids.TabIndex = 1;
            this.listViewRestrictedSids.UseCompatibleStateImageBehavior = false;
            this.listViewRestrictedSids.View = System.Windows.Forms.View.Details;
            this.listViewRestrictedSids.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.listView_ColumnClick);
            // 
            // columnHeader1
            // 
            this.columnHeader1.Text = "Name";
            this.columnHeader1.Width = 210;
            // 
            // columnHeader2
            // 
            this.columnHeader2.Text = "Flags";
            this.columnHeader2.Width = 194;
            // 
            // tabPageAppContainer
            // 
            this.tabPageAppContainer.Controls.Add(label27);
            this.tabPageAppContainer.Controls.Add(this.txtPackageSid);
            this.tabPageAppContainer.Controls.Add(label12);
            this.tabPageAppContainer.Controls.Add(this.txtACNumber);
            this.tabPageAppContainer.Controls.Add(this.listViewCapabilities);
            this.tabPageAppContainer.Controls.Add(label11);
            this.tabPageAppContainer.Controls.Add(this.txtPackageName);
            this.tabPageAppContainer.Location = new System.Drawing.Point(4, 25);
            this.tabPageAppContainer.Margin = new System.Windows.Forms.Padding(4);
            this.tabPageAppContainer.Name = "tabPageAppContainer";
            this.tabPageAppContainer.Padding = new System.Windows.Forms.Padding(4);
            this.tabPageAppContainer.Size = new System.Drawing.Size(625, 565);
            this.tabPageAppContainer.TabIndex = 4;
            this.tabPageAppContainer.Text = "App Container";
            this.tabPageAppContainer.UseVisualStyleBackColor = true;
            // 
            // txtACNumber
            // 
            this.txtACNumber.Location = new System.Drawing.Point(189, 82);
            this.txtACNumber.Margin = new System.Windows.Forms.Padding(4);
            this.txtACNumber.Name = "txtACNumber";
            this.txtACNumber.ReadOnly = true;
            this.txtACNumber.Size = new System.Drawing.Size(111, 22);
            this.txtACNumber.TabIndex = 12;
            // 
            // listViewCapabilities
            // 
            this.listViewCapabilities.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.listViewCapabilities.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader3,
            this.columnHeader4});
            this.listViewCapabilities.FullRowSelect = true;
            this.listViewCapabilities.Location = new System.Drawing.Point(4, 112);
            this.listViewCapabilities.Margin = new System.Windows.Forms.Padding(4);
            this.listViewCapabilities.Name = "listViewCapabilities";
            this.listViewCapabilities.Size = new System.Drawing.Size(613, 438);
            this.listViewCapabilities.TabIndex = 10;
            this.listViewCapabilities.UseCompatibleStateImageBehavior = false;
            this.listViewCapabilities.View = System.Windows.Forms.View.Details;
            this.listViewCapabilities.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.listView_ColumnClick);
            // 
            // columnHeader3
            // 
            this.columnHeader3.Text = "Name";
            this.columnHeader3.Width = 210;
            // 
            // columnHeader4
            // 
            this.columnHeader4.Text = "Flags";
            this.columnHeader4.Width = 194;
            // 
            // txtPackageName
            // 
            this.txtPackageName.Location = new System.Drawing.Point(189, 17);
            this.txtPackageName.Margin = new System.Windows.Forms.Padding(4);
            this.txtPackageName.Name = "txtPackageName";
            this.txtPackageName.ReadOnly = true;
            this.txtPackageName.Size = new System.Drawing.Size(340, 22);
            this.txtPackageName.TabIndex = 9;
            // 
            // tabPageMisc
            // 
            this.tabPageMisc.Controls.Add(groupBox2);
            this.tabPageMisc.Location = new System.Drawing.Point(4, 25);
            this.tabPageMisc.Margin = new System.Windows.Forms.Padding(4);
            this.tabPageMisc.Name = "tabPageMisc";
            this.tabPageMisc.Padding = new System.Windows.Forms.Padding(4);
            this.tabPageMisc.Size = new System.Drawing.Size(625, 565);
            this.tabPageMisc.TabIndex = 6;
            this.tabPageMisc.Text = "Misc";
            this.tabPageMisc.UseVisualStyleBackColor = true;
            // 
            // tabPageOperations
            // 
            this.tabPageOperations.Controls.Add(groupBox4);
            this.tabPageOperations.Controls.Add(groupBoxSafer);
            this.tabPageOperations.Controls.Add(groupBox1);
            this.tabPageOperations.Controls.Add(groupBoxDuplicate);
            this.tabPageOperations.Location = new System.Drawing.Point(4, 25);
            this.tabPageOperations.Margin = new System.Windows.Forms.Padding(4);
            this.tabPageOperations.Name = "tabPageOperations";
            this.tabPageOperations.Padding = new System.Windows.Forms.Padding(4);
            this.tabPageOperations.Size = new System.Drawing.Size(625, 565);
            this.tabPageOperations.TabIndex = 5;
            this.tabPageOperations.Text = "Operations";
            this.tabPageOperations.UseVisualStyleBackColor = true;
            // 
            // label27
            // 
            label27.AutoSize = true;
            label27.Location = new System.Drawing.Point(29, 52);
            label27.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label27.Name = "label27";
            label27.Size = new System.Drawing.Size(93, 17);
            label27.TabIndex = 13;
            label27.Text = "Package SID:";
            // 
            // txtPackageSid
            // 
            this.txtPackageSid.Location = new System.Drawing.Point(189, 52);
            this.txtPackageSid.Margin = new System.Windows.Forms.Padding(4);
            this.txtPackageSid.Name = "txtPackageSid";
            this.txtPackageSid.ReadOnly = true;
            this.txtPackageSid.Size = new System.Drawing.Size(340, 22);
            this.txtPackageSid.TabIndex = 14;
            // 
            // TokenForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(633, 594);
            this.Controls.Add(this.tabControlMain);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(4);
            this.MinimumSize = new System.Drawing.Size(649, 624);
            this.Name = "TokenForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "Token View";
            tabPageMain.ResumeLayout(false);
            this.groupBoxSource.ResumeLayout(false);
            this.groupBoxSource.PerformLayout();
            groupBoxToken.ResumeLayout(false);
            groupBoxToken.PerformLayout();
            tabPageGroups.ResumeLayout(false);
            this.contextMenuStripGroups.ResumeLayout(false);
            tabPageDefaultDacl.ResumeLayout(false);
            tabPageDefaultDacl.PerformLayout();
            groupBoxDuplicate.ResumeLayout(false);
            groupBoxDuplicate.PerformLayout();
            groupBox1.ResumeLayout(false);
            groupBox1.PerformLayout();
            groupBox2.ResumeLayout(false);
            groupBox2.PerformLayout();
            groupBoxSafer.ResumeLayout(false);
            groupBoxSafer.PerformLayout();
            groupBox4.ResumeLayout(false);
            groupBox4.PerformLayout();
            this.tabControlMain.ResumeLayout(false);
            this.tabPagePrivs.ResumeLayout(false);
            this.contextMenuStripPrivileges.ResumeLayout(false);
            this.tabPageRestricted.ResumeLayout(false);
            this.tabPageAppContainer.ResumeLayout(false);
            this.tabPageAppContainer.PerformLayout();
            this.tabPageMisc.ResumeLayout(false);
            this.tabPageOperations.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TabControl tabControlMain;
        private System.Windows.Forms.TextBox txtUserSid;
        private System.Windows.Forms.TextBox txtUsername;
        private System.Windows.Forms.Label lblUsername;
        private System.Windows.Forms.Label lblUserSid;
        private System.Windows.Forms.TextBox txtImpLevel;
        private System.Windows.Forms.TextBox txtTokenType;
        private System.Windows.Forms.TextBox txtModifiedId;
        private System.Windows.Forms.TextBox txtAuthId;
        private System.Windows.Forms.TextBox txtTokenId;
        private System.Windows.Forms.Button btnPermissions;
        private System.Windows.Forms.TextBox txtSessionId;
        private System.Windows.Forms.GroupBox groupBoxSource;
        private System.Windows.Forms.TextBox txtSourceId;
        private System.Windows.Forms.TextBox txtSourceName;
        private System.Windows.Forms.TextBox txtElevationType;
        private System.Windows.Forms.Button btnLinkedToken;
        private System.Windows.Forms.ListView listViewGroups;
        private System.Windows.Forms.TextBox txtPrimaryGroup;
        private System.Windows.Forms.TextBox txtOwner;
        private System.Windows.Forms.ListView listViewDefDacl;
        private System.Windows.Forms.TabPage tabPageRestricted;
        private System.Windows.Forms.ListView listViewRestrictedSids;
        private System.Windows.Forms.ColumnHeader columnHeader1;
        private System.Windows.Forms.ColumnHeader columnHeader2;
        private System.Windows.Forms.TabPage tabPageAppContainer;
        private System.Windows.Forms.TextBox txtPackageName;
        private System.Windows.Forms.ListView listViewCapabilities;
        private System.Windows.Forms.ColumnHeader columnHeader3;
        private System.Windows.Forms.ColumnHeader columnHeader4;
        private System.Windows.Forms.TextBox txtACNumber;
        private System.Windows.Forms.TabPage tabPageOperations;
        private System.Windows.Forms.TextBox txtOriginLoginId;
        private System.Windows.Forms.ComboBox comboBoxImpLevel;
        private System.Windows.Forms.ComboBox comboBoxTokenType;
        private System.Windows.Forms.Button btnDuplicate;
        private System.Windows.Forms.Button btnCreateProcess;
        private System.Windows.Forms.TextBox txtCommandLine;
        private System.Windows.Forms.TabPage tabPageMisc;
        private System.Windows.Forms.TextBox txtUIAccess;
        private System.Windows.Forms.TextBox txtSandboxInert;
        private System.Windows.Forms.TextBox txtVirtualizationEnabled;
        private System.Windows.Forms.TextBox txtVirtualizationAllowed;
        private System.Windows.Forms.ComboBox comboBoxSaferLevel;
        private System.Windows.Forms.CheckBox checkBoxSaferMakeInert;
        private System.Windows.Forms.Button btnComputeSafer;
        private System.Windows.Forms.TextBox txtMandatoryILPolicy;
        private System.Windows.Forms.CheckBox checkBoxMakeInteractive;
        private System.Windows.Forms.ComboBox comboBoxIL;
        private System.Windows.Forms.Button btnSetIL;
        private System.Windows.Forms.ComboBox comboBoxILForDup;
        private System.Windows.Forms.Button btnBrowse;
        private System.Windows.Forms.TextBox txtFileContents;
        private System.Windows.Forms.TextBox txtFilePath;
        private System.Windows.Forms.Button btnCreate;
        private System.Windows.Forms.TabPage tabPagePrivs;
        private System.Windows.Forms.ListView listViewPrivs;
        private System.Windows.Forms.ContextMenuStrip contextMenuStripPrivileges;
        private System.Windows.Forms.ToolStripMenuItem enablePrivilegeToolStripMenuItem;
        private System.Windows.Forms.TextBox txtIsElevated;
        private System.Windows.Forms.ToolStripMenuItem selectAllPrivsToolStripMenuItem;
        private System.Windows.Forms.ContextMenuStrip contextMenuStripGroups;
        private System.Windows.Forms.ToolStripMenuItem enableGroupToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem selectAllGroupsToolStripMenuItem;
        private System.Windows.Forms.Button btnCreateSandbox;
        private System.Windows.Forms.Button btnImpersonate;
        private System.Windows.Forms.ToolTip toolTip;
        private System.Windows.Forms.CheckBox checkBoxUseWmi;
        private System.Windows.Forms.ToolStripMenuItem removePrivilegeToolStripMenuItem;
        private System.Windows.Forms.Label llbSecurityAttributes;
        private System.Windows.Forms.TreeView treeViewSecurityAttributes;
        private System.Windows.Forms.Button btnToggleUIAccess;
        private System.Windows.Forms.TextBox txtHandleAccess;
        private System.Windows.Forms.Button btnToggleVirtualizationEnabled;
        private System.Windows.Forms.CheckBox checkBoxUseNetLogon;
        private System.Windows.Forms.TextBox txtPackageSid;
    }
}