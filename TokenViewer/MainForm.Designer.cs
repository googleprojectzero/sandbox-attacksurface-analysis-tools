namespace TokenViewer
{
    partial class MainForm
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
            System.Windows.Forms.TabPage tabPageServices;
            System.Windows.Forms.GroupBox groupBoxAnonymous;
            System.Windows.Forms.GroupBox groupBox2;
            System.Windows.Forms.GroupBox groupBox1;
            System.Windows.Forms.Label label3;
            System.Windows.Forms.TabPage tabPageGeneral;
            System.Windows.Forms.GroupBox groupBoxLogonUser;
            System.Windows.Forms.Label label6;
            System.Windows.Forms.Label label2;
            System.Windows.Forms.ColumnHeader columnHeaderSessionId;
            System.Windows.Forms.ColumnHeader columnHeaderUserName;
            System.Windows.Forms.ColumnHeader columnHeaderProcess;
            System.Windows.Forms.Label label4;
            System.Windows.Forms.ColumnHeader columnHeaderProcessId;
            System.Windows.Forms.ColumnHeader columnHeaderProcessName;
            System.Windows.Forms.ColumnHeader columnHeaderProcessUser;
            System.Windows.Forms.ColumnHeader columnHeaderProcessIL;
            System.Windows.Forms.ColumnHeader columnHeaderProcessRestricted;
            System.Windows.Forms.ColumnHeader columnHeaderProcessAC;
            System.Windows.Forms.ColumnHeader columnHeaderHandleProcessId;
            System.Windows.Forms.ColumnHeader columnHeaderHandleProcessName;
            System.Windows.Forms.ColumnHeader columnHeaderHandleUser;
            System.Windows.Forms.ColumnHeader columnHeaderHandleIL;
            System.Windows.Forms.ColumnHeader columnHeaderHandleRestricted;
            System.Windows.Forms.ColumnHeader columnHeaderHandleAC;
            System.Windows.Forms.ColumnHeader columnHeaderHandleHandle;
            System.Windows.Forms.ColumnHeader columnHeaderHandleTokenType;
            System.Windows.Forms.ColumnHeader columnHeaderHandleImpLevel;
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            this.btnCreateAnonymous = new System.Windows.Forms.Button();
            this.btnClipboardToken = new System.Windows.Forms.Button();
            this.btnPipeConnect = new System.Windows.Forms.Button();
            this.btnStartServer = new System.Windows.Forms.Button();
            this.txtPipeName = new System.Windows.Forms.TextBox();
            this.groupBoxServiceAccounts = new System.Windows.Forms.GroupBox();
            this.btnCreateSystem = new System.Windows.Forms.Button();
            this.btnCreateNetworkService = new System.Windows.Forms.Button();
            this.btnCreateLocalService = new System.Windows.Forms.Button();
            this.radioLUS4U = new System.Windows.Forms.RadioButton();
            this.radioLUNormal = new System.Windows.Forms.RadioButton();
            this.txtLUPassword = new System.Windows.Forms.TextBox();
            this.comboBoxS4ULogonType = new System.Windows.Forms.ComboBox();
            this.btnCreteS4U = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.txtS4URealm = new System.Windows.Forms.TextBox();
            this.txtS4UUserName = new System.Windows.Forms.TextBox();
            this.labelUsername = new System.Windows.Forms.Label();
            this.contextMenuStripProcesses = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.openTokenToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.refreshToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.contextMenuStripThreads = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.toolStripMenuItemOpenThreadToken = new System.Windows.Forms.ToolStripMenuItem();
            this.openProcessTokenToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripMenuItemRefreshThreads = new System.Windows.Forms.ToolStripMenuItem();
            this.contextMenuStripSessions = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.openSessionTokenToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.refreshSessionsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.tabPageSessions = new System.Windows.Forms.TabPage();
            this.btnRefreshSessions = new System.Windows.Forms.Button();
            this.listViewSessions = new System.Windows.Forms.ListView();
            this.tabPageThreads = new System.Windows.Forms.TabPage();
            this.listViewThreads = new System.Windows.Forms.ListView();
            this.columnHeaderTID = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderTokenUser = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderImpLevel = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.tabPageProcesses = new System.Windows.Forms.TabPage();
            this.listViewProcesses = new System.Windows.Forms.ListView();
            this.txtFilter = new System.Windows.Forms.TextBox();
            this.btnFilter = new System.Windows.Forms.Button();
            this.checkBoxUnrestricted = new System.Windows.Forms.CheckBox();
            this.btnCurrentProcess = new System.Windows.Forms.Button();
            this.tabControlTests = new System.Windows.Forms.TabControl();
            this.tabPageHandles = new System.Windows.Forms.TabPage();
            this.btnRefreshHandles = new System.Windows.Forms.Button();
            this.listViewHandles = new System.Windows.Forms.ListView();
            this.contextMenuStripHandles = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.toolStripMenuItemHandlesOpenToken = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripMenuItemHandlesRefresh = new System.Windows.Forms.ToolStripMenuItem();
            tabPageServices = new System.Windows.Forms.TabPage();
            groupBoxAnonymous = new System.Windows.Forms.GroupBox();
            groupBox2 = new System.Windows.Forms.GroupBox();
            groupBox1 = new System.Windows.Forms.GroupBox();
            label3 = new System.Windows.Forms.Label();
            tabPageGeneral = new System.Windows.Forms.TabPage();
            groupBoxLogonUser = new System.Windows.Forms.GroupBox();
            label6 = new System.Windows.Forms.Label();
            label2 = new System.Windows.Forms.Label();
            columnHeaderSessionId = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderUserName = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderProcess = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            label4 = new System.Windows.Forms.Label();
            columnHeaderProcessId = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderProcessName = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderProcessUser = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderProcessIL = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderProcessRestricted = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderProcessAC = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderHandleProcessId = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderHandleProcessName = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderHandleUser = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderHandleIL = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderHandleRestricted = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderHandleAC = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderHandleHandle = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderHandleTokenType = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            columnHeaderHandleImpLevel = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            tabPageServices.SuspendLayout();
            groupBoxAnonymous.SuspendLayout();
            groupBox2.SuspendLayout();
            groupBox1.SuspendLayout();
            tabPageGeneral.SuspendLayout();
            this.groupBoxServiceAccounts.SuspendLayout();
            groupBoxLogonUser.SuspendLayout();
            this.contextMenuStripProcesses.SuspendLayout();
            this.contextMenuStripThreads.SuspendLayout();
            this.contextMenuStripSessions.SuspendLayout();
            this.tabPageSessions.SuspendLayout();
            this.tabPageThreads.SuspendLayout();
            this.tabPageProcesses.SuspendLayout();
            this.tabControlTests.SuspendLayout();
            this.tabPageHandles.SuspendLayout();
            this.contextMenuStripHandles.SuspendLayout();
            this.SuspendLayout();
            // 
            // tabPageServices
            // 
            tabPageServices.Controls.Add(groupBoxAnonymous);
            tabPageServices.Controls.Add(groupBox2);
            tabPageServices.Controls.Add(groupBox1);
            tabPageServices.Location = new System.Drawing.Point(4, 25);
            tabPageServices.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            tabPageServices.Name = "tabPageServices";
            tabPageServices.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            tabPageServices.Size = new System.Drawing.Size(803, 492);
            tabPageServices.TabIndex = 4;
            tabPageServices.Text = "Services";
            tabPageServices.UseVisualStyleBackColor = true;
            // 
            // groupBoxAnonymous
            // 
            groupBoxAnonymous.Controls.Add(this.btnCreateAnonymous);
            groupBoxAnonymous.Location = new System.Drawing.Point(8, 207);
            groupBoxAnonymous.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            groupBoxAnonymous.Name = "groupBoxAnonymous";
            groupBoxAnonymous.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            groupBoxAnonymous.Size = new System.Drawing.Size(395, 65);
            groupBoxAnonymous.TabIndex = 3;
            groupBoxAnonymous.TabStop = false;
            groupBoxAnonymous.Text = "Anonymous Token";
            // 
            // btnCreateAnonymous
            // 
            this.btnCreateAnonymous.Location = new System.Drawing.Point(8, 23);
            this.btnCreateAnonymous.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnCreateAnonymous.Name = "btnCreateAnonymous";
            this.btnCreateAnonymous.Size = new System.Drawing.Size(100, 28);
            this.btnCreateAnonymous.TabIndex = 10;
            this.btnCreateAnonymous.Text = "Create";
            this.btnCreateAnonymous.UseVisualStyleBackColor = true;
            this.btnCreateAnonymous.Click += new System.EventHandler(this.btnCreateAnonymous_Click);
            // 
            // groupBox2
            // 
            groupBox2.Controls.Add(this.btnClipboardToken);
            groupBox2.Location = new System.Drawing.Point(8, 134);
            groupBox2.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            groupBox2.Name = "groupBox2";
            groupBox2.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            groupBox2.Size = new System.Drawing.Size(395, 65);
            groupBox2.TabIndex = 2;
            groupBox2.TabStop = false;
            groupBox2.Text = "Win32 Clipboard Token";
            // 
            // btnClipboardToken
            // 
            this.btnClipboardToken.Location = new System.Drawing.Point(8, 23);
            this.btnClipboardToken.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnClipboardToken.Name = "btnClipboardToken";
            this.btnClipboardToken.Size = new System.Drawing.Size(100, 28);
            this.btnClipboardToken.TabIndex = 2;
            this.btnClipboardToken.Text = "Create";
            this.btnClipboardToken.UseVisualStyleBackColor = true;
            this.btnClipboardToken.Click += new System.EventHandler(this.btnClipboardToken_Click);
            // 
            // groupBox1
            // 
            groupBox1.Controls.Add(this.btnPipeConnect);
            groupBox1.Controls.Add(this.btnStartServer);
            groupBox1.Controls.Add(this.txtPipeName);
            groupBox1.Controls.Add(label3);
            groupBox1.Location = new System.Drawing.Point(8, 7);
            groupBox1.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            groupBox1.Name = "groupBox1";
            groupBox1.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            groupBox1.Size = new System.Drawing.Size(395, 119);
            groupBox1.TabIndex = 1;
            groupBox1.TabStop = false;
            groupBox1.Text = "Named Pipe";
            // 
            // btnPipeConnect
            // 
            this.btnPipeConnect.Location = new System.Drawing.Point(145, 76);
            this.btnPipeConnect.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnPipeConnect.Name = "btnPipeConnect";
            this.btnPipeConnect.Size = new System.Drawing.Size(100, 28);
            this.btnPipeConnect.TabIndex = 10;
            this.btnPipeConnect.Text = "Connect";
            this.btnPipeConnect.UseVisualStyleBackColor = true;
            this.btnPipeConnect.Click += new System.EventHandler(this.btnPipeConnect_Click);
            // 
            // btnStartServer
            // 
            this.btnStartServer.Location = new System.Drawing.Point(8, 76);
            this.btnStartServer.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnStartServer.Name = "btnStartServer";
            this.btnStartServer.Size = new System.Drawing.Size(100, 28);
            this.btnStartServer.TabIndex = 9;
            this.btnStartServer.Text = "Start Server";
            this.btnStartServer.UseVisualStyleBackColor = true;
            this.btnStartServer.Click += new System.EventHandler(this.btnStartServer_Click);
            // 
            // txtPipeName
            // 
            this.txtPipeName.Location = new System.Drawing.Point(111, 28);
            this.txtPipeName.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtPipeName.Name = "txtPipeName";
            this.txtPipeName.Size = new System.Drawing.Size(259, 22);
            this.txtPipeName.TabIndex = 8;
            this.txtPipeName.Text = "dummypipe";
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new System.Drawing.Point(8, 32);
            label3.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label3.Name = "label3";
            label3.Size = new System.Drawing.Size(81, 17);
            label3.TabIndex = 7;
            label3.Text = "Pipe Name:";
            // 
            // tabPageGeneral
            // 
            tabPageGeneral.Controls.Add(this.groupBoxServiceAccounts);
            tabPageGeneral.Controls.Add(groupBoxLogonUser);
            tabPageGeneral.Location = new System.Drawing.Point(4, 25);
            tabPageGeneral.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            tabPageGeneral.Name = "tabPageGeneral";
            tabPageGeneral.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            tabPageGeneral.Size = new System.Drawing.Size(803, 492);
            tabPageGeneral.TabIndex = 3;
            tabPageGeneral.Text = "Logon User";
            tabPageGeneral.UseVisualStyleBackColor = true;
            // 
            // groupBoxServiceAccounts
            // 
            this.groupBoxServiceAccounts.Controls.Add(this.btnCreateSystem);
            this.groupBoxServiceAccounts.Controls.Add(this.btnCreateNetworkService);
            this.groupBoxServiceAccounts.Controls.Add(this.btnCreateLocalService);
            this.groupBoxServiceAccounts.Location = new System.Drawing.Point(8, 240);
            this.groupBoxServiceAccounts.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.groupBoxServiceAccounts.Name = "groupBoxServiceAccounts";
            this.groupBoxServiceAccounts.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.groupBoxServiceAccounts.Size = new System.Drawing.Size(411, 63);
            this.groupBoxServiceAccounts.TabIndex = 2;
            this.groupBoxServiceAccounts.TabStop = false;
            this.groupBoxServiceAccounts.Text = "Service Accounts";
            // 
            // btnCreateSystem
            // 
            this.btnCreateSystem.Location = new System.Drawing.Point(295, 23);
            this.btnCreateSystem.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnCreateSystem.Name = "btnCreateSystem";
            this.btnCreateSystem.Size = new System.Drawing.Size(100, 28);
            this.btnCreateSystem.TabIndex = 13;
            this.btnCreateSystem.Text = "System";
            this.btnCreateSystem.UseVisualStyleBackColor = true;
            this.btnCreateSystem.Click += new System.EventHandler(this.btnCreateSystem_Click);
            // 
            // btnCreateNetworkService
            // 
            this.btnCreateNetworkService.Location = new System.Drawing.Point(149, 23);
            this.btnCreateNetworkService.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnCreateNetworkService.Name = "btnCreateNetworkService";
            this.btnCreateNetworkService.Size = new System.Drawing.Size(137, 28);
            this.btnCreateNetworkService.TabIndex = 12;
            this.btnCreateNetworkService.Text = "Network Service";
            this.btnCreateNetworkService.UseVisualStyleBackColor = true;
            this.btnCreateNetworkService.Click += new System.EventHandler(this.btnCreateNetworkService_Click);
            // 
            // btnCreateLocalService
            // 
            this.btnCreateLocalService.Location = new System.Drawing.Point(19, 23);
            this.btnCreateLocalService.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnCreateLocalService.Name = "btnCreateLocalService";
            this.btnCreateLocalService.Size = new System.Drawing.Size(123, 28);
            this.btnCreateLocalService.TabIndex = 11;
            this.btnCreateLocalService.Text = "Local Service";
            this.btnCreateLocalService.UseVisualStyleBackColor = true;
            this.btnCreateLocalService.Click += new System.EventHandler(this.btnCreateLocalService_Click);
            // 
            // groupBoxLogonUser
            // 
            groupBoxLogonUser.Controls.Add(this.radioLUS4U);
            groupBoxLogonUser.Controls.Add(this.radioLUNormal);
            groupBoxLogonUser.Controls.Add(this.txtLUPassword);
            groupBoxLogonUser.Controls.Add(label6);
            groupBoxLogonUser.Controls.Add(this.comboBoxS4ULogonType);
            groupBoxLogonUser.Controls.Add(label2);
            groupBoxLogonUser.Controls.Add(this.btnCreteS4U);
            groupBoxLogonUser.Controls.Add(this.label1);
            groupBoxLogonUser.Controls.Add(this.txtS4URealm);
            groupBoxLogonUser.Controls.Add(this.txtS4UUserName);
            groupBoxLogonUser.Controls.Add(this.labelUsername);
            groupBoxLogonUser.Location = new System.Drawing.Point(8, 7);
            groupBoxLogonUser.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            groupBoxLogonUser.Name = "groupBoxLogonUser";
            groupBoxLogonUser.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            groupBoxLogonUser.Size = new System.Drawing.Size(411, 225);
            groupBoxLogonUser.TabIndex = 0;
            groupBoxLogonUser.TabStop = false;
            groupBoxLogonUser.Text = "Logon User";
            // 
            // radioLUS4U
            // 
            this.radioLUS4U.AutoSize = true;
            this.radioLUS4U.Location = new System.Drawing.Point(120, 23);
            this.radioLUS4U.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.radioLUS4U.Name = "radioLUS4U";
            this.radioLUS4U.Size = new System.Drawing.Size(136, 21);
            this.radioLUS4U.TabIndex = 17;
            this.radioLUS4U.Text = "Services 4 Users";
            this.radioLUS4U.UseVisualStyleBackColor = true;
            this.radioLUS4U.CheckedChanged += new System.EventHandler(this.radioLUS4U_CheckedChanged);
            // 
            // radioLUNormal
            // 
            this.radioLUNormal.AutoSize = true;
            this.radioLUNormal.Checked = true;
            this.radioLUNormal.Location = new System.Drawing.Point(21, 23);
            this.radioLUNormal.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.radioLUNormal.Name = "radioLUNormal";
            this.radioLUNormal.Size = new System.Drawing.Size(74, 21);
            this.radioLUNormal.TabIndex = 16;
            this.radioLUNormal.TabStop = true;
            this.radioLUNormal.Text = "Normal";
            this.radioLUNormal.UseVisualStyleBackColor = true;
            // 
            // txtLUPassword
            // 
            this.txtLUPassword.Location = new System.Drawing.Point(120, 121);
            this.txtLUPassword.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtLUPassword.Name = "txtLUPassword";
            this.txtLUPassword.Size = new System.Drawing.Size(259, 22);
            this.txtLUPassword.TabIndex = 15;
            this.txtLUPassword.UseSystemPasswordChar = true;
            // 
            // label6
            // 
            label6.AutoSize = true;
            label6.Location = new System.Drawing.Point(17, 122);
            label6.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label6.Name = "label6";
            label6.Size = new System.Drawing.Size(73, 17);
            label6.TabIndex = 14;
            label6.Text = "Password:";
            // 
            // comboBoxS4ULogonType
            // 
            this.comboBoxS4ULogonType.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBoxS4ULogonType.FormattingEnabled = true;
            this.comboBoxS4ULogonType.Location = new System.Drawing.Point(120, 153);
            this.comboBoxS4ULogonType.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.comboBoxS4ULogonType.Name = "comboBoxS4ULogonType";
            this.comboBoxS4ULogonType.Size = new System.Drawing.Size(160, 24);
            this.comboBoxS4ULogonType.TabIndex = 11;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new System.Drawing.Point(17, 156);
            label2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label2.Name = "label2";
            label2.Size = new System.Drawing.Size(88, 17);
            label2.TabIndex = 10;
            label2.Text = "Logon Type:";
            // 
            // btnCreteS4U
            // 
            this.btnCreteS4U.Location = new System.Drawing.Point(21, 186);
            this.btnCreteS4U.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnCreteS4U.Name = "btnCreteS4U";
            this.btnCreteS4U.Size = new System.Drawing.Size(100, 28);
            this.btnCreteS4U.TabIndex = 9;
            this.btnCreteS4U.Text = "Create";
            this.btnCreteS4U.UseVisualStyleBackColor = true;
            this.btnCreteS4U.Click += new System.EventHandler(this.btnTestS4U_Click);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(17, 89);
            this.label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(60, 17);
            this.label1.TabIndex = 8;
            this.label1.Text = "Domain:";
            // 
            // txtS4URealm
            // 
            this.txtS4URealm.Location = new System.Drawing.Point(120, 89);
            this.txtS4URealm.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtS4URealm.Name = "txtS4URealm";
            this.txtS4URealm.Size = new System.Drawing.Size(259, 22);
            this.txtS4URealm.TabIndex = 7;
            // 
            // txtS4UUserName
            // 
            this.txtS4UUserName.Location = new System.Drawing.Point(120, 55);
            this.txtS4UUserName.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtS4UUserName.Name = "txtS4UUserName";
            this.txtS4UUserName.Size = new System.Drawing.Size(259, 22);
            this.txtS4UUserName.TabIndex = 6;
            // 
            // labelUsername
            // 
            this.labelUsername.AutoSize = true;
            this.labelUsername.Location = new System.Drawing.Point(17, 59);
            this.labelUsername.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.labelUsername.Name = "labelUsername";
            this.labelUsername.Size = new System.Drawing.Size(77, 17);
            this.labelUsername.TabIndex = 5;
            this.labelUsername.Text = "Username:";
            // 
            // columnHeaderSessionId
            // 
            columnHeaderSessionId.Text = "Session ID";
            columnHeaderSessionId.Width = 81;
            // 
            // columnHeaderUserName
            // 
            columnHeaderUserName.Text = "User Name";
            columnHeaderUserName.Width = 248;
            // 
            // columnHeaderProcess
            // 
            columnHeaderProcess.Text = "Process";
            columnHeaderProcess.Width = 71;
            // 
            // label4
            // 
            label4.AutoSize = true;
            label4.Location = new System.Drawing.Point(145, 14);
            label4.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label4.Name = "label4";
            label4.Size = new System.Drawing.Size(84, 17);
            label4.TabIndex = 3;
            label4.Text = "Name Filter:";
            // 
            // columnHeaderProcessId
            // 
            columnHeaderProcessId.Text = "Process ID";
            // 
            // columnHeaderProcessName
            // 
            columnHeaderProcessName.Text = "Name";
            // 
            // columnHeaderProcessUser
            // 
            columnHeaderProcessUser.Text = "User";
            // 
            // columnHeaderProcessIL
            // 
            columnHeaderProcessIL.Text = "Integrity Level";
            // 
            // columnHeaderProcessRestricted
            // 
            columnHeaderProcessRestricted.Text = "Restricted";
            // 
            // columnHeaderProcessAC
            // 
            columnHeaderProcessAC.Text = "App Container";
            // 
            // columnHeaderHandleProcessId
            // 
            columnHeaderHandleProcessId.Text = "Process ID";
            // 
            // columnHeaderHandleProcessName
            // 
            columnHeaderHandleProcessName.Text = "Name";
            // 
            // columnHeaderHandleUser
            // 
            columnHeaderHandleUser.Text = "User";
            // 
            // columnHeaderHandleIL
            // 
            columnHeaderHandleIL.Text = "Integrity Level";
            // 
            // columnHeaderHandleRestricted
            // 
            columnHeaderHandleRestricted.Text = "Restricted";
            // 
            // columnHeaderHandleAC
            // 
            columnHeaderHandleAC.Text = "App Container";
            // 
            // columnHeaderHandleHandle
            // 
            columnHeaderHandleHandle.Text = "Handle";
            // 
            // columnHeaderHandleTokenType
            // 
            columnHeaderHandleTokenType.Text = "Token Type";
            // 
            // columnHeaderHandleImpLevel
            // 
            columnHeaderHandleImpLevel.Text = "Impersonation Level";
            // 
            // contextMenuStripProcesses
            // 
            this.contextMenuStripProcesses.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.contextMenuStripProcesses.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.openTokenToolStripMenuItem,
            this.refreshToolStripMenuItem});
            this.contextMenuStripProcesses.Name = "contextMenuStripProcesses";
            this.contextMenuStripProcesses.Size = new System.Drawing.Size(158, 52);
            // 
            // openTokenToolStripMenuItem
            // 
            this.openTokenToolStripMenuItem.Name = "openTokenToolStripMenuItem";
            this.openTokenToolStripMenuItem.Size = new System.Drawing.Size(157, 24);
            this.openTokenToolStripMenuItem.Text = "Open Token";
            this.openTokenToolStripMenuItem.Click += new System.EventHandler(this.openTokenToolStripMenuItem_Click);
            // 
            // refreshToolStripMenuItem
            // 
            this.refreshToolStripMenuItem.Name = "refreshToolStripMenuItem";
            this.refreshToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F5;
            this.refreshToolStripMenuItem.Size = new System.Drawing.Size(157, 24);
            this.refreshToolStripMenuItem.Text = "Refresh";
            this.refreshToolStripMenuItem.Click += new System.EventHandler(this.refreshToolStripMenuItem_Click);
            // 
            // contextMenuStripThreads
            // 
            this.contextMenuStripThreads.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.contextMenuStripThreads.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripMenuItemOpenThreadToken,
            this.openProcessTokenToolStripMenuItem,
            this.toolStripMenuItemRefreshThreads});
            this.contextMenuStripThreads.Name = "contextMenuStripProcesses";
            this.contextMenuStripThreads.Size = new System.Drawing.Size(211, 76);
            // 
            // toolStripMenuItemOpenThreadToken
            // 
            this.toolStripMenuItemOpenThreadToken.Name = "toolStripMenuItemOpenThreadToken";
            this.toolStripMenuItemOpenThreadToken.Size = new System.Drawing.Size(210, 24);
            this.toolStripMenuItemOpenThreadToken.Text = "Open Thread Token";
            this.toolStripMenuItemOpenThreadToken.Click += new System.EventHandler(this.toolStripMenuItemOpenThreadToken_Click);
            // 
            // openProcessTokenToolStripMenuItem
            // 
            this.openProcessTokenToolStripMenuItem.Name = "openProcessTokenToolStripMenuItem";
            this.openProcessTokenToolStripMenuItem.Size = new System.Drawing.Size(210, 24);
            this.openProcessTokenToolStripMenuItem.Text = "Open Process Token";
            this.openProcessTokenToolStripMenuItem.Click += new System.EventHandler(this.openProcessTokenToolStripMenuItem_Click);
            // 
            // toolStripMenuItemRefreshThreads
            // 
            this.toolStripMenuItemRefreshThreads.Name = "toolStripMenuItemRefreshThreads";
            this.toolStripMenuItemRefreshThreads.ShortcutKeys = System.Windows.Forms.Keys.F5;
            this.toolStripMenuItemRefreshThreads.Size = new System.Drawing.Size(210, 24);
            this.toolStripMenuItemRefreshThreads.Text = "Refresh";
            this.toolStripMenuItemRefreshThreads.Click += new System.EventHandler(this.refreshToolStripMenuItem_Click);
            // 
            // contextMenuStripSessions
            // 
            this.contextMenuStripSessions.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.contextMenuStripSessions.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.openSessionTokenToolStripMenuItem,
            this.refreshSessionsToolStripMenuItem});
            this.contextMenuStripSessions.Name = "contextMenuStripSessions";
            this.contextMenuStripSessions.Size = new System.Drawing.Size(158, 52);
            // 
            // openSessionTokenToolStripMenuItem
            // 
            this.openSessionTokenToolStripMenuItem.Name = "openSessionTokenToolStripMenuItem";
            this.openSessionTokenToolStripMenuItem.Size = new System.Drawing.Size(157, 24);
            this.openSessionTokenToolStripMenuItem.Text = "Open Token";
            this.openSessionTokenToolStripMenuItem.Click += new System.EventHandler(this.openSessionTokenToolStripMenuItem_Click);
            // 
            // refreshSessionsToolStripMenuItem
            // 
            this.refreshSessionsToolStripMenuItem.Name = "refreshSessionsToolStripMenuItem";
            this.refreshSessionsToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F5;
            this.refreshSessionsToolStripMenuItem.Size = new System.Drawing.Size(157, 24);
            this.refreshSessionsToolStripMenuItem.Text = "Refresh";
            this.refreshSessionsToolStripMenuItem.Click += new System.EventHandler(this.refreshSessionsToolStripMenuItem_Click);
            // 
            // tabPageSessions
            // 
            this.tabPageSessions.Controls.Add(this.btnRefreshSessions);
            this.tabPageSessions.Controls.Add(this.listViewSessions);
            this.tabPageSessions.Location = new System.Drawing.Point(4, 25);
            this.tabPageSessions.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPageSessions.Name = "tabPageSessions";
            this.tabPageSessions.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPageSessions.Size = new System.Drawing.Size(803, 492);
            this.tabPageSessions.TabIndex = 6;
            this.tabPageSessions.Text = "Sessions";
            this.tabPageSessions.UseVisualStyleBackColor = true;
            // 
            // btnRefreshSessions
            // 
            this.btnRefreshSessions.Location = new System.Drawing.Point(8, 4);
            this.btnRefreshSessions.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnRefreshSessions.Name = "btnRefreshSessions";
            this.btnRefreshSessions.Size = new System.Drawing.Size(100, 28);
            this.btnRefreshSessions.TabIndex = 1;
            this.btnRefreshSessions.Text = "Refresh";
            this.btnRefreshSessions.UseVisualStyleBackColor = true;
            this.btnRefreshSessions.Click += new System.EventHandler(this.btnRefreshSessions_Click);
            // 
            // listViewSessions
            // 
            this.listViewSessions.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.listViewSessions.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeaderSessionId,
            columnHeaderUserName});
            this.listViewSessions.ContextMenuStrip = this.contextMenuStripSessions;
            this.listViewSessions.FullRowSelect = true;
            this.listViewSessions.Location = new System.Drawing.Point(0, 34);
            this.listViewSessions.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.listViewSessions.MultiSelect = false;
            this.listViewSessions.Name = "listViewSessions";
            this.listViewSessions.Size = new System.Drawing.Size(795, 450);
            this.listViewSessions.TabIndex = 0;
            this.listViewSessions.UseCompatibleStateImageBehavior = false;
            this.listViewSessions.View = System.Windows.Forms.View.Details;
            this.listViewSessions.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.listView_ColumnClick);
            // 
            // tabPageThreads
            // 
            this.tabPageThreads.Controls.Add(this.listViewThreads);
            this.tabPageThreads.Location = new System.Drawing.Point(4, 25);
            this.tabPageThreads.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPageThreads.Name = "tabPageThreads";
            this.tabPageThreads.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPageThreads.Size = new System.Drawing.Size(803, 492);
            this.tabPageThreads.TabIndex = 5;
            this.tabPageThreads.Text = "Threads";
            this.tabPageThreads.UseVisualStyleBackColor = true;
            // 
            // listViewThreads
            // 
            this.listViewThreads.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeaderProcess,
            this.columnHeaderTID,
            this.columnHeaderTokenUser,
            this.columnHeaderImpLevel});
            this.listViewThreads.ContextMenuStrip = this.contextMenuStripThreads;
            this.listViewThreads.Dock = System.Windows.Forms.DockStyle.Fill;
            this.listViewThreads.FullRowSelect = true;
            this.listViewThreads.Location = new System.Drawing.Point(4, 4);
            this.listViewThreads.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.listViewThreads.Name = "listViewThreads";
            this.listViewThreads.Size = new System.Drawing.Size(795, 484);
            this.listViewThreads.TabIndex = 0;
            this.listViewThreads.UseCompatibleStateImageBehavior = false;
            this.listViewThreads.View = System.Windows.Forms.View.Details;
            this.listViewThreads.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.listView_ColumnClick);
            this.listViewThreads.DoubleClick += new System.EventHandler(this.toolStripMenuItemOpenThreadToken_Click);
            // 
            // columnHeaderTID
            // 
            this.columnHeaderTID.Text = "Thread ID";
            this.columnHeaderTID.Width = 89;
            // 
            // columnHeaderTokenUser
            // 
            this.columnHeaderTokenUser.Text = "User";
            this.columnHeaderTokenUser.Width = 257;
            // 
            // columnHeaderImpLevel
            // 
            this.columnHeaderImpLevel.Text = "Impersonation Level";
            this.columnHeaderImpLevel.Width = 149;
            // 
            // tabPageProcesses
            // 
            this.tabPageProcesses.Controls.Add(this.listViewProcesses);
            this.tabPageProcesses.Controls.Add(this.txtFilter);
            this.tabPageProcesses.Controls.Add(this.btnFilter);
            this.tabPageProcesses.Controls.Add(label4);
            this.tabPageProcesses.Controls.Add(this.checkBoxUnrestricted);
            this.tabPageProcesses.Controls.Add(this.btnCurrentProcess);
            this.tabPageProcesses.Location = new System.Drawing.Point(4, 25);
            this.tabPageProcesses.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPageProcesses.Name = "tabPageProcesses";
            this.tabPageProcesses.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPageProcesses.Size = new System.Drawing.Size(803, 492);
            this.tabPageProcesses.TabIndex = 2;
            this.tabPageProcesses.Text = "Processes";
            this.tabPageProcesses.UseVisualStyleBackColor = true;
            // 
            // listViewProcesses
            // 
            this.listViewProcesses.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.listViewProcesses.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeaderProcessId,
            columnHeaderProcessName,
            columnHeaderProcessUser,
            columnHeaderProcessIL,
            columnHeaderProcessRestricted,
            columnHeaderProcessAC});
            this.listViewProcesses.ContextMenuStrip = this.contextMenuStripProcesses;
            this.listViewProcesses.FullRowSelect = true;
            this.listViewProcesses.Location = new System.Drawing.Point(4, 43);
            this.listViewProcesses.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.listViewProcesses.MultiSelect = false;
            this.listViewProcesses.Name = "listViewProcesses";
            this.listViewProcesses.Size = new System.Drawing.Size(795, 445);
            this.listViewProcesses.TabIndex = 6;
            this.listViewProcesses.UseCompatibleStateImageBehavior = false;
            this.listViewProcesses.View = System.Windows.Forms.View.Details;
            this.listViewProcesses.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.listView_ColumnClick);
            this.listViewProcesses.DoubleClick += new System.EventHandler(this.openTokenToolStripMenuItem_Click);
            // 
            // txtFilter
            // 
            this.txtFilter.Location = new System.Drawing.Point(237, 10);
            this.txtFilter.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtFilter.Name = "txtFilter";
            this.txtFilter.Size = new System.Drawing.Size(185, 22);
            this.txtFilter.TabIndex = 4;
            // 
            // btnFilter
            // 
            this.btnFilter.Location = new System.Drawing.Point(584, 6);
            this.btnFilter.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnFilter.Name = "btnFilter";
            this.btnFilter.Size = new System.Drawing.Size(100, 28);
            this.btnFilter.TabIndex = 5;
            this.btnFilter.Text = "Apply Filter";
            this.btnFilter.UseVisualStyleBackColor = true;
            this.btnFilter.Click += new System.EventHandler(this.btnFilter_Click);
            // 
            // checkBoxUnrestricted
            // 
            this.checkBoxUnrestricted.AutoSize = true;
            this.checkBoxUnrestricted.Location = new System.Drawing.Point(432, 10);
            this.checkBoxUnrestricted.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.checkBoxUnrestricted.Name = "checkBoxUnrestricted";
            this.checkBoxUnrestricted.Size = new System.Drawing.Size(140, 21);
            this.checkBoxUnrestricted.TabIndex = 2;
            this.checkBoxUnrestricted.Text = "Hide Unrestricted";
            this.checkBoxUnrestricted.UseVisualStyleBackColor = true;
            // 
            // btnCurrentProcess
            // 
            this.btnCurrentProcess.Location = new System.Drawing.Point(4, 7);
            this.btnCurrentProcess.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnCurrentProcess.Name = "btnCurrentProcess";
            this.btnCurrentProcess.Size = new System.Drawing.Size(133, 28);
            this.btnCurrentProcess.TabIndex = 1;
            this.btnCurrentProcess.Text = "Current Process";
            this.btnCurrentProcess.UseVisualStyleBackColor = true;
            this.btnCurrentProcess.Click += new System.EventHandler(this.btnCurrentProcess_Click);
            // 
            // tabControlTests
            // 
            this.tabControlTests.Controls.Add(this.tabPageProcesses);
            this.tabControlTests.Controls.Add(this.tabPageThreads);
            this.tabControlTests.Controls.Add(this.tabPageHandles);
            this.tabControlTests.Controls.Add(this.tabPageSessions);
            this.tabControlTests.Controls.Add(tabPageGeneral);
            this.tabControlTests.Controls.Add(tabPageServices);
            this.tabControlTests.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tabControlTests.Location = new System.Drawing.Point(0, 0);
            this.tabControlTests.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabControlTests.Name = "tabControlTests";
            this.tabControlTests.SelectedIndex = 0;
            this.tabControlTests.Size = new System.Drawing.Size(811, 521);
            this.tabControlTests.TabIndex = 0;
            // 
            // tabPageHandles
            // 
            this.tabPageHandles.Controls.Add(this.btnRefreshHandles);
            this.tabPageHandles.Controls.Add(this.listViewHandles);
            this.tabPageHandles.Location = new System.Drawing.Point(4, 25);
            this.tabPageHandles.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPageHandles.Name = "tabPageHandles";
            this.tabPageHandles.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPageHandles.Size = new System.Drawing.Size(803, 492);
            this.tabPageHandles.TabIndex = 7;
            this.tabPageHandles.Text = "Handles";
            this.tabPageHandles.UseVisualStyleBackColor = true;
            // 
            // btnRefreshHandles
            // 
            this.btnRefreshHandles.Location = new System.Drawing.Point(4, 4);
            this.btnRefreshHandles.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnRefreshHandles.Name = "btnRefreshHandles";
            this.btnRefreshHandles.Size = new System.Drawing.Size(100, 28);
            this.btnRefreshHandles.TabIndex = 8;
            this.btnRefreshHandles.Text = "Refresh";
            this.btnRefreshHandles.UseVisualStyleBackColor = true;
            this.btnRefreshHandles.Click += new System.EventHandler(this.btnRefreshHandles_Click);
            // 
            // listViewHandles
            // 
            this.listViewHandles.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.listViewHandles.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            columnHeaderHandleProcessId,
            columnHeaderHandleProcessName,
            columnHeaderHandleHandle,
            columnHeaderHandleUser,
            columnHeaderHandleIL,
            columnHeaderHandleRestricted,
            columnHeaderHandleAC,
            columnHeaderHandleTokenType,
            columnHeaderHandleImpLevel});
            this.listViewHandles.ContextMenuStrip = this.contextMenuStripHandles;
            this.listViewHandles.FullRowSelect = true;
            this.listViewHandles.Location = new System.Drawing.Point(0, 39);
            this.listViewHandles.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.listViewHandles.MultiSelect = false;
            this.listViewHandles.Name = "listViewHandles";
            this.listViewHandles.Size = new System.Drawing.Size(795, 448);
            this.listViewHandles.TabIndex = 7;
            this.listViewHandles.UseCompatibleStateImageBehavior = false;
            this.listViewHandles.View = System.Windows.Forms.View.Details;
            this.listViewHandles.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.listView_ColumnClick);
            this.listViewHandles.DoubleClick += new System.EventHandler(this.listViewHandles_DoubleClick);
            // 
            // contextMenuStripHandles
            // 
            this.contextMenuStripHandles.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.contextMenuStripHandles.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripMenuItemHandlesOpenToken,
            this.toolStripMenuItemHandlesRefresh});
            this.contextMenuStripHandles.Name = "contextMenuStripSessions";
            this.contextMenuStripHandles.Size = new System.Drawing.Size(158, 52);
            // 
            // toolStripMenuItemHandlesOpenToken
            // 
            this.toolStripMenuItemHandlesOpenToken.Name = "toolStripMenuItemHandlesOpenToken";
            this.toolStripMenuItemHandlesOpenToken.Size = new System.Drawing.Size(157, 24);
            this.toolStripMenuItemHandlesOpenToken.Text = "Open Token";
            this.toolStripMenuItemHandlesOpenToken.Click += new System.EventHandler(this.toolStripMenuItemHandlesOpenToken_Click);
            // 
            // toolStripMenuItemHandlesRefresh
            // 
            this.toolStripMenuItemHandlesRefresh.Name = "toolStripMenuItemHandlesRefresh";
            this.toolStripMenuItemHandlesRefresh.ShortcutKeys = System.Windows.Forms.Keys.F5;
            this.toolStripMenuItemHandlesRefresh.Size = new System.Drawing.Size(157, 24);
            this.toolStripMenuItemHandlesRefresh.Text = "Refresh";
            this.toolStripMenuItemHandlesRefresh.Click += new System.EventHandler(this.btnRefreshHandles_Click);
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(811, 521);
            this.Controls.Add(this.tabControlTests);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.Name = "MainForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "Token Viewer";
            this.Load += new System.EventHandler(this.MainForm_Load);
            tabPageServices.ResumeLayout(false);
            groupBoxAnonymous.ResumeLayout(false);
            groupBox2.ResumeLayout(false);
            groupBox1.ResumeLayout(false);
            groupBox1.PerformLayout();
            tabPageGeneral.ResumeLayout(false);
            this.groupBoxServiceAccounts.ResumeLayout(false);
            groupBoxLogonUser.ResumeLayout(false);
            groupBoxLogonUser.PerformLayout();
            this.contextMenuStripProcesses.ResumeLayout(false);
            this.contextMenuStripThreads.ResumeLayout(false);
            this.contextMenuStripSessions.ResumeLayout(false);
            this.tabPageSessions.ResumeLayout(false);
            this.tabPageThreads.ResumeLayout(false);
            this.tabPageProcesses.ResumeLayout(false);
            this.tabPageProcesses.PerformLayout();
            this.tabControlTests.ResumeLayout(false);
            this.tabPageHandles.ResumeLayout(false);
            this.contextMenuStripHandles.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion
        private System.Windows.Forms.ContextMenuStrip contextMenuStripProcesses;
        private System.Windows.Forms.ToolStripMenuItem openTokenToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem refreshToolStripMenuItem;
        private System.Windows.Forms.ContextMenuStrip contextMenuStripThreads;
        private System.Windows.Forms.ToolStripMenuItem toolStripMenuItemOpenThreadToken;
        private System.Windows.Forms.ToolStripMenuItem toolStripMenuItemRefreshThreads;
        private System.Windows.Forms.ToolStripMenuItem openProcessTokenToolStripMenuItem;
        private System.Windows.Forms.ContextMenuStrip contextMenuStripSessions;
        private System.Windows.Forms.ToolStripMenuItem refreshSessionsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem openSessionTokenToolStripMenuItem;
        private System.Windows.Forms.Button btnCreateAnonymous;
        private System.Windows.Forms.Button btnClipboardToken;
        private System.Windows.Forms.Button btnPipeConnect;
        private System.Windows.Forms.Button btnStartServer;
        private System.Windows.Forms.TextBox txtPipeName;
        private System.Windows.Forms.GroupBox groupBoxServiceAccounts;
        private System.Windows.Forms.Button btnCreateSystem;
        private System.Windows.Forms.Button btnCreateNetworkService;
        private System.Windows.Forms.Button btnCreateLocalService;
        private System.Windows.Forms.RadioButton radioLUS4U;
        private System.Windows.Forms.RadioButton radioLUNormal;
        private System.Windows.Forms.TextBox txtLUPassword;
        private System.Windows.Forms.ComboBox comboBoxS4ULogonType;
        private System.Windows.Forms.Button btnCreteS4U;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox txtS4URealm;
        private System.Windows.Forms.TextBox txtS4UUserName;
        private System.Windows.Forms.Label labelUsername;
        private System.Windows.Forms.TabPage tabPageSessions;
        private System.Windows.Forms.Button btnRefreshSessions;
        private System.Windows.Forms.ListView listViewSessions;
        private System.Windows.Forms.TabPage tabPageThreads;
        private System.Windows.Forms.ListView listViewThreads;
        private System.Windows.Forms.ColumnHeader columnHeaderTID;
        private System.Windows.Forms.ColumnHeader columnHeaderTokenUser;
        private System.Windows.Forms.ColumnHeader columnHeaderImpLevel;
        private System.Windows.Forms.TabPage tabPageProcesses;
        private System.Windows.Forms.ListView listViewProcesses;
        private System.Windows.Forms.TextBox txtFilter;
        private System.Windows.Forms.Button btnFilter;
        private System.Windows.Forms.CheckBox checkBoxUnrestricted;
        private System.Windows.Forms.Button btnCurrentProcess;
        private System.Windows.Forms.TabControl tabControlTests;
        private System.Windows.Forms.TabPage tabPageHandles;
        private System.Windows.Forms.Button btnRefreshHandles;
        private System.Windows.Forms.ListView listViewHandles;
        private System.Windows.Forms.ContextMenuStrip contextMenuStripHandles;
        private System.Windows.Forms.ToolStripMenuItem toolStripMenuItemHandlesOpenToken;
        private System.Windows.Forms.ToolStripMenuItem toolStripMenuItemHandlesRefresh;
    }
}

