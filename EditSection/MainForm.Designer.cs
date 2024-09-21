namespace EditSection;

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
        System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
        this.dockPanel = new WeifenLuo.WinFormsUI.Docking.DockPanel();
        this.menuStrip = new System.Windows.Forms.MenuStrip();
        this.fileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
        this.openSectionToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
        this.openNamedSectionToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
        this.setNamedEventToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
        this.exitToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
        this.menuStrip.SuspendLayout();
        this.SuspendLayout();
        // 
        // dockPanel
        // 
        this.dockPanel.Dock = System.Windows.Forms.DockStyle.Fill;
        this.dockPanel.Location = new System.Drawing.Point(0, 28);
        this.dockPanel.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
        this.dockPanel.Name = "dockPanel";
        this.dockPanel.Size = new System.Drawing.Size(1189, 605);
        this.dockPanel.TabIndex = 0;
        // 
        // menuStrip
        // 
        this.menuStrip.ImageScalingSize = new System.Drawing.Size(20, 20);
        this.menuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
        this.fileToolStripMenuItem});
        this.menuStrip.Location = new System.Drawing.Point(0, 0);
        this.menuStrip.Name = "menuStrip";
        this.menuStrip.Padding = new System.Windows.Forms.Padding(8, 2, 0, 2);
        this.menuStrip.Size = new System.Drawing.Size(1189, 28);
        this.menuStrip.TabIndex = 2;
        // 
        // fileToolStripMenuItem
        // 
        this.fileToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
        this.openSectionToolStripMenuItem,
        this.openNamedSectionToolStripMenuItem,
        this.setNamedEventToolStripMenuItem,
        this.exitToolStripMenuItem});
        this.fileToolStripMenuItem.Name = "fileToolStripMenuItem";
        this.fileToolStripMenuItem.Size = new System.Drawing.Size(44, 24);
        this.fileToolStripMenuItem.Text = "&File";
        // 
        // openSectionToolStripMenuItem
        // 
        this.openSectionToolStripMenuItem.Name = "openSectionToolStripMenuItem";
        this.openSectionToolStripMenuItem.Size = new System.Drawing.Size(226, 26);
        this.openSectionToolStripMenuItem.Text = "Open Section";
        this.openSectionToolStripMenuItem.Click += new System.EventHandler(this.openSectionToolStripMenuItem_Click);
        // 
        // openNamedSectionToolStripMenuItem
        // 
        this.openNamedSectionToolStripMenuItem.Name = "openNamedSectionToolStripMenuItem";
        this.openNamedSectionToolStripMenuItem.Size = new System.Drawing.Size(226, 26);
        this.openNamedSectionToolStripMenuItem.Text = "Open Named Section";
        this.openNamedSectionToolStripMenuItem.Click += new System.EventHandler(this.openNamedSectionToolStripMenuItem_Click);
        // 
        // setNamedEventToolStripMenuItem
        // 
        this.setNamedEventToolStripMenuItem.Name = "setNamedEventToolStripMenuItem";
        this.setNamedEventToolStripMenuItem.Size = new System.Drawing.Size(226, 26);
        this.setNamedEventToolStripMenuItem.Text = "Set Named Event";
        this.setNamedEventToolStripMenuItem.Click += new System.EventHandler(this.setNamedEventToolStripMenuItem_Click);
        // 
        // exitToolStripMenuItem
        // 
        this.exitToolStripMenuItem.Name = "exitToolStripMenuItem";
        this.exitToolStripMenuItem.Size = new System.Drawing.Size(226, 26);
        this.exitToolStripMenuItem.Text = "E&xit";
        this.exitToolStripMenuItem.Click += new System.EventHandler(this.exitToolStripMenuItem_Click);
        // 
        // MainForm
        // 
        this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
        this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
        this.ClientSize = new System.Drawing.Size(1189, 633);
        this.Controls.Add(this.dockPanel);
        this.Controls.Add(this.menuStrip);
        this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
        this.IsMdiContainer = true;
        this.MainMenuStrip = this.menuStrip;
        this.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
        this.Name = "MainForm";
        this.Text = "Section Editor";
        this.menuStrip.ResumeLayout(false);
        this.menuStrip.PerformLayout();
        this.ResumeLayout(false);
        this.PerformLayout();

    }

    #endregion

    private WeifenLuo.WinFormsUI.Docking.DockPanel dockPanel;
    private System.Windows.Forms.MenuStrip menuStrip;
    private System.Windows.Forms.ToolStripMenuItem fileToolStripMenuItem;
    private System.Windows.Forms.ToolStripMenuItem exitToolStripMenuItem;
    private System.Windows.Forms.ToolStripMenuItem openSectionToolStripMenuItem;
    private System.Windows.Forms.ToolStripMenuItem openNamedSectionToolStripMenuItem;
    private System.Windows.Forms.ToolStripMenuItem setNamedEventToolStripMenuItem;
}

