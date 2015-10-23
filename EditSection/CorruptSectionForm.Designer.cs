namespace EditSection
{
    partial class CorruptSectionForm
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
            System.Windows.Forms.Label label1;
            System.Windows.Forms.Label label2;
            System.Windows.Forms.Button btnOK;
            System.Windows.Forms.Button btnCancel;
            System.Windows.Forms.Label label3;
            System.Windows.Forms.Label label4;
            System.Windows.Forms.Label label6;
            System.Windows.Forms.Label label5;
            System.Windows.Forms.Label label7;
            this.radioRandom = new System.Windows.Forms.RadioButton();
            this.groupBoxRandomCorruption = new System.Windows.Forms.GroupBox();
            this.numericMinimum = new System.Windows.Forms.NumericUpDown();
            this.numericMaximum = new System.Windows.Forms.NumericUpDown();
            this.comboBoxRandomOperation = new System.Windows.Forms.ComboBox();
            this.radioFixed = new System.Windows.Forms.RadioButton();
            this.groupBoxFixedCorruption = new System.Windows.Forms.GroupBox();
            this.comboBoxFixedOperation = new System.Windows.Forms.ComboBox();
            this.numericFixedValue = new System.Windows.Forms.NumericUpDown();
            this.radioString = new System.Windows.Forms.RadioButton();
            this.groupBoxStringCorruption = new System.Windows.Forms.GroupBox();
            this.comboBoxStringOperation = new System.Windows.Forms.ComboBox();
            this.textBoxString = new System.Windows.Forms.TextBox();
            label1 = new System.Windows.Forms.Label();
            label2 = new System.Windows.Forms.Label();
            btnOK = new System.Windows.Forms.Button();
            btnCancel = new System.Windows.Forms.Button();
            label3 = new System.Windows.Forms.Label();
            label4 = new System.Windows.Forms.Label();
            label6 = new System.Windows.Forms.Label();
            label5 = new System.Windows.Forms.Label();
            label7 = new System.Windows.Forms.Label();
            this.groupBoxRandomCorruption.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericMinimum)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.numericMaximum)).BeginInit();
            this.groupBoxFixedCorruption.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericFixedValue)).BeginInit();
            this.groupBoxStringCorruption.SuspendLayout();
            this.SuspendLayout();
            // 
            // radioRandom
            // 
            this.radioRandom.AutoSize = true;
            this.radioRandom.Checked = true;
            this.radioRandom.Location = new System.Drawing.Point(12, 12);
            this.radioRandom.Name = "radioRandom";
            this.radioRandom.Size = new System.Drawing.Size(116, 17);
            this.radioRandom.TabIndex = 0;
            this.radioRandom.TabStop = true;
            this.radioRandom.Text = "Random Corruption";
            this.radioRandom.UseVisualStyleBackColor = true;
            this.radioRandom.CheckedChanged += new System.EventHandler(this.radioRandom_CheckedChanged);
            // 
            // groupBoxRandomCorruption
            // 
            this.groupBoxRandomCorruption.Controls.Add(label3);
            this.groupBoxRandomCorruption.Controls.Add(this.comboBoxRandomOperation);
            this.groupBoxRandomCorruption.Controls.Add(label2);
            this.groupBoxRandomCorruption.Controls.Add(this.numericMaximum);
            this.groupBoxRandomCorruption.Controls.Add(label1);
            this.groupBoxRandomCorruption.Controls.Add(this.numericMinimum);
            this.groupBoxRandomCorruption.Location = new System.Drawing.Point(12, 35);
            this.groupBoxRandomCorruption.Name = "groupBoxRandomCorruption";
            this.groupBoxRandomCorruption.Size = new System.Drawing.Size(353, 71);
            this.groupBoxRandomCorruption.TabIndex = 1;
            this.groupBoxRandomCorruption.TabStop = false;
            this.groupBoxRandomCorruption.Text = "Random Corruption Settings";
            // 
            // numericMinimum
            // 
            this.numericMinimum.Location = new System.Drawing.Point(93, 19);
            this.numericMinimum.Maximum = new decimal(new int[] {
            255,
            0,
            0,
            0});
            this.numericMinimum.Name = "numericMinimum";
            this.numericMinimum.Size = new System.Drawing.Size(49, 20);
            this.numericMinimum.TabIndex = 0;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new System.Drawing.Point(6, 21);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(81, 13);
            label1.TabIndex = 1;
            label1.Text = "Minimum Value:";
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new System.Drawing.Point(6, 45);
            label2.Name = "label2";
            label2.Size = new System.Drawing.Size(84, 13);
            label2.TabIndex = 3;
            label2.Text = "Maximum Value:";
            // 
            // numericMaximum
            // 
            this.numericMaximum.Location = new System.Drawing.Point(93, 43);
            this.numericMaximum.Maximum = new decimal(new int[] {
            255,
            0,
            0,
            0});
            this.numericMaximum.Name = "numericMaximum";
            this.numericMaximum.Size = new System.Drawing.Size(49, 20);
            this.numericMaximum.TabIndex = 2;
            this.numericMaximum.Value = new decimal(new int[] {
            255,
            0,
            0,
            0});
            // 
            // comboBoxRandomOperation
            // 
            this.comboBoxRandomOperation.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBoxRandomOperation.FormattingEnabled = true;
            this.comboBoxRandomOperation.Location = new System.Drawing.Point(221, 18);
            this.comboBoxRandomOperation.Name = "comboBoxRandomOperation";
            this.comboBoxRandomOperation.Size = new System.Drawing.Size(121, 21);
            this.comboBoxRandomOperation.TabIndex = 4;
            // 
            // btnOK
            // 
            btnOK.DialogResult = System.Windows.Forms.DialogResult.OK;
            btnOK.Location = new System.Drawing.Point(98, 270);
            btnOK.Name = "btnOK";
            btnOK.Size = new System.Drawing.Size(75, 23);
            btnOK.TabIndex = 2;
            btnOK.Text = "OK";
            btnOK.UseVisualStyleBackColor = true;
            btnOK.Click += new System.EventHandler(this.btnOK_Click);
            // 
            // btnCancel
            // 
            btnCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            btnCancel.Location = new System.Drawing.Point(194, 270);
            btnCancel.Name = "btnCancel";
            btnCancel.Size = new System.Drawing.Size(75, 23);
            btnCancel.TabIndex = 3;
            btnCancel.Text = "Cancel";
            btnCancel.UseVisualStyleBackColor = true;
            // 
            // radioFixed
            // 
            this.radioFixed.AutoSize = true;
            this.radioFixed.Location = new System.Drawing.Point(12, 112);
            this.radioFixed.Name = "radioFixed";
            this.radioFixed.Size = new System.Drawing.Size(101, 17);
            this.radioFixed.TabIndex = 4;
            this.radioFixed.TabStop = true;
            this.radioFixed.Text = "Fixed Corruption";
            this.radioFixed.UseVisualStyleBackColor = true;
            this.radioFixed.CheckedChanged += new System.EventHandler(this.radioFixed_CheckedChanged);
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new System.Drawing.Point(159, 21);
            label3.Name = "label3";
            label3.Size = new System.Drawing.Size(56, 13);
            label3.TabIndex = 5;
            label3.Text = "Operation:";
            // 
            // groupBoxFixedCorruption
            // 
            this.groupBoxFixedCorruption.Controls.Add(label4);
            this.groupBoxFixedCorruption.Controls.Add(this.comboBoxFixedOperation);
            this.groupBoxFixedCorruption.Controls.Add(label6);
            this.groupBoxFixedCorruption.Controls.Add(this.numericFixedValue);
            this.groupBoxFixedCorruption.Enabled = false;
            this.groupBoxFixedCorruption.Location = new System.Drawing.Point(12, 135);
            this.groupBoxFixedCorruption.Name = "groupBoxFixedCorruption";
            this.groupBoxFixedCorruption.Size = new System.Drawing.Size(353, 50);
            this.groupBoxFixedCorruption.TabIndex = 6;
            this.groupBoxFixedCorruption.TabStop = false;
            this.groupBoxFixedCorruption.Text = "Fixed Corruption Settings";
            // 
            // label4
            // 
            label4.AutoSize = true;
            label4.Location = new System.Drawing.Point(159, 21);
            label4.Name = "label4";
            label4.Size = new System.Drawing.Size(56, 13);
            label4.TabIndex = 5;
            label4.Text = "Operation:";
            // 
            // comboBoxFixedOperation
            // 
            this.comboBoxFixedOperation.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBoxFixedOperation.FormattingEnabled = true;
            this.comboBoxFixedOperation.Location = new System.Drawing.Point(221, 18);
            this.comboBoxFixedOperation.Name = "comboBoxFixedOperation";
            this.comboBoxFixedOperation.Size = new System.Drawing.Size(121, 21);
            this.comboBoxFixedOperation.TabIndex = 4;
            // 
            // label6
            // 
            label6.AutoSize = true;
            label6.Location = new System.Drawing.Point(6, 21);
            label6.Name = "label6";
            label6.Size = new System.Drawing.Size(37, 13);
            label6.TabIndex = 1;
            label6.Text = "Value:";
            // 
            // numericFixedValue
            // 
            this.numericFixedValue.Location = new System.Drawing.Point(93, 19);
            this.numericFixedValue.Maximum = new decimal(new int[] {
            255,
            0,
            0,
            0});
            this.numericFixedValue.Name = "numericFixedValue";
            this.numericFixedValue.Size = new System.Drawing.Size(49, 20);
            this.numericFixedValue.TabIndex = 0;
            // 
            // radioString
            // 
            this.radioString.AutoSize = true;
            this.radioString.Location = new System.Drawing.Point(12, 191);
            this.radioString.Name = "radioString";
            this.radioString.Size = new System.Drawing.Size(103, 17);
            this.radioString.TabIndex = 7;
            this.radioString.TabStop = true;
            this.radioString.Text = "String Corruption";
            this.radioString.UseVisualStyleBackColor = true;
            this.radioString.CheckedChanged += new System.EventHandler(this.radioString_CheckedChanged);
            // 
            // groupBoxStringCorruption
            // 
            this.groupBoxStringCorruption.Controls.Add(this.textBoxString);
            this.groupBoxStringCorruption.Controls.Add(label5);
            this.groupBoxStringCorruption.Controls.Add(this.comboBoxStringOperation);
            this.groupBoxStringCorruption.Controls.Add(label7);
            this.groupBoxStringCorruption.Enabled = false;
            this.groupBoxStringCorruption.Location = new System.Drawing.Point(12, 214);
            this.groupBoxStringCorruption.Name = "groupBoxStringCorruption";
            this.groupBoxStringCorruption.Size = new System.Drawing.Size(353, 50);
            this.groupBoxStringCorruption.TabIndex = 7;
            this.groupBoxStringCorruption.TabStop = false;
            this.groupBoxStringCorruption.Text = "String Corruption Settings";
            // 
            // label5
            // 
            label5.AutoSize = true;
            label5.Location = new System.Drawing.Point(159, 21);
            label5.Name = "label5";
            label5.Size = new System.Drawing.Size(56, 13);
            label5.TabIndex = 5;
            label5.Text = "Operation:";
            // 
            // comboBoxStringOperation
            // 
            this.comboBoxStringOperation.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBoxStringOperation.FormattingEnabled = true;
            this.comboBoxStringOperation.Location = new System.Drawing.Point(221, 18);
            this.comboBoxStringOperation.Name = "comboBoxStringOperation";
            this.comboBoxStringOperation.Size = new System.Drawing.Size(121, 21);
            this.comboBoxStringOperation.TabIndex = 4;
            // 
            // label7
            // 
            label7.AutoSize = true;
            label7.Location = new System.Drawing.Point(6, 21);
            label7.Name = "label7";
            label7.Size = new System.Drawing.Size(37, 13);
            label7.TabIndex = 1;
            label7.Text = "Value:";
            // 
            // textBoxString
            // 
            this.textBoxString.Location = new System.Drawing.Point(42, 18);
            this.textBoxString.Name = "textBoxString";
            this.textBoxString.Size = new System.Drawing.Size(111, 20);
            this.textBoxString.TabIndex = 8;
            // 
            // CorruptSectionForm
            // 
            this.AcceptButton = btnOK;
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.CancelButton = btnCancel;
            this.ClientSize = new System.Drawing.Size(375, 304);
            this.Controls.Add(this.groupBoxStringCorruption);
            this.Controls.Add(this.radioString);
            this.Controls.Add(this.groupBoxFixedCorruption);
            this.Controls.Add(this.radioFixed);
            this.Controls.Add(btnCancel);
            this.Controls.Add(btnOK);
            this.Controls.Add(this.groupBoxRandomCorruption);
            this.Controls.Add(this.radioRandom);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "CorruptSectionForm";
            this.ShowIcon = false;
            this.ShowInTaskbar = false;
            this.Text = "Corrupt Section";
            this.groupBoxRandomCorruption.ResumeLayout(false);
            this.groupBoxRandomCorruption.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericMinimum)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.numericMaximum)).EndInit();
            this.groupBoxFixedCorruption.ResumeLayout(false);
            this.groupBoxFixedCorruption.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericFixedValue)).EndInit();
            this.groupBoxStringCorruption.ResumeLayout(false);
            this.groupBoxStringCorruption.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.RadioButton radioRandom;
        private System.Windows.Forms.NumericUpDown numericMaximum;
        private System.Windows.Forms.NumericUpDown numericMinimum;
        private System.Windows.Forms.ComboBox comboBoxRandomOperation;
        private System.Windows.Forms.GroupBox groupBoxRandomCorruption;
        private System.Windows.Forms.RadioButton radioFixed;
        private System.Windows.Forms.GroupBox groupBoxFixedCorruption;
        private System.Windows.Forms.ComboBox comboBoxFixedOperation;
        private System.Windows.Forms.NumericUpDown numericFixedValue;
        private System.Windows.Forms.RadioButton radioString;
        private System.Windows.Forms.GroupBox groupBoxStringCorruption;
        private System.Windows.Forms.ComboBox comboBoxStringOperation;
        private System.Windows.Forms.TextBox textBoxString;
    }
}