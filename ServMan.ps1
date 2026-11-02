param ([string]$cmdLine)
$Config = @{
	Title             = 'POS Services Manager'
	Version           = '1.3.0'
}

if ($cmdLine -eq "COMPILE") { 
	if (!(Get-Module -ListAvailable -Name ps2exe)) {
		try {
			Install-Module -Name ps2exe -Scope CurrentUser -Force -ErrorAction SilentlyContinue
		} catch {
			Write-Warning $_
			return
		}
	}
	$iconPath = "$PSScriptRoot\ServMan.ico"
	Invoke-PS2EXE -InputFile $PSCommandPath -x64 -noConsole -verbose -IconFile $iconPath -Title $Config.Title -Product $Config.Title -Copyright 'https://github.com/mozers3' -Company 'mozers™' -Version $Config.Version
	Exit 0
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	if ($PSCommandPath) {
		Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`"" -Verb RunAs
	} else {
		Start-Process ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) -Verb RunAs
	}
	exit
}

# ==============================================================================
$date = Get-Date

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

Add-Type -Namespace '' -Name 'ComPortProbe' -MemberDefinition @'
	[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Auto)]
	public static extern System.IntPtr CreateFile(
		string lpFileName, uint dwDesiredAccess, uint dwShareMode,
		System.IntPtr lpSecurityAttributes, uint dwCreationDisposition,
		uint dwFlagsAndAttributes, System.IntPtr hTemplateFile);
	[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
	public static extern bool CloseHandle(System.IntPtr hObject);
	public const uint GENERIC_READ = 0x80000000;
	public const uint GENERIC_WRITE = 0x40000000;
	public const uint OPEN_EXISTING = 3;
	public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
	public const int ERROR_ACCESS_DENIED = 5;
	public const int ERROR_FILE_NOT_FOUND = 2;
	public const int ERROR_SHARING_VIOLATION = 32;
	public static int ProbePort(string portName) {
		string path = @"\\.\" + portName;
		System.IntPtr h = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0,
			System.IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, System.IntPtr.Zero);
		if (h == new System.IntPtr(-1)) {
			int err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
			if (err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION) return 1;
			if (err == ERROR_FILE_NOT_FOUND) return 2;
			return 3;
		}
		CloseHandle(h);
		return 0;
	}
'@

function Create-Form () {
	function New-ServiceControl([string]$ServiceName) {
		$btnCOM = New-Object System.Windows.Forms.Button -Property @{
			Dock = "Fill"
			Margin = "10, 5, 10, 15"
		}
		$toolTip = New-Object System.Windows.Forms.ToolTip
		$toolTip.SetToolTip($btnCOM, "Содержимое файла конфигурации сервиса`nНажмите для изменения")

		$btnStartStop = New-Object System.Windows.Forms.Button -Property @{
			Size = "40, 36"
			Margin = "10, 5, 10, 15"
		}
		$btnStartStop.Add_Click({
			try {
				if ($btnStartStop.Text -eq "4") {
					[void](Start-Service -Name $ServiceName -ErrorAction Stop)
				} else {
					[void](Stop-Service -Name $ServiceName -Force -ErrorAction Stop -WarningAction SilentlyContinue)
				}
# 				Update-ServiceStatus -ServiceName $ServiceName
			} catch {
				[System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", 'OK', 'Error')
			}
		}.GetNewClosure())
		$txtStatus = New-Object System.Windows.Forms.TextBox -Property @{
			Dock = "Fill"
			TextAlign = "Center"
			Margin = "10, 10, 10, 15"
		}
		$btnLog = New-Object System.Windows.Forms.Button -Property @{
			Dock = "Fill"
			Text = "Log"
			Margin = "10, 5, 10, 15"
		}
		$btnLog.Add_Click({
			if ([System.IO.File]::Exists($this.Tag)) {
				notepad $this.Tag
			} else {
				[System.Windows.Forms.MessageBox]::Show("Log от $($date.ToString('dd.MM.yyyy')) отсутствует!`n(Вероятно, сервис сегодня не запускался)", "Warning", 'OK', 'Warning')
			}
		}.GetNewClosure())

		$tlp = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
			Dock = "Fill"; ColumnCount = 4; RowCount = 1; ForeColor = [System.Drawing.SystemColors]::ControlText
		}
		$ST = [System.Windows.Forms.SizeType]
		[void]$tlp.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new($ST::Absolute, 160))
		[void]$tlp.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new($ST::Absolute, 60))
		[void]$tlp.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new($ST::Percent, 100))
		[void]$tlp.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new($ST::Absolute, 90))
		[void]$tlp.Controls.Add($btnCOM, 0, 0)
		[void]$tlp.Controls.Add($btnStartStop,  1, 0)
		[void]$tlp.Controls.Add($txtStatus, 2, 0)
		[void]$tlp.Controls.Add($btnLog, 3, 0)

		$gb = New-Object System.Windows.Forms.GroupBox -Property @{
			Text = $ServiceName; Dock = "Fill"; Padding = "5, 0, 5, 5"; ForeColor = 'Navy'
		}
		$gb.Controls.Add($tlp)

		[PSCustomObject]@{ GroupBox = $gb; btnCOM = $btnCOM; btnStartStop = $btnStartStop; txtStatus = $txtStatus; btnLog = $btnLog; }
	}

	$form = New-Object System.Windows.Forms.Form -Property @{
		Size = "500, 250"
		StartPosition = "CenterScreen"
		AutoScaleMode = "Font"
		Font = [System.Drawing.Font]::new("Segoe UI", 12)
		Padding = "10, 10, 10, 10"
	}
	if (!$PSCommandPath) {
		$exePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
		$appIcon = [System.Drawing.Icon]::ExtractAssociatedIcon($exePath)
		$form.Icon = $appIcon
	}

	$dgv = New-Object System.Windows.Forms.DataGridView
	$dgv.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
	$dgv.Dock = "Fill"
	$dgv.AutoSizeColumnsMode = "Fill"
	$dgv.AllowUserToAddRows = $false
	$dgv.ReadOnly = $true
	$dgv.SelectionMode = "FullRowSelect"
	$dgv.RowHeadersVisible = $false
	$dgv.BackgroundColor = "White"
	$dgv.DefaultCellStyle.BackColor = "LightCyan"
	$dgv.DefaultCellStyle.SelectionBackColor = "Blue"

	[void]$dgv.Columns.Add([System.Windows.Forms.DataGridViewTextBoxColumn]@{ Name="Status"; HeaderText="Status"; FillWeight=15 })
	[void]$dgv.Columns.Add([System.Windows.Forms.DataGridViewTextBoxColumn]@{ Name="COM"; HeaderText="COM"; FillWeight=15 })
	[void]$dgv.Columns.Add([System.Windows.Forms.DataGridViewTextBoxColumn]@{ Name="VidPid"; HeaderText="Model / VID & PID"; FillWeight=35 })
	[void]$dgv.Columns.Add([System.Windows.Forms.DataGridViewTextBoxColumn]@{ Name="FriendlyName"; HeaderText="FriendlyName"; FillWeight=40 })

# 	$dgv.add_CellFormatting({
# 		param($sender, $e)
# 		if ($e.RowIndex -lt 0) { return }
# 		$statusValue = $sender.Rows[$e.RowIndex].Cells["Status"].Value
# 		if ($statusValue -ne $null -and $statusValue -ne "Free") {
# 			$e.CellStyle.ForeColor = [System.Drawing.Color]::LightCoral
# 			$e.CellStyle.SelectionForeColor = [System.Drawing.Color]::LightCoral
# 		} else {
# 			$e.CellStyle.ForeColor = $sender.DefaultCellStyle.ForeColor
# 			$e.CellStyle.SelectionForeColor = $sender.DefaultCellStyle.SelectionForeColor
# 		}
# 	})

	$dgv.AutoGenerateColumns = $false
	$dgv.Columns["Status"].DataPropertyName = "Status"
	$dgv.Columns["COM"].DataPropertyName = "COM"
	$dgv.Columns["VidPid"].DataPropertyName = "VidPid"
	$dgv.Columns["FriendlyName"].DataPropertyName = "FriendlyName"

# 	$dt = New-Object System.Data.DataTable
# 	[void]$dt.Columns.Add("Status", [string])
# 	[void]$dt.Columns.Add("COM", [string])
# 	[void]$dt.Columns.Add("VidPid", [string])
# 	[void]$dt.Columns.Add("FriendlyName", [string])

# 	$dgv.DataSource = $dt

	$gbTop = New-Object System.Windows.Forms.GroupBox -Property @{
		Dock = "Fill"
		Padding = "15, 5, 15, 15"
		Text = "COM Ports"
		ForeColor = 'Navy'
	}
	$gbTop.Controls.Add($dgv)

	$bottom = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
		Dock = "Bottom"; Height = 180; ColumnCount = 1; RowCount = 2
	}
	$ST = [System.Windows.Forms.SizeType]
	[void]$bottom.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new($ST::Percent, 100))
	[void]$bottom.RowStyles.Add([System.Windows.Forms.RowStyle]::new($ST::Percent, 50))
	[void]$bottom.RowStyles.Add([System.Windows.Forms.RowStyle]::new($ST::Percent, 50))

	$srvCtrlPBF = New-ServiceControl 'PBF Proxy Service'
	$srvCtrlDC = New-ServiceControl '"Dual Connector Service"'
	$srvCtrlPBF.GroupBox.Margin = "0, 5, 0, 5"
	$srvCtrlDC.GroupBox.Margin = "0, 5, 0, 0"
	[void]$bottom.Controls.Add($srvCtrlPBF.GroupBox, 0, 0)
	[void]$bottom.Controls.Add($srvCtrlDC.GroupBox, 0, 1)

	[void]$form.Controls.Add($gbTop)
	[void]$form.Controls.Add($bottom)

# 	$form.Tag = @{ Dt = $dt; Dgv = $dgv; SrvCtrlPBF = $srvCtrlPBF; SrvCtrlDC = $srvCtrlDC }
	$form.Tag = @{ Dgv = $dgv; SrvCtrlPBF = $srvCtrlPBF; SrvCtrlDC = $srvCtrlDC }

	return $form
}

function List-COM-Ports() {
	try {
		$ports = Get-PnpDevice -Class Ports -Status OK -ErrorAction Stop 
	} catch { $ports = @() }

	$Data = New-Object System.Collections.Generic.List[object]
	foreach ($p in $ports) {
		if ($p.Name -match '(.+)\((COM\d+)\)') {
			$friendlyName = $matches[1]
			$com = $matches[2]
		} else {continue}

		if ($p.DeviceID.ToUpper() -match 'VID_[0-9A-F]{4}&PID_[0-9A-F]{4}') {
			$vidPid = $matches[0]
		} else {continue}

		$status = switch ([ComPortProbe]::ProbePort($com)) {
			0       { 'Free' }
			1       { 'Busy' }
			2       { 'Missing' }
			default { 'Unknown' }
		}

		$map = @{
			'VID_1782&PID_5D30' = 'UniTodi P8 Bio'
			'VID_1A86&PID_7523' = 'Aisino A99 Lite'
			'VID_1234&PID_0101' = 'PAX Q25'
			'VID_2FB8&PID_1101' = 'PAX D230'
			'VID_2FB8&PID_3101' = 'PAX S210 Pinpad'
		}
		$model = $map[$VidPid]
		if (-not $model) { $model = $VidPid }

		[void]$Data.Add([PSCustomObject]@{
			Status       = $status
			COM          = $com
			VidPid       = $model
			FriendlyName = $friendlyName
		})
	}

	return $Data.ToArray()
}

function Update-GridViev ($dgv, $listCOMports) {
	$dgv.SuspendLayout()
	foreach ($row in $dgv.Rows) { $row.Tag = "ToDelete" }
	foreach ($port in $listCOMports) {
		$found = $false
		# Ищем, есть ли уже строка с таким COM-портом
		foreach ($row in $dgv.Rows) {
			if ($row.Cells["COM"].Value -eq $port.COM) {
				# Строка существует: обновляем только данные, объект строки остается тем же!
				$row.Cells["Status"].Value = $port.Status
				$row.Cells["VidPid"].Value = $port.VidPid
				$row.Cells["FriendlyName"].Value = $port.FriendlyName

				if ($port.Status -ne "Free") {
					$row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::LightCoral
					$row.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::LightCoral
				} else {
					$row.DefaultCellStyle = New-Object System.Windows.Forms.DataGridViewCellStyle
				}

				$row.Tag = "Keep" # Снимаем метку удаления
				$found = $true
				break
			}
		}
		# Если порта не было в таблице, добавляем новую строку
		if (-not $found) {
			$dgv.Rows.Add($port.Status, $port.COM, $port.VidPid, $port.FriendlyName)
		}
	}
	# 3. Удаляем только те строки, которые остались с меткой "ToDelete" (устройства отключились)
	for ($i = $dgv.Rows.Count - 1; $i -ge 0; $i--) {
		if ($dgv.Rows[$i].Tag -eq "ToDelete") {
			$dgv.Rows.RemoveAt($i)
		}
	}

	$dgv.ResumeLayout()
}

function Update-ServiceStatus($svControl) {
	$svName = $svControl.GroupBox.Text
	$sv = Get-Service -Name $svName -ErrorAction SilentlyContinue

	if (-not $sv) {
		if ($svControl.TxtStatus.Text -ne "Service not found!") {
			$svControl.TxtStatus.Text = "Service not found!"
			$svControl.TxtStatus.BackColor = 'Red'
			$svControl.BtnStartStop.Enabled = $false
			$svControl.BtnCOM.Enabled = $false
			$svControl.BtnLog.Enabled = $false
		}
		return
	}

	$currentStatus = $sv.Status.ToString()

	if ($svControl.TxtStatus.Text -ne $currentStatus) {
		$svControl.TxtStatus.Text = $currentStatus
		switch ($currentStatus) {
			'Running' { 
				$svControl.TxtStatus.BackColor = 'LightGreen'
				$svControl.BtnStartStop.Text = 'g'
				$svControl.BtnStartStop.Font = "Marlett, 20"
				$svControl.BtnStartStop.ForeColor = 'Red'
			}
			'Stopped' { 
				$svControl.TxtStatus.BackColor = 'LightGray'
				$svControl.BtnStartStop.Text = '4'
				$svControl.BtnStartStop.Font = "Marlett, 24"
				$svControl.BtnStartStop.ForeColor = 'Green'
			}
			'StartPending' { 
				$svControl.TxtStatus.BackColor = 'LightYellow'
			}
			'StopPending' { 
				$svControl.TxtStatus.BackColor = 'LightYellow'
			}
		}
	}
}

function IniContent {
	param(
		[Parameter(Mandatory)][string]$FilePath,
		[hashtable]$Config
	)

	if ($Config) {
		# Запись: собираем INI из хэш-таблицы
		$out = foreach ($s in $Config.Keys) {
			"[$s]"
			foreach ($k in $Config[$s].Keys) { "$k=$($Config[$s][$k])" }
			""
		}
		Set-Content -Path $FilePath -Value $out -Encoding UTF8
		return
	}

	# Чтение: разбираем INI в хэш-таблицу
	$ini = @{}
	$section = 'NoSection'
	switch -regex -file $FilePath {
		'^\s*\[(.+)\]\s*$'        { $section = $matches[1].Trim(); $ini[$section] = @{} }
		'^\s*([^=;]+?)\s*=\s*(.*)' {
			if (-not $ini[$section]) { $ini[$section] = @{} }
			$ini[$section][$matches[1].Trim()] = $matches[2].Trim()
		}
	}
	return $ini
}

function Get-ServiceFiles($ServiceName) {
	$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
	if (-not $svc) {return ""}

	switch ($ServiceName) {
		'PBF Proxy Service' {
			$imagePath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName").ImagePath
			$servicePath = $imagePath -replace '^"?(.+)\\.*', '$1'
			$inifile = "$servicePath\config.ini"
			if ([System.IO.File]::Exists($inifile)) {
				$config = IniContent -FilePath $inifile
				$port = $config["SerialPort"]["name"]
				$dVid = $config["SerialPort"]["vid"]
				$dPid = $config["SerialPort"]["pid"]
				if ($dVid -eq "1782" -and $dPid -eq "5D30") {$model = 'P8'}
				elseif ($dVid -eq "1A86" -and $dPid -eq "7523") {$model = 'A99'}
				else {$model = '???'}
				$frmMain.Tag.SrvCtrlPBF.btnCOM.Text = "$model / $port"
				$frmMain.Tag.SrvCtrlPBF.btnCOM.Tag = $inifile
			} else {
				[System.Windows.Forms.MessageBox]::Show("Файл конфигурации`n$inifile`nотсутствует!", "Warning", 'OK', 'Warning')
			}
			$frmMain.Tag.SrvCtrlPBF.btnLog.Tag = "$servicePath\pbfproxy_$($date.ToString('yyyy-MM-dd')).log"
		}
		'"Dual Connector Service"' {
			$imagePath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DCService").ImagePath
# 			$servicePath = ($imagePath -replace '"', '') -replace '\\bin\\.*', ''
# 			$servicePath = ($imagePath -split '\\bin\\')[0].Trim('"')
			$servicePath = $imagePath -replace '^"?(.+)\\bin\\.*', '$1'
			$xmlfile = "$servicePath\config\Connector.xml"
			if ([System.IO.File]::Exists($xmlfile)) {
				$port = (Select-Xml -Path $xmlfile -XPath '//CONNECTION_PORT').Node.InnerText
				$frmMain.Tag.SrvCtrlDC.btnCOM.Text = $port
				$frmMain.Tag.SrvCtrlDC.btnCOM.Tag = $xmlfile
			} else {
				[System.Windows.Forms.MessageBox]::Show("Файл конфигурации`n$xmlfile`nотсутствует!", "Warning", 'OK', 'Warning')
			}
			$frmMain.Tag.SrvCtrlDC.btnLog.Tag = "$servicePath\log\Connector$($date.ToString('yyyyMMdd')).log"
		}
	}
}

# ==============================================================================
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 2000

$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new('List-COM-Ports', ${function:List-COM-Ports}))
$iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new('Update-GridViev', ${function:Update-GridViev}))
$iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new('Update-ServiceStatus', ${function:Update-ServiceStatus}))

$runspacePool = [runspacefactory]::CreateRunspacePool(1, 1, $iss, $Host)
$runspacePool.Open()

$timer.Add_Tick({
	$ps = [powershell]::Create()
	$ps.RunspacePool = $runspacePool

	$ps.AddScript({
		param($FormRef)
		if ($null -eq $FormRef -or $FormRef.IsDisposed) { return }
		$listCOMports = @(List-COM-Ports)
		if ($FormRef.IsHandleCreated) {
			$FormRef.Invoke([action]{
				Update-GridViev $FormRef.Tag.Dgv $listCOMports
				Update-ServiceStatus $FormRef.Tag.SrvCtrlPBF
				Update-ServiceStatus $FormRef.Tag.SrvCtrlDC
			})
		}
	}).AddArgument($frmMain)

	$null = $ps.BeginInvoke()

	Register-ObjectEvent -InputObject $ps -EventName InvocationStateChanged -Action {
		if ($Event.SourceEventArgs.InvocationStateInfo.State -eq 'Completed') {
			$Event.MessageData.Dispose()
			Unregister-Event -SourceIdentifier $EventSubscriber.SourceIdentifier
		}
	} -MessageData $ps | Out-Null
})

# ==============================================================================
$frmMain = Create-Form
$frmMain.Text = "$($Config.Title) v$($Config.Version)"

$frmMain.Add_Shown({
	$frmMain.Activate()
	Get-ServiceFiles 'PBF Proxy Service'
	Get-ServiceFiles '"Dual Connector Service"'
	$timer.Start()
})

$frmMain.Add_FormClosing({
	$timer.Stop()
	$timer.Dispose()
	Get-EventSubscriber -ErrorAction SilentlyContinue | 
		Where-Object { $_.SourceIdentifier -match 'InvocationStateChanged' } | 
		Unregister-Event -ErrorAction SilentlyContinue
	if ($runspacePool) {
		$runspacePool.Close()
		$runspacePool.Dispose()
	}
	Start-Sleep -Milliseconds 500
})

# ==============================================================================
$frmMain.Tag.SrvCtrlPBF.btnCOM.Add_Click({
	$inifile = $this.Tag
	if (!$frmMain.Tag.Dgv.CurrentRow) {return}
	$port = $frmMain.Tag.Dgv.CurrentRow.Cells[1].Value
	$model = $frmMain.Tag.Dgv.CurrentRow.Cells[2].Value
	switch ($model) {
		'UniTodi P8 Bio' { $dVID = "1782"; $dPID = "5D30"; $speed = "115200" }
		'Aisino A99 Lite' { $dVID = "1A86"; $dPID = "7523"; $speed = "460800" }
	}
	if (-not $dVID) {
		[System.Windows.Forms.MessageBox]::Show("Задаю параметры только для`nUniTodi P8 Bio`nAisino A99 Lite", "Warning", 'OK', 'Warning')
		return
	}
	if ([System.Windows.Forms.MessageBox]::Show("Изменить конфигурацию сервиса для $model ?`nБудут заданы name=$port, VID=$dVID, PID=$dPID, speed=$speed", "Подтверждение", "YesNo", "Question") -eq "Yes") {
		Stop-Service -Name 'PBF Proxy Service' -Force -ErrorAction Stop -WarningAction SilentlyContinue
		$config = IniContent -FilePath $inifile
		$config["SerialPort"]["name"] = $port
		$config["SerialPort"]["vid"] = $dVid
		$config["SerialPort"]["pid"] = $dPid
		$config["SerialPort"]["speed"] = $speed
		IniContent -FilePath $inifile -Config $config
		Get-ServiceFiles 'PBF Proxy Service'
	}
})

$frmMain.Tag.SrvCtrlDC.btnCOM.Add_Click({
	$xmlfile = $this.Tag
	$port = $frmMain.Tag.Dgv.CurrentRow.Cells[1].Value
	$model = $frmMain.Tag.Dgv.CurrentRow.Cells[2].Value
	if ([System.Windows.Forms.MessageBox]::Show("Изменить конфигурацию сервиса?`nБудет задан CONNECTION_PORT $port", "Подтверждение", "YesNo", "Question") -eq "Yes") {
		Stop-Service -Name '"Dual Connector Service"' -Force -ErrorAction Stop -WarningAction SilentlyContinue
		(Get-Content $xmlfile -Raw) -replace '(?<=<CONNECTION_PORT>).*?(?=</CONNECTION_PORT>)', $port | Set-Content $xmlfile -Encoding UTF8
		Get-ServiceFiles '"Dual Connector Service"'
	}
})

[void]$frmMain.ShowDialog()