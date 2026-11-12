param ([string]$cmdLine)
$Config = @{
	Title             = 'POS Services Manager'
	Version           = '1.7.1'
	ServerUrl         = 'https://raw.githubusercontent.com/mozers3/POS-Services-Manager/main'
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
	Invoke-PS2EXE -InputFile $PSCommandPath -x86 -noConsole -verbose -IconFile $iconPath -Title $Config.Title -Product $Config.Title -Copyright 'https://github.com/mozers3' -Company 'mozers™' -Version $Config.Version
	$exePath = [System.IO.Path]::ChangeExtension($PSCommandPath, '.exe')
	$hash = (Get-FileHash -Path $exePath -Algorithm MD5).Hash
	Set-Content -Path "version" -Value "$($Config.Version)*$hash"
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
$Date = Get-Date
$Service = @{
	DC  = '"Dual Connector Service"'
	PBF = 'PBF Proxy Service'
	OFD = 'OFD Proxy Service'
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class Win32 {
	[DllImport("user32.dll", CharSet = CharSet.Auto)]
	public static extern IntPtr SendMessage(IntPtr hWnd, int wMsg, bool wParam, int lParam);

	public const int WM_SETREDRAW = 0x000B;
}
"@

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

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

public class HiddenUsbCleaner {
	[DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
	static extern IntPtr SetupDiGetClassDevs(ref Guid ClassGuid, string Enumerator, IntPtr hwndParent, uint Flags);

	[DllImport("setupapi.dll", SetLastError = true)]
	static extern bool SetupDiEnumDeviceInfo(IntPtr DeviceInfoSet, uint MemberIndex, ref SP_DEVINFO_DATA DeviceInfoData);

	[DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
	static extern bool SetupDiGetDeviceInstanceId(IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData, StringBuilder DeviceInstanceId, int DeviceInstanceIdSize, out int RequiredSize);

	[DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
	static extern bool SetupDiGetDeviceRegistryProperty(IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData, uint Property, out uint PropertyRegDataType, byte[] PropertyBuffer, uint PropertyBufferSize, out uint RequiredSize);

	[DllImport("setupapi.dll", SetLastError = true)]
	static extern bool SetupDiRemoveDevice(IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData);

	[DllImport("setupapi.dll", SetLastError = true)]
	static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

	[StructLayout(LayoutKind.Sequential)]
	public struct SP_DEVINFO_DATA {
		public uint cbSize;
		public Guid ClassGuid;
		public uint DevInst;
		public IntPtr Reserved;
	}

	const uint DIGCF_PRESENT = 0x00000002;
	const uint SPDRP_FRIENDLYNAME = 0x0000000C;

	private static readonly Guid PortsClassGuid = new Guid("{4D36E978-E325-11CE-BFC1-08002BE10318}");

	public static List<string> Clean() {
		List<string> removedDevices = new List<string>();
		Guid classGuid = PortsClassGuid;
		HashSet<int> activeComPorts = new HashSet<int>();

		IntPtr hDevInfoPresent = SetupDiGetClassDevs(ref classGuid, null, IntPtr.Zero, DIGCF_PRESENT);
		if (hDevInfoPresent != IntPtr.Zero && hDevInfoPresent != new IntPtr(-1)) {
			SP_DEVINFO_DATA devInfoPresent = new SP_DEVINFO_DATA();
			devInfoPresent.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));

			for (uint i = 0; SetupDiEnumDeviceInfo(hDevInfoPresent, i, ref devInfoPresent); i++) {
				string friendlyName = GetRegistryString(hDevInfoPresent, ref devInfoPresent, SPDRP_FRIENDLYNAME);
				if (!string.IsNullOrEmpty(friendlyName)) {
					Match match = Regex.Match(friendlyName, @"(?:\(|\s)(COM)(\d+)(?:\)|\s|$)", RegexOptions.IgnoreCase);
					if (match.Success) {
						int comNum;
						if (int.TryParse(match.Groups[2].Value, out comNum)) {
							activeComPorts.Add(comNum);
						}
					}
				}
			}
			SetupDiDestroyDeviceInfoList(hDevInfoPresent);
		}

		IntPtr hDevInfoAll = SetupDiGetClassDevs(ref classGuid, null, IntPtr.Zero, 0);
		if (hDevInfoAll != IntPtr.Zero && hDevInfoAll != new IntPtr(-1)) {
			SP_DEVINFO_DATA devInfoAll = new SP_DEVINFO_DATA();
			devInfoAll.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));

			for (uint i = 0; SetupDiEnumDeviceInfo(hDevInfoAll, i, ref devInfoAll); i++) {
				string instanceId = GetInstanceId(hDevInfoAll, ref devInfoAll);
				if (string.IsNullOrEmpty(instanceId)) continue;

				if (!IsDevicePresent(hDevInfoAll, ref devInfoAll, classGuid, instanceId) && IsUsbDevice(instanceId)) {
					if (SetupDiRemoveDevice(hDevInfoAll, ref devInfoAll)) {
						removedDevices.Add(instanceId);
					}
				}
			}
			SetupDiDestroyDeviceInfoList(hDevInfoAll);
		}

		FreeUnusedComPorts(activeComPorts);
		return removedDevices;
	}

	private static bool IsDevicePresent(IntPtr hDevInfoAll, ref SP_DEVINFO_DATA devInfoAll, Guid classGuid, string targetInstanceId) {
		IntPtr hDevInfoPresent = SetupDiGetClassDevs(ref classGuid, null, IntPtr.Zero, DIGCF_PRESENT);
		bool found = false;
		if (hDevInfoPresent != IntPtr.Zero && hDevInfoPresent != new IntPtr(-1)) {
			SP_DEVINFO_DATA devInfoPresent = new SP_DEVINFO_DATA();
			devInfoPresent.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
			for (uint i = 0; SetupDiEnumDeviceInfo(hDevInfoPresent, i, ref devInfoPresent); i++) {
				if (GetInstanceId(hDevInfoPresent, ref devInfoPresent) == targetInstanceId) {
					found = true;
					break;
				}
			}
			SetupDiDestroyDeviceInfoList(hDevInfoPresent);
		}
		return found;
	}

	private static bool IsUsbDevice(string instanceId) {
		return instanceId.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase) ||
				instanceId.StartsWith("FTDIBUS\\", StringComparison.OrdinalIgnoreCase) ||
				instanceId.StartsWith("USBVID_", StringComparison.OrdinalIgnoreCase);
	}

	private static string GetInstanceId(IntPtr hDevInfo, ref SP_DEVINFO_DATA devInfoData) {
		int requiredSize = 0;
		SetupDiGetDeviceInstanceId(hDevInfo, ref devInfoData, null, 0, out requiredSize);
		if (requiredSize == 0) return null;

		StringBuilder sb = new StringBuilder(requiredSize);
		if (SetupDiGetDeviceInstanceId(hDevInfo, ref devInfoData, sb, sb.Capacity, out requiredSize)) {
			return sb.ToString();
		}
		return null;
	}

	private static string GetRegistryString(IntPtr hDevInfo, ref SP_DEVINFO_DATA devInfoData, uint property) {
		uint propertyType;
		uint requiredSize;
		int bufferSize = 1024;
		byte[] buffer = new byte[bufferSize];

		if (SetupDiGetDeviceRegistryProperty(hDevInfo, ref devInfoData, property, out propertyType, buffer, (uint)bufferSize, out requiredSize)) {
			return Encoding.Unicode.GetString(buffer).TrimEnd('\0');
		}
		return null;
	}

	private static void FreeUnusedComPorts(HashSet<int> activeComPorts) {
		try {
			using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\COM Name Arbiter", true)) {
				if (key == null) return;

				byte[] comDb = (byte[])key.GetValue("ComDB");
				if (comDb == null || comDb.Length == 0) return;

				bool modified = false;
				for (int i = 0; i < comDb.Length; i++) {
					for (int bit = 0; bit < 8; bit++) {
						int comNumber = (i * 8) + bit + 1;
						bool isMarkedAsUsed = (comDb[i] & (1 << bit)) != 0;

						if (isMarkedAsUsed && !activeComPorts.Contains(comNumber)) {
							comDb[i] &= (byte)~(1 << bit);
							modified = true;
						}
					}
				}

				if (modified) {
					key.SetValue("ComDB", comDb, RegistryValueKind.Binary);
				}
			}
		} catch {}
	}
}
'@ -Language CSharp -ErrorAction Stop

function Get-Update {
	if ($PSCommandPath) {
		$currentPath = $PSCommandPath
		$scriptDir = $PSScriptRoot
	} else {
		$currentPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
		$scriptDir = Split-Path $currentPath
	}
	$baseName = [System.IO.Path]::GetFileNameWithoutExtension($currentPath)

	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
	$ProgressPreference = 'SilentlyContinue'

	$remoteVersion = $null
	$headers = @{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' }
	$versionUrl = "$($Config.ServerUrl)/version?t=$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
	try {
		$response = Invoke-WebRequest -Uri $versionUrl -TimeoutSec 3 -UseBasicParsing -Headers $headers -ErrorAction Stop
		$remoteVersion = $response.Content.Trim()
	} catch {
		return $null
	}

	if ([string]::IsNullOrEmpty($remoteVersion)) { return $null }
	$ver, $hash = $remoteVersion.Split('*')
	if ($ver -eq $Config.Version) { return $null }

	$msg = "Доступна новая версия приложения: $ver`n`nЗагрузить и установить?"
	$result = [System.Windows.Forms.MessageBox]::Show($msg, "$($Config.Title) $($Config.Version)", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
	if ($result -ne 'Yes') { return $null }

	$newExePath = Join-Path $scriptDir "${baseName}_new.exe"
	$downloadUrl = "$($Config.ServerUrl)/$baseName.exe"

	try {
		Invoke-WebRequest -Uri $downloadUrl -OutFile $newExePath -UseBasicParsing -ErrorAction Stop
	} catch {
		return "Ошибка загрузки файла:`n$($_.Exception.Message)"
	}

	if (!(Test-Path $newExePath)) { return "Файл не был сохранен на диск." }
	if ($hash -ne (Get-FileHash -Path $newExePath -Algorithm MD5).Hash) {
		Remove-Item $newExePath -Force -ErrorAction Stop
		return "Скачан битый файл."
	}

	$updateLogic = @"
`$appDir = '$scriptDir'
`$baseName = '$baseName'
`$appExe = Join-Path `$appDir "`$baseName.exe"
`$newAppExe = Join-Path `$appDir "`${baseName}_new.exe"

`$timeout = 20
while ((Get-Process -Name `$baseName -ErrorAction SilentlyContinue) -and `$timeout -gt 0) {
	Start-Sleep -Milliseconds 500
	`$timeout--
}
Start-Sleep -Seconds 1

try {
	Remove-Item `$appExe -Force -ErrorAction Stop
	Rename-Item `$newAppExe "`$baseName.exe" -Force -ErrorAction Stop
	Start-Process `$appExe -WorkingDirectory `$appDir
} catch {
	Add-Type -AssemblyName System.Windows.Forms
	[void][System.Windows.Forms.MessageBox]::Show("Ошибка при установке обновления:`n`$_", "Ошибка", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
}
exit
"@

	$bytes = [System.Text.Encoding]::Unicode.GetBytes($updateLogic)
	$encodedCommand = [Convert]::ToBase64String($bytes)
	$psArgs = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"

	Start-Process powershell.exe -ArgumentList $psArgs -WindowStyle Hidden
	exit 
}

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
					[void](Start-Service -Name $ServiceName -ErrorAction Stop -WarningAction SilentlyContinue)
				} else {
					[void](Stop-Service -Name $ServiceName -Force -ErrorAction Stop -WarningAction SilentlyContinue)
				}
			} catch {
				[System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", 'OK', 'Error')
			}
		}.GetNewClosure())

		$txtStatus = New-Object System.Windows.Forms.TextBox -Property @{
			Dock = "Fill"
			TextAlign = "Center"
			Margin = "10, 10, 10, 15"
		}

		$btnTestApp = New-Object System.Windows.Forms.Button -Property @{
			Dock = "Fill"
			Text = "Test"
			Margin = "10, 5, 10, 15"
		}
		$btnTestApp.Add_Click({
			Start-Process -FilePath $this.Tag
		}.GetNewClosure())
		$btnTestAppToolTip = if ($ServiceName -eq $Service.DC) { "DC Control"} else { "POS Connector"}
		$toolTip.SetToolTip($btnTestApp, $btnTestAppToolTip)

		$btnLog = New-Object System.Windows.Forms.Button -Property @{
			Dock = "Fill"
			Text = "Log"
			Margin = "10, 5, 10, 15"
		}
		$btnLog.Add_Click({
			if ([System.IO.File]::Exists($this.Tag)) {
				Start-Process -FilePath notepad -ArgumentList $this.Tag
			} else {
				[System.Windows.Forms.MessageBox]::Show("Log от $($Date.ToString('dd.MM.yyyy')) отсутствует!`n(Вероятно, сервис сегодня не запускался)", "Warning", 'OK', 'Warning')
			}
		}.GetNewClosure())

		$tlp = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
			Dock = "Fill"; ColumnCount = 5; RowCount = 1; ForeColor = [System.Drawing.SystemColors]::ControlText
		}
		$ST = [System.Windows.Forms.SizeType]
		[void]$tlp.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new($ST::Absolute, 160))
		[void]$tlp.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new($ST::Absolute, 60))
		[void]$tlp.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new($ST::Percent, 100))
		[void]$tlp.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new($ST::Absolute, 90))
		[void]$tlp.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new($ST::Absolute, 90))
		[void]$tlp.Controls.Add($btnCOM, 0, 0)
		[void]$tlp.Controls.Add($btnStartStop,  1, 0)
		[void]$tlp.Controls.Add($txtStatus, 2, 0)
		[void]$tlp.Controls.Add($btnTestApp, 3, 0)
		[void]$tlp.Controls.Add($btnLog, 4, 0)

		$gb = New-Object System.Windows.Forms.GroupBox -Property @{
			Text = $ServiceName; Dock = "Fill"; Padding = "5, 0, 5, 5"; ForeColor = 'Navy'
		}
		$gb.Controls.Add($tlp)

		[PSCustomObject]@{ GroupBox = $gb; btnCOM = $btnCOM; btnStartStop = $btnStartStop; txtStatus = $txtStatus; btnTestApp = $btnTestApp; btnLog = $btnLog; }
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

	$cms = New-Object System.Windows.Forms.ContextMenuStrip
	$menuItem = $cms.Items.Add('Вычистить COM порты (высвободить номера)')
	$menuItem.Add_Click({ 
		$removedList = [HiddenUsbCleaner]::Clean()
		if ($removedList.Count -eq 0) {
			$msg = "Скрытые USB-устройства не найдены. Реестр COM-портов проверен."
		} else {
			$msg = "Удалено $($removedList.Count) скрытых USB-устройств и освобождены занятые ими COM-порты"
		}
		[System.Windows.Forms.MessageBox]::Show($msg, "Успех", 'OK', 'Information')
	})
	$dgv.ContextMenuStrip = $cms

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

	$srvCtrlPBF = New-ServiceControl $Service.PBF
	$srvCtrlDC = New-ServiceControl $Service.DC
	$srvCtrlPBF.GroupBox.Margin = "0, 5, 0, 5"
	$srvCtrlDC.GroupBox.Margin = "0, 5, 0, 0"
	[void]$bottom.Controls.Add($srvCtrlPBF.GroupBox, 0, 0)
	[void]$bottom.Controls.Add($srvCtrlDC.GroupBox, 0, 1)

	[void]$form.Controls.Add($gbTop)
	[void]$form.Controls.Add($bottom)

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

function Update-DGV ($dgv, $listCOMports) {
	if ($null -eq $dgv -or $dgv.IsDisposed -or -not $dgv.IsHandleCreated) { return }

	[Win32]::SendMessage($dgv.Handle, [Win32]::WM_SETREDRAW, $false, 0)
	try {
		foreach ($row in $dgv.Rows) {
			$row.Tag = "ToDelete"
		}

		foreach ($port in $listCOMports) {
			$found = $false
			foreach ($row in $dgv.Rows) {
				if ($row.Cells["COM"].Value -eq $port.COM) {
					$row.Cells["Status"].Value = $port.Status
					$row.Cells["VidPid"].Value = $port.VidPid
					$row.Cells["FriendlyName"].Value = $port.FriendlyName

					if ($port.Status -ne "Free") {
						$row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Orange
						$row.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::Yellow
					} else {
						$row.DefaultCellStyle.ForeColor = $dgv.DefaultCellStyle.ForeColor
						$row.DefaultCellStyle.SelectionForeColor = $dgv.DefaultCellStyle.SelectionForeColor
					}

					$row.Tag = "Keep"
					$found = $true
					break
				}
			}

			if (-not $found) {
				$dgv.Rows.Add($port.Status, $port.COM, $port.VidPid, $port.FriendlyName)
			}
		}

		for ($i = $dgv.Rows.Count - 1; $i -ge 0; $i--) {
			if ($dgv.Rows[$i].Tag -eq "ToDelete") {
				$dgv.Rows.RemoveAt($i)
			}
		}
	}
	finally {
		[Win32]::SendMessage($dgv.Handle, [Win32]::WM_SETREDRAW, $true, 0)
		$dgv.Refresh()
	}
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
			$svControl.btnTestApp.Enabled = $false
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
		$Service.PBF {
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
			$testAppPath = $servicePath -replace '[^\\]*$', ''
			$testApp = "$testAppPath\PosConnector\poscon_tester_gui.exe"
			if ([System.IO.File]::Exists($testApp)) {
				$frmMain.Tag.SrvCtrlPBF.btnTestApp.Tag = $testApp
			} else {
				[System.Windows.Forms.MessageBox]::Show("Тестовое приложение`n$testApp`nотсутствует!", "Warning", 'OK', 'Warning')
				$frmMain.Tag.SrvCtrlPBF.btnTestApp.Enabled = $false
			}
			$frmMain.Tag.SrvCtrlPBF.btnLog.Tag = "$servicePath\pbfproxy_$($Date.ToString('yyyy-MM-dd')).log"
		}
		$Service.DC {
			$imagePath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DCService").ImagePath
			$servicePath = $imagePath -replace '^"?(.+)\\bin\\.*', '$1'
			$xmlfile = "$servicePath\config\Connector.xml"
			if ([System.IO.File]::Exists($xmlfile)) {
				$port = (Select-Xml -Path $xmlfile -XPath '//CONNECTION_PORT').Node.InnerText
				$frmMain.Tag.SrvCtrlDC.btnCOM.Text = $port
				$frmMain.Tag.SrvCtrlDC.btnCOM.Tag = $xmlfile
			} else {
				[System.Windows.Forms.MessageBox]::Show("Файл конфигурации`n$xmlfile`nотсутствует!", "Warning", 'OK', 'Warning')
			}
			$testAppPath = $servicePath -replace '[^\\]*$', ''
			$testApp = "$testAppPath\DCControl.bat"
			if (![System.IO.File]::Exists($testApp)) { $testApp = "$testAppPath\DC Control.exe" } # Pos Connector version 0.1.?
			if ([System.IO.File]::Exists($testApp)) {
				$frmMain.Tag.SrvCtrlDC.btnTestApp.Tag = $testApp
			} else {
				[System.Windows.Forms.MessageBox]::Show("Тестовое приложение`n$testApp`nотсутствует!", "Warning", 'OK', 'Warning')
				$frmMain.Tag.SrvCtrlDC.btnTestApp.Enabled = $false
			}
			$frmMain.Tag.SrvCtrlDC.btnLog.Tag = "$servicePath\log\Connector$($Date.ToString('yyyyMMdd')).log"
		}
	}
}

# ==============================================================================
$updateError = Get-Update
if ($updateError) {
	[void][System.Windows.Forms.MessageBox]::Show($updateError, "Ошибка обновления", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
}

# ==============================================================================
$script:_isClosing = $false

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 2000

$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new('List-COM-Ports', ${function:List-COM-Ports}))
$iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new('Update-DGV', ${function:Update-DGV}))
$iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new('Update-ServiceStatus', ${function:Update-ServiceStatus}))

$runspacePool = [runspacefactory]::CreateRunspacePool(1, 1, $iss, $Host)
$runspacePool.Open()

$timerAction = {
	if ($script:_isClosing) { return }

	$ps = [powershell]::Create()
	$ps.RunspacePool = $runspacePool

	$ps.AddScript({
		param($FormRef, $ClosingFlagRef)

		try {
			if ($ClosingFlagRef.Value) { return }
			if ($null -eq $FormRef -or $FormRef.IsDisposed) { return }

			$listCOMports = @(List-COM-Ports)

			if ($ClosingFlagRef.Value) { return }
			if ($FormRef.IsDisposed -or -not $FormRef.IsHandleCreated) { return }

			$dvg     = $FormRef.Tag.Dgv
			$srvPBF  = $FormRef.Tag.SrvCtrlPBF
			$srvDC   = $FormRef.Tag.SrvCtrlDC

			if ($null -eq $dvg -or $dvg.IsDisposed) { return }

			$FormRef.BeginInvoke([action]{
				try {
					if ($ClosingFlagRef.Value) { return }
					if ($dvg.IsDisposed -or $srvPBF.IsDisposed -or $srvDC.IsDisposed) { return }

					Update-DGV     $dvg $listCOMports
					Update-ServiceStatus $srvPBF
					Update-ServiceStatus $srvDC
				} catch { }
			}) | Out-Null
		} catch { }
	}).AddArgument($frmMain).AddArgument(([ref]$script:_isClosing)) | Out-Null

	$null = $ps.BeginInvoke()

	$subId = 'PSDone_' + [guid]::NewGuid().ToString('N')
	Register-ObjectEvent -InputObject $ps -EventName InvocationStateChanged `
		-SourceIdentifier $subId -Action {
		try {
			if ($Event.SourceEventArgs.InvocationStateInfo.State -eq 'Completed') {
				$Event.MessageData.Dispose()
			}
		} catch { }
		Unregister-Event -SourceIdentifier $EventSubscriber.SourceIdentifier -ErrorAction SilentlyContinue
	} -MessageData $ps | Out-Null
}

$timer.Add_Tick($timerAction)

# ==============================================================================
$frmMain = Create-Form
$frmMain.Text = "$($Config.Title) v$($Config.Version)"

$frmMain.Add_Shown({
	$frmMain.Activate()
	Get-ServiceFiles $Service.PBF
	Get-ServiceFiles $Service.DC
	& $timerAction
	$timer.Start()
})

$frmMain.Add_FormClosing({
	$script:_isClosing = $true
	$timer.Stop()
	$timer.Dispose()

	Get-EventSubscriber -ErrorAction SilentlyContinue |
		Where-Object { $_.SourceIdentifier -like 'PSDone_*' } |
		Unregister-Event -ErrorAction SilentlyContinue

	if ($runspacePool) {
		try {
			$runspacePool.Close()
			$runspacePool.Dispose()
		} catch { }
	}
})

# ==============================================================================
$frmMain = Create-Form
$frmMain.Text = "$($Config.Title) v$($Config.Version)"

$frmMain.Add_Shown({
	$frmMain.Activate()
	Get-ServiceFiles $Service.PBF
	Get-ServiceFiles $Service.DC
	& $timerAction
	$timer.Start()
})

$frmMain.Add_FormClosing({
	$script:_isClosing = $true
	$timer.Stop()

	if ($script:_psLock) {
		foreach ($ps in $script:_activePS.ToArray()) {
			try {
				if ($ps.InvocationStateInfo.State -eq 'Running') { $ps.Stop() }
				$ps.Dispose()
			} catch { }
		}
		$script:_activePS.Clear()
	}

	$timer.Dispose()

	Get-EventSubscriber -ErrorAction SilentlyContinue |
		Where-Object { $_.SourceIdentifier -like 'PSDone_*' } |
		Unregister-Event -ErrorAction SilentlyContinue

	if ($runspacePool) {
		try {
			$runspacePool.Close()
			$runspacePool.Dispose()
		} catch { }
	}

	[System.Windows.Forms.Application]::Exit()
	[System.Environment]::Exit(0)
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
	if ([System.Windows.Forms.MessageBox]::Show("Изменить конфигурацию сервиса для $model ?`nБудут заданы:`nname=$port, VID=$dVID, PID=$dPID, speed=$speed", "Подтверждение", "YesNo", "Question") -eq "Yes") {
		Stop-Service -Name $Service.PBF -Force -ErrorAction Stop -WarningAction SilentlyContinue
		$config = IniContent -FilePath $inifile
		$config["SerialPort"]["name"] = $port
		$config["SerialPort"]["vid"] = $dVid
		$config["SerialPort"]["pid"] = $dPid
		$config["SerialPort"]["speed"] = $speed
		IniContent -FilePath $inifile -Config $config
		Get-ServiceFiles $Service.PBF
	}
})

$frmMain.Tag.SrvCtrlDC.btnCOM.Add_Click({
	$xmlfile = $this.Tag
	$port = $frmMain.Tag.Dgv.CurrentRow.Cells[1].Value
	$model = $frmMain.Tag.Dgv.CurrentRow.Cells[2].Value
	if ([System.Windows.Forms.MessageBox]::Show("Изменить конфигурацию сервиса?`nБудет задан CONNECTION_PORT $port", "Подтверждение", "YesNo", "Question") -eq "Yes") {
		Stop-Service -Name $Service.DC -Force -ErrorAction Stop -WarningAction SilentlyContinue
		(Get-Content $xmlfile -Raw) -replace '(?<=<CONNECTION_PORT>).*?(?=</CONNECTION_PORT>)', $port | Set-Content $xmlfile -Encoding UTF8
		Get-ServiceFiles $Service.DC
	}
})

[void]$frmMain.ShowDialog()