# =============================================================================
# LTI MS365 Investigation Utility
# REV 2.2 - MFA Scan Fix Build
# =============================================================================
#
# WPF GUI for Microsoft 365 account compromise investigations.
#   - Exchange Online connection with auto domain detection
#   - Multi-select mailbox picker (individual, range, or Select All)
#   - Configurable investigation steps (choose which checks to run)
#   - Baseline comparison: select a previous investigation folder to
#     detect configuration drift (new rules, forwarding changes, etc.)
#   - MFA Status panel: click "Refresh MFA" after mailboxes load. Uses
#     Microsoft Graph with a device-code sign-in (no MSOnline, no MSAL SDK).
#   - Days back selector, output folder picker
#   - Live verbose console output and progress tracking
#
# Requires: ExchangeOnlineManagement module v3+, PowerShell 5.1+
#           Exchange: Global Admin, Security Admin, or delegated compliance role
#           MFA scan: Global Admin / Global Reader in the tenant being
#                     investigated. Authentication Administrator can read
#                     methods but not the audit log, so the MFA config-date
#                     columns stay blank for that role.
#           MFA scan: admin consent for "Microsoft Graph Command Line Tools"
#                     (UserAuthenticationMethod.Read.All, AuditLog.Read.All,
#                     User.Read.All). A Global Admin is prompted on first use.
#
# License Compatibility: Exchange Online Plan 1 and above.
# Does NOT require Entra ID P1/P2. With P1/P2 the MFA panel also shows the
# user's real default MFA method and 30 days of MFA audit history (7 on Free).
#
# REV 2.2 changes
#   FIX  MFA scan aborted with "Cannot bind argument to parameter
#        'AuditEvents' because it is an empty array" whenever the tenant had
#        no MFA audit events in the last 30 days or the audit query was
#        refused. An empty result is now normal and the scan carries on.
#   FIX  Graph errors show the real code and message instead of a bare
#        "(403) Forbidden", and a scan that is refused outright stops after
#        five users with an explanation instead of failing every user.
#   FIX  Graph sign-in targets the tenant Exchange Online is connected to.
#   FIX  Email (password-reset only), Temporary Access Pass and QR code no
#        longer count as MFA. Default Method was the first method listed, and
#        a single character for one-method users; it is now the real default
#        (P1/P2) or blank.
#   FIX  Reports no longer say "MFA DISABLED" / "AUDIT OFF" for mailboxes
#        where those checks were not run or failed - they say so instead.
#   FIX  Message trace for 14 and 30 days (Get-MessageTraceV2 accepts at most
#        10 days per query; the range is now walked in 10-day windows).
#   FIX  A failed run can no longer leave the window stuck on "Running...".
#   NEW  17a_MFA_Method_Details.csv - every registered method with device /
#        phone detail, date added and date last used.
#   NEW  17b_MFA_Config_Audit_Events.csv - who changed MFA, when, from which IP.
#   NEW  Alert when an MFA method was added inside the investigation window.
#   NEW  Throttling retries, silent token renewal, sign-in-blocked awareness.
# =============================================================================

# -----------------------------------------------------------------------------
#  EXECUTION POLICY
#  Set process-scope bypass so module .psm1 files can be imported regardless
#  of machine or user policy. Process scope is temporary - it resets when this
#  PowerShell session exits and does not change any system-wide policy.
# -----------------------------------------------------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Windows PowerShell 5.1 can still default to TLS 1.0/1.1 on older builds.
# Microsoft's sign-in and Graph endpoints require TLS 1.2 or later.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

# -----------------------------------------------------------------------------
#  FILE LOGGING
#  Captures everything to a timestamped log on the Desktop so crashes that
#  close the window before you can read them are still recoverable.
# -----------------------------------------------------------------------------
$script:LogFile = Join-Path ([Environment]::GetFolderPath("Desktop")) ("LTI_M365_Debug_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch {}
}

# Catch any unhandled terminating errors at the script level
trap {
    Write-Log "UNHANDLED EXCEPTION: $_" "FATAL"
    Write-Log "Script line: $($_.InvocationInfo.ScriptLineNumber) - $($_.InvocationInfo.Line.Trim())" "FATAL"
    Write-Log "Stack: $($_.ScriptStackTrace)" "FATAL"
    try {
        [System.Windows.MessageBox]::Show(
            "A fatal error occurred and the script must close.`n`nError: $_`n`nFull details written to:`n$script:LogFile",
            "LTI Fatal Error", "OK", "Error")
    } catch {}
    continue
}

Write-Log "Script started - LTI MS365 Investigation Utility REV 2.2 (PowerShell $($PSVersionTable.PSVersion))"

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Host "ExchangeOnlineManagement module not found. Installing..." -ForegroundColor Yellow
    try { Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber }
    catch {
        [System.Windows.MessageBox]::Show("Failed to install ExchangeOnlineManagement module.`nPlease run:`nInstall-Module ExchangeOnlineManagement -Scope CurrentUser","Module Required","OK","Error")
        exit 1
    }
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# AllocConsole / FreeConsole P/Invoke
# EXO v3.7+ uses GetConsoleWindow() internally to find the WAM parent handle.
# In a WPF host there is no console, so GetConsoleWindow() returns NULL and
# MSAL throws "A window handle must be configured."
# Fix: briefly allocate a hidden console before connecting, then free it.
$script:ConsoleSupportSource = @'
using System;
using System.Runtime.InteropServices;
public class LTIConsoleSupport {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AllocConsole();
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeConsole();
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    public const int SW_HIDE = 0;
}
'@
Add-Type -TypeDefinition $script:ConsoleSupportSource -Language CSharp

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

# -----------------------------------------------------------------------------
#  WPF GUI DEFINITION
# -----------------------------------------------------------------------------
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="LTI MS365 Investigation Utility"
        Width="920" Height="1120"
        WindowStartupLocation="CenterScreen"
        ResizeMode="CanResizeWithGrip"
        Background="#1e1e2e">
    <Window.Resources>
        <Style TargetType="TextBlock"><Setter Property="Foreground" Value="#cdd6f4"/><Setter Property="FontFamily" Value="Segoe UI"/><Setter Property="FontSize" Value="13"/></Style>
        <Style TargetType="Label"><Setter Property="Foreground" Value="#cdd6f4"/><Setter Property="FontFamily" Value="Segoe UI"/><Setter Property="FontSize" Value="13"/></Style>
        <Style TargetType="Button"><Setter Property="Background" Value="#45475a"/><Setter Property="Foreground" Value="#cdd6f4"/><Setter Property="BorderBrush" Value="#585b70"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="12,6"/><Setter Property="FontFamily" Value="Segoe UI"/><Setter Property="FontSize" Value="13"/><Setter Property="Cursor" Value="Hand"/></Style>
        <Style TargetType="TextBox"><Setter Property="Background" Value="#313244"/><Setter Property="Foreground" Value="#cdd6f4"/><Setter Property="BorderBrush" Value="#585b70"/><Setter Property="Padding" Value="6,4"/><Setter Property="FontFamily" Value="Segoe UI"/><Setter Property="FontSize" Value="13"/><Setter Property="CaretBrush" Value="#cdd6f4"/></Style>
        <Style TargetType="ComboBox"><Setter Property="Background" Value="#313244"/><Setter Property="Foreground" Value="#1e1e2e"/><Setter Property="BorderBrush" Value="#585b70"/><Setter Property="Padding" Value="6,4"/><Setter Property="FontFamily" Value="Segoe UI"/><Setter Property="FontSize" Value="13"/></Style>
        <Style TargetType="CheckBox"><Setter Property="Foreground" Value="#cdd6f4"/><Setter Property="FontFamily" Value="Segoe UI"/><Setter Property="FontSize" Value="12"/><Setter Property="Margin" Value="0,1"/></Style>
        <Style TargetType="ListBox"><Setter Property="Background" Value="#313244"/><Setter Property="Foreground" Value="#cdd6f4"/><Setter Property="BorderBrush" Value="#585b70"/><Setter Property="FontFamily" Value="Segoe UI"/><Setter Property="FontSize" Value="12"/></Style>
    </Window.Resources>
    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*" MinHeight="80"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Title -->
        <TextBlock Grid.Row="0" Text="LTI MS365 Investigation Utility" FontSize="20" FontWeight="Bold" Foreground="#89b4fa" Margin="0,0,0,16"/>

        <!-- Connection and Domain -->
        <Grid Grid.Row="1" Margin="0,0,0,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Label Grid.Column="0" Content="Domain:" VerticalAlignment="Center"/>
            <TextBox Grid.Column="1" x:Name="txtDomain" Margin="4,0" VerticalAlignment="Center" ToolTip="Enter domain (e.g. contoso.com)"/>
            <Button Grid.Column="2" x:Name="btnConnect" Content="Connect" Margin="4,0" VerticalAlignment="Center"/>
            <Button Grid.Column="3" x:Name="btnLoadMailboxes" Content="Load Mailboxes" Margin="4,0" VerticalAlignment="Center" IsEnabled="False"/>
        </Grid>

        <!-- Connection status -->
        <TextBlock Grid.Row="2" x:Name="lblConnectionStatus" Text="Status: Not connected" Foreground="#f38ba8" Margin="0,0,0,8"/>

        <!-- Mailbox List -->
        <Grid Grid.Row="3" Margin="0,0,0,8">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <Grid Grid.Row="0" Margin="0,0,0,4">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <Label Grid.Column="0" Content="Mailboxes:" VerticalAlignment="Center"/>
                <TextBox Grid.Column="1" x:Name="txtFilter" Margin="4,0" VerticalAlignment="Center" ToolTip="Type to filter"/>
                <Button Grid.Column="2" x:Name="btnSelectAll" Content="Select All" Margin="4,0" VerticalAlignment="Center" IsEnabled="False"/>
                <Button Grid.Column="3" x:Name="btnSelectNone" Content="Select None" Margin="4,0" VerticalAlignment="Center" IsEnabled="False"/>
                <TextBlock Grid.Column="4" x:Name="lblMailboxCount" Text="0 mailboxes loaded" VerticalAlignment="Center" Margin="8,0,0,0" Foreground="#a6adc8"/>
            </Grid>
            <ListBox Grid.Row="1" x:Name="lstMailboxes" SelectionMode="Extended" MinHeight="100"/>
        </Grid>

        <!-- MFA Status Panel -->
        <Grid Grid.Row="4" Margin="0,0,0,8">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <Grid Grid.Row="0" Margin="0,0,0,4">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <Label Grid.Column="0" Content="MFA Status:" FontWeight="SemiBold" VerticalAlignment="Center"/>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center" Margin="8,0,0,0">
                    <TextBlock x:Name="lblMFAEnabled" Text="Enabled: -" Foreground="#a6e3a1" FontWeight="SemiBold" Margin="0,0,16,0"/>
                    <TextBlock x:Name="lblMFADisabled" Text="Disabled: -" Foreground="#f38ba8" FontWeight="SemiBold" Margin="0,0,16,0"/>
                    <TextBlock x:Name="lblMFATotal" Text="Total: -" Foreground="#a6adc8"/>
                </StackPanel>
                <ComboBox Grid.Column="2" x:Name="cmbMFAFilter" Width="130" Margin="4,0" VerticalAlignment="Center" SelectedIndex="0">
                    <ComboBoxItem Content="All Users"/>
                    <ComboBoxItem Content="MFA Disabled"/>
                    <ComboBoxItem Content="MFA Enabled"/>
                    <ComboBoxItem Content="MFA Unknown"/>
                </ComboBox>
                <Button Grid.Column="3" x:Name="btnRefreshMFA" Content="Refresh MFA" Margin="4,0" VerticalAlignment="Center" IsEnabled="False"/>
                <Button Grid.Column="4" x:Name="btnExportMFA" Content="Export MFA CSV" Margin="4,0" VerticalAlignment="Center" IsEnabled="False"/>
            </Grid>
            <Border Grid.Row="1" Background="#313244" BorderBrush="#585b70" BorderThickness="1" CornerRadius="4">
                <DataGrid x:Name="dgMFAStatus"
                          Height="130"
                          Background="#313244"
                          Foreground="#cdd6f4"
                          BorderThickness="0"
                          GridLinesVisibility="Horizontal"
                          HorizontalGridLinesBrush="#45475a"
                          AutoGenerateColumns="False"
                          IsReadOnly="True"
                          HeadersVisibility="Column"
                          SelectionMode="Extended"
                          CanUserResizeRows="False"
                          FontFamily="Segoe UI"
                          FontSize="12"
                          RowBackground="#313244"
                          AlternatingRowBackground="#2a2a3e">
                    <DataGrid.ColumnHeaderStyle>
                        <Style TargetType="DataGridColumnHeader">
                            <Setter Property="Background" Value="#45475a"/>
                            <Setter Property="Foreground" Value="#cdd6f4"/>
                            <Setter Property="Padding" Value="6,4"/>
                            <Setter Property="FontWeight" Value="SemiBold"/>
                            <Setter Property="BorderBrush" Value="#585b70"/>
                            <Setter Property="BorderThickness" Value="0,0,1,1"/>
                        </Style>
                    </DataGrid.ColumnHeaderStyle>
                    <DataGrid.CellStyle>
                        <Style TargetType="DataGridCell">
                            <Setter Property="BorderThickness" Value="0"/>
                            <Setter Property="Padding" Value="6,2"/>
                            <Setter Property="Foreground" Value="#cdd6f4"/>
                        </Style>
                    </DataGrid.CellStyle>
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Display Name"      Binding="{Binding DisplayName}"    Width="180"/>
                        <DataGridTextColumn Header="UPN"               Binding="{Binding UPN}"            Width="220"/>
                        <DataGridTemplateColumn Header="MFA Status" Width="110">
                            <DataGridTemplateColumn.CellTemplate>
                                <DataTemplate>
                                    <TextBlock Text="{Binding MFAStatus}"
                                               FontWeight="SemiBold"
                                               Padding="4,2">
                                        <TextBlock.Style>
                                            <Style TargetType="TextBlock">
                                                <Style.Triggers>
                                                    <DataTrigger Binding="{Binding MFAStatus}" Value="Enabled">
                                                        <Setter Property="Foreground" Value="#a6e3a1"/>
                                                    </DataTrigger>
                                                    <DataTrigger Binding="{Binding MFAStatus}" Value="Disabled">
                                                        <Setter Property="Foreground" Value="#f38ba8"/>
                                                    </DataTrigger>
                                                    <DataTrigger Binding="{Binding MFAStatus}" Value="Unknown">
                                                        <Setter Property="Foreground" Value="#f9e2af"/>
                                                    </DataTrigger>
                                                </Style.Triggers>
                                            </Style>
                                        </TextBlock.Style>
                                    </TextBlock>
                                </DataTemplate>
                            </DataGridTemplateColumn.CellTemplate>
                        </DataGridTemplateColumn>
                        <DataGridTextColumn Header="MFA Methods"       Binding="{Binding MFAMethods}"           Width="220"/>
                        <DataGridTextColumn Header="Newest Method Added" Binding="{Binding NewestMethodAdded}"   Width="165"/>
                        <DataGridTextColumn Header="Sign-In Allowed"   Binding="{Binding AccountEnabled}"        Width="100"/>
                        <DataGridTextColumn Header="MFA First Config Seen" Binding="{Binding MFAFirstConfigSeen}" Width="165"/>
                        <DataGridTextColumn Header="MFA Last Config"   Binding="{Binding MFALastConfig}"          Width="165"/>
                        <DataGridTextColumn Header="Last Config Event" Binding="{Binding MFALastConfigEvent}"     Width="220"/>
                        <DataGridTextColumn Header="Default Method"    Binding="{Binding DefaultMethod}"          Width="140"/>
                    </DataGrid.Columns>
                </DataGrid>
            </Border>
        </Grid>

        <!-- Investigation Steps -->
        <Grid Grid.Row="5" Margin="0,0,0,8">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
            <Grid Grid.Row="0" Margin="0,0,0,4">
                <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                <Label Grid.Column="0" Content="Investigation Steps:" VerticalAlignment="Center" FontWeight="SemiBold"/>
                <Button Grid.Column="2" x:Name="btnCheckAll" Content="Check All" Margin="4,0" VerticalAlignment="Center" Padding="8,4"/>
                <Button Grid.Column="3" x:Name="btnUncheckAll" Content="Uncheck All" Margin="4,0" VerticalAlignment="Center" Padding="8,4"/>
            </Grid>
            <Border Grid.Row="1" Background="#313244" BorderBrush="#585b70" BorderThickness="1" CornerRadius="4" Padding="10,6">
                <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                    <StackPanel Grid.Column="0">
                        <CheckBox x:Name="chkStep01" Content="1.  Sign-In / Auth Events" IsChecked="True"/>
                        <CheckBox x:Name="chkStep02" Content="2.  Mailbox Activity" IsChecked="True"/>
                        <CheckBox x:Name="chkStep03" Content="3.  Inbox Rules" IsChecked="True"/>
                        <CheckBox x:Name="chkStep04" Content="4.  Mailbox Forwarding (SMTP)" IsChecked="True"/>
                        <CheckBox x:Name="chkStep05" Content="5.  Transport Rules" IsChecked="True"/>
                        <CheckBox x:Name="chkStep06" Content="6.  Permissions / Delegates" IsChecked="True"/>
                        <CheckBox x:Name="chkStep07" Content="7.  Auto-Reply / OOF" IsChecked="True"/>
                        <CheckBox x:Name="chkStep08" Content="8.  Mobile Devices" IsChecked="True"/>
                        <CheckBox x:Name="chkStep17" Content="17. MFA Status Export" IsChecked="True"/>
                    </StackPanel>
                    <StackPanel Grid.Column="1">
                        <CheckBox x:Name="chkStep09" Content="9.  OAuth / App Consent" IsChecked="True"/>
                        <CheckBox x:Name="chkStep10" Content="10. Rule Creation / Changes" IsChecked="True"/>
                        <CheckBox x:Name="chkStep11" Content="11. SharePoint / OneDrive Files" IsChecked="True"/>
                        <CheckBox x:Name="chkStep12" Content="12. Admin / Elevated Actions" IsChecked="True"/>
                        <CheckBox x:Name="chkStep13" Content="13. eDiscovery / Compliance" IsChecked="True"/>
                        <CheckBox x:Name="chkStep14" Content="14. Message Trace (Mail Flow)" IsChecked="True"/>
                        <CheckBox x:Name="chkStep15" Content="15. Mailbox Audit Config" IsChecked="True"/>
                        <CheckBox x:Name="chkStep16" Content="16. Catch-All Audit Dump" IsChecked="True"/>
                    </StackPanel>
                </Grid>
            </Border>
        </Grid>

        <!-- Options Row -->
        <Grid Grid.Row="6" Margin="0,0,0,8">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="20"/>
                <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Label Grid.Column="0" Content="Days Back:" VerticalAlignment="Center"/>
            <ComboBox Grid.Column="1" x:Name="cmbDaysBack" Width="60" VerticalAlignment="Center" SelectedIndex="2"/>
            <Label Grid.Column="3" Content="Output Folder:" VerticalAlignment="Center"/>
            <TextBox Grid.Column="4" x:Name="txtOutputPath" Margin="4,0" VerticalAlignment="Center" IsReadOnly="True"/>
            <Button Grid.Column="5" x:Name="btnBrowse" Content="Browse..." Margin="4,0" VerticalAlignment="Center"/>
        </Grid>

        <!-- Baseline Comparison Row -->
        <Grid Grid.Row="7" Margin="0,0,0,8">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <CheckBox Grid.Column="0" x:Name="chkBaseline" Content="Compare to baseline:" VerticalAlignment="Center" IsChecked="False" FontWeight="SemiBold"/>
            <TextBox Grid.Column="1" x:Name="txtBaselinePath" Margin="8,0,4,0" VerticalAlignment="Center" IsReadOnly="True"
                     ToolTip="Select a previous Investigation_* folder to compare against" IsEnabled="False"/>
            <Button Grid.Column="2" x:Name="btnBaselineBrowse" Content="Browse..." Margin="4,0" VerticalAlignment="Center" IsEnabled="False"/>
            <Button Grid.Column="3" x:Name="btnBaselineClear" Content="Clear" Margin="4,0" VerticalAlignment="Center" IsEnabled="False" Padding="8,6"/>
        </Grid>

        <!-- Checkboxes row -->
        <CheckBox Grid.Row="8" x:Name="chkOpenFolder" Content="Open output folder when complete" IsChecked="True" Margin="0,0,0,10"/>

        <!-- Run Button -->
        <Button Grid.Row="9" x:Name="btnRun" Content="Run Investigation" FontSize="15" FontWeight="Bold" Padding="16,10"
                HorizontalAlignment="Stretch" Margin="0,0,0,10" IsEnabled="False" Background="#89b4fa" Foreground="#1e1e2e"/>

        <!-- Progress -->
        <Grid Grid.Row="10" Margin="0,0,0,6">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <ProgressBar Grid.Column="0" x:Name="progressBar" Height="22" Minimum="0" Maximum="100" Value="0" Background="#313244" Foreground="#a6e3a1" BorderBrush="#585b70"/>
            <TextBlock Grid.Column="1" x:Name="lblProgress" Text="Ready" Margin="10,0,0,0" VerticalAlignment="Center" Foreground="#a6adc8"/>
        </Grid>

        <!-- Status log -->
        <TextBox Grid.Row="11" x:Name="txtLog" Height="200" IsReadOnly="True" TextWrapping="Wrap"
                 VerticalScrollBarVisibility="Auto" Background="#181825" Foreground="#a6adc8"
                 BorderBrush="#585b70" FontFamily="Consolas" FontSize="11"/>
    </Grid>
</Window>
'@

# -----------------------------------------------------------------------------
#  PARSE XAML
# -----------------------------------------------------------------------------
$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$window = [System.Windows.Markup.XamlReader]::Load($reader)

$txtDomain=$window.FindName("txtDomain"); $btnConnect=$window.FindName("btnConnect"); $btnLoadMailboxes=$window.FindName("btnLoadMailboxes")
$lblConnectionStatus=$window.FindName("lblConnectionStatus"); $lstMailboxes=$window.FindName("lstMailboxes"); $txtFilter=$window.FindName("txtFilter")
$btnSelectAll=$window.FindName("btnSelectAll"); $btnSelectNone=$window.FindName("btnSelectNone"); $lblMailboxCount=$window.FindName("lblMailboxCount")
$cmbDaysBack=$window.FindName("cmbDaysBack"); $txtOutputPath=$window.FindName("txtOutputPath"); $btnBrowse=$window.FindName("btnBrowse")
$chkOpenFolder=$window.FindName("chkOpenFolder"); $btnRun=$window.FindName("btnRun"); $progressBar=$window.FindName("progressBar")
$lblProgress=$window.FindName("lblProgress"); $txtLog=$window.FindName("txtLog")
$btnCheckAll=$window.FindName("btnCheckAll"); $btnUncheckAll=$window.FindName("btnUncheckAll")
$chkBaseline=$window.FindName("chkBaseline"); $txtBaselinePath=$window.FindName("txtBaselinePath")
$btnBaselineBrowse=$window.FindName("btnBaselineBrowse"); $btnBaselineClear=$window.FindName("btnBaselineClear")

# MFA panel controls
$dgMFAStatus=$window.FindName("dgMFAStatus"); $lblMFAEnabled=$window.FindName("lblMFAEnabled")
$lblMFADisabled=$window.FindName("lblMFADisabled"); $lblMFATotal=$window.FindName("lblMFATotal")
$cmbMFAFilter=$window.FindName("cmbMFAFilter"); $btnRefreshMFA=$window.FindName("btnRefreshMFA")
$btnExportMFA=$window.FindName("btnExportMFA")

$chkSteps = @{}
for ($i = 1; $i -le 16; $i++) { $chkSteps[$i] = $window.FindName("chkStep{0:D2}" -f $i) }
$chkSteps[17] = $window.FindName("chkStep17")

foreach ($d in @(1, 3, 7, 14, 30)) { $item = [System.Windows.Controls.ComboBoxItem]::new(); $item.Content = "$d"; $cmbDaysBack.Items.Add($item) | Out-Null }
$cmbDaysBack.SelectedIndex = 2

$txtOutputPath.Text = Join-Path ([Environment]::GetFolderPath("Desktop")) "LTI_M365_Investigation"
$script:allMailboxes = @()
$script:isConnected = $false
$script:ExoTenantId = $null          # tenant GUID of the Exchange Online connection

# MFA caches. Filled by "Refresh MFA", read by step 17 and the per-mailbox findings.
$script:allMFAData          = [System.Collections.Generic.List[PSCustomObject]]::new()   # one row per mailbox
$script:allMFAMethodDetails = [System.Collections.Generic.List[PSCustomObject]]::new()   # one row per registered method
$script:allMFAAuditRows     = [System.Collections.Generic.List[PSCustomObject]]::new()   # one row per MFA audit event
$script:MFAContext          = $null                                                      # tenant-level lookups

# Microsoft Graph sign-in state
$script:GraphClientId     = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph Command Line Tools (public client)
$script:GraphScopes       = @(
    "https://graph.microsoft.com/UserAuthenticationMethod.Read.All",
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/User.Read.All"
)
$script:GraphToken        = $null
$script:GraphRefreshToken = $null
$script:GraphTokenExpiry  = [DateTime]::MinValue
$script:GraphAuthority    = $null    # login authority the current token came from
$script:GraphTokenTenant  = $null    # Exchange tenant the current token was requested for

# Graph authentication method types -> grid label, and whether the method can
# satisfy an MFA prompt. Types missing from this table are shown under their
# Graph name and do NOT count as MFA.
$script:LTIMethodTypes = @{
    'microsoftAuthenticatorAuthenticationMethod'             = @{ Label = 'Authenticator App';            MFA = $true  }
    'passwordlessMicrosoftAuthenticatorAuthenticationMethod' = @{ Label = 'Authenticator (Passwordless)'; MFA = $true  }
    'phoneAuthenticationMethod'                              = @{ Label = 'Phone (SMS/Call)';             MFA = $true  }
    'fido2AuthenticationMethod'                              = @{ Label = 'FIDO2 Key';                    MFA = $true  }
    'windowsHelloForBusinessAuthenticationMethod'            = @{ Label = 'Windows Hello';                MFA = $true  }
    'softwareOathAuthenticationMethod'                       = @{ Label = 'OATH TOTP';                    MFA = $true  }
    'hardwareOathAuthenticationMethod'                       = @{ Label = 'Hardware OATH Token';          MFA = $true  }
    'platformCredentialAuthenticationMethod'                 = @{ Label = 'Platform Credential';          MFA = $true  }
    'externalAuthenticationMethod'                           = @{ Label = 'External MFA Provider';        MFA = $true  }
    'emailAuthenticationMethod'                              = @{ Label = 'Email (reset only)';           MFA = $false }
    'temporaryAccessPassAuthenticationMethod'                = @{ Label = 'Temp Access Pass';             MFA = $false }
    'qrCodePinAuthenticationMethod'                          = @{ Label = 'QR Code + PIN';                MFA = $false }
}

# -----------------------------------------------------------------------------
#  GUI HELPERS
# -----------------------------------------------------------------------------
function Add-Log {
    param([string]$Message)
    Write-Log $Message "UI"
    $ts = Get-Date -Format "HH:mm:ss"
    # "$null =" keeps the dispatcher call from ever leaking a value into the
    # output of a function that calls Add-Log / Flush-UI and returns data.
    try {
        $null = $txtLog.Dispatcher.Invoke([Action]{ $txtLog.AppendText("[$ts] $Message`r`n"); $txtLog.ScrollToEnd() })
    } catch {
        Write-Log "Add-Log dispatcher error: $_" "WARN"
    }
}
function Flush-UI { $null = [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background) }

function Update-MFAGrid {
    param([string]$Filter = "All Users")

    Write-Log "Update-MFAGrid called, filter=$Filter, allMFAData.Count=$($script:allMFAData.Count)"
    $filtered = switch ($Filter) {
        "MFA Disabled" { @($script:allMFAData | Where-Object { $_.MFAStatus -eq "Disabled" }) }
        "MFA Enabled"  { @($script:allMFAData | Where-Object { $_.MFAStatus -eq "Enabled"  }) }
        "MFA Unknown"  { @($script:allMFAData | Where-Object { $_.MFAStatus -eq "Unknown"  }) }
        default        { @($script:allMFAData) }
    }
    Write-Log "Update-MFAGrid filtered count=$($filtered.Count), binding to DataGrid"

    try {
        $dgMFAStatus.Dispatcher.Invoke([Action]{
            $dgMFAStatus.ItemsSource = $null
            $dgMFAStatus.ItemsSource = $filtered
        })
        Write-Log "Update-MFAGrid DataGrid bind OK"
    } catch {
        Write-Log "Update-MFAGrid DataGrid bind FAILED: $_" "ERROR"
        throw
    }

    $enabledCount  = @($script:allMFAData | Where-Object { $_.MFAStatus -eq "Enabled"  }).Count
    $disabledCount = @($script:allMFAData | Where-Object { $_.MFAStatus -eq "Disabled" }).Count
    $totalCount    = $script:allMFAData.Count

    $lblMFAEnabled.Dispatcher.Invoke([Action]{
        $lblMFAEnabled.Text  = "Enabled: $enabledCount"
        $lblMFADisabled.Text = "Disabled: $disabledCount"
        $lblMFATotal.Text    = "Total: $totalCount"
    })
}

# -----------------------------------------------------------------------------
#  MICROSOFT GRAPH: SIGN-IN + REQUEST HELPERS
# -----------------------------------------------------------------------------
# Device-code OAuth via plain Invoke-RestMethod (no MSAL SDK - avoids assembly
# conflicts with ExchangeOnlineManagement), polled by a DispatcherTimer so the
# UI never blocks. No background threads, no Start-Sleep while waiting for the
# user, no MessageBox from non-WPF threads.

function Get-LTIGraphAuthority {
    # Sign in against the SAME tenant Exchange Online is connected to. The old
    # "/organizations" authority issues a token for the signing-in account's
    # HOME tenant, which is the wrong directory when that differs from the
    # tenant under investigation.
    $tenant = $null
    if (-not [string]::IsNullOrWhiteSpace($script:ExoTenantId)) {
        $tenant = $script:ExoTenantId
    } else {
        $domain = ([string]$txtDomain.Text).Trim()
        if ($domain -match '^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$') { $tenant = $domain }
    }
    if ([string]::IsNullOrWhiteSpace($tenant)) { $tenant = "organizations" }
    return "https://login.microsoftonline.com/$tenant"
}

function ConvertFrom-LTIJwt {
    # Decodes the (unencrypted) claims section of an access token so the tool
    # can show who signed in, to which tenant, and with which scopes.
    param([string]$Token)
    try {
        $parts = $Token.Split('.')
        if ($parts.Count -lt 2) { return $null }
        $p = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
        $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($p))
        return ($json | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Get-LTIHttpErrorInfo {
    # Turns an Invoke-RestMethod failure into something readable. The bare
    # exception text ("The remote server returned an error: (403) Forbidden.")
    # hides the part that matters - the error code and message in the body.
    # Works on Windows PowerShell 5.1 and PowerShell 7.
    param($ErrorRecord)

    $status = 0; $code = ""; $msg = ""; $retryAfter = 0; $body = $null; $resp = $null

    try { $resp = $ErrorRecord.Exception.Response } catch {}
    if ($resp) {
        try { $status = [int]$resp.StatusCode } catch {}
        try {
            $ra = $null
            if ($resp.Headers -and $resp.Headers.RetryAfter -and $resp.Headers.RetryAfter.Delta) {
                $ra = $resp.Headers.RetryAfter.Delta.TotalSeconds      # PowerShell 7
            } elseif ($resp.Headers) {
                $ra = $resp.Headers['Retry-After']                     # Windows PowerShell 5.1
            }
            if ($ra) { $retryAfter = [int][double]$ra }
        } catch {}
    }

    try {
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $body = [string]$ErrorRecord.ErrorDetails.Message }
    } catch {}
    if (-not $body -and $resp -and ($resp -is [System.Net.HttpWebResponse])) {
        try {
            $stream = $resp.GetResponseStream()
            if ($stream.CanSeek) { $stream.Position = 0 }
            $sr = New-Object System.IO.StreamReader($stream)
            $body = $sr.ReadToEnd()
        } catch {}
    }

    if ($body) {
        try {
            $j = $body | ConvertFrom-Json
            if ($j.error -is [string]) {
                # login.microsoftonline.com shape: { error, error_description }
                $code = [string]$j.error
                $msg  = [string]$j.error_description
            } elseif ($j.error) {
                # Graph shape: { error: { code, message } }
                $code = [string]$j.error.code
                $msg  = [string]$j.error.message
            }
        } catch {}
    }

    if ([string]::IsNullOrWhiteSpace($msg)) { $msg = [string]$ErrorRecord.Exception.Message }
    # AADSTS descriptions carry trace IDs and timestamps on later lines - keep line one.
    $msg = (($msg -split "`r?`n")[0]).Trim()

    $prefix = ""
    if ($status -gt 0) { $prefix = "HTTP $status" }
    if ($code) { $prefix = ("$prefix $code").Trim() }
    $text = $msg
    if ($prefix) { $text = "$prefix - $msg" }

    return [PSCustomObject]@{ Status = $status; Code = $code; Message = $msg; RetryAfter = $retryAfter; Text = $text }
}

function Invoke-LTIGraphGet {
    # GET against Graph using the cached token. Retries throttling (429) and
    # transient gateway errors, honouring Retry-After. On a final failure it
    # throws an exception whose message is the decoded Graph error and whose
    # Data carries the HTTP status (LTIStatus) and Graph error code (LTICode).
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [int]$MaxRetries = 4
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return Invoke-RestMethod -Method GET -Uri $Uri -Headers @{ Authorization = "Bearer $($script:GraphToken)" } -ErrorAction Stop
        } catch {
            $info = Get-LTIHttpErrorInfo -ErrorRecord $_
            if ((@(429, 502, 503, 504) -contains $info.Status) -and $attempt -le $MaxRetries) {
                $wait = [int][Math]::Min(2 * [Math]::Pow(2, $attempt - 1), 30)
                if ($info.RetryAfter -gt 0) { $wait = [int][Math]::Min($info.RetryAfter, 60) }
                Write-Log "Graph HTTP $($info.Status) - retry $attempt of $MaxRetries in ${wait}s ($Uri)" "WARN"
                Flush-UI
                Start-Sleep -Seconds $wait
                continue
            }
            $ex = New-Object System.Exception($info.Text)
            $ex.Data['LTIStatus'] = $info.Status
            $ex.Data['LTICode']   = $info.Code
            throw $ex
        }
    }
}

function Get-LTIGraphPaged {
    # Follows @odata.nextLink and always returns an array (possibly empty).
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [int]$MaxPages = 500
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $page = 0
    while ($next -and $page -lt $MaxPages) {
        $page++
        $resp = Invoke-LTIGraphGet -Uri $next
        foreach ($v in @($resp.value)) { if ($null -ne $v) { $items.Add($v) } }
        $next = $resp.'@odata.nextLink'
        if ($page % 3 -eq 0) { Flush-UI }
    }
    return , $items.ToArray()
}

function Clear-LTIGraphToken {
    $script:GraphToken        = $null
    $script:GraphRefreshToken = $null
    $script:GraphTokenExpiry  = [DateTime]::MinValue
    $script:GraphAuthority    = $null
    $script:GraphTokenTenant  = $null
}

function Set-LTIGraphToken {
    # Stores a token response and reports who/where/what it is good for.
    param(
        $TokenResp,
        [string]$Authority,
        [switch]$Quiet
    )

    $script:GraphToken = [string]$TokenResp.access_token
    $life = 3600
    try { if ($TokenResp.expires_in) { $life = [int]$TokenResp.expires_in } } catch {}
    # Treat the token as expired five minutes early so a long run never starts on a dying token.
    $script:GraphTokenExpiry = (Get-Date).AddSeconds([Math]::Max($life - 300, 60))
    if ($TokenResp.refresh_token) { $script:GraphRefreshToken = [string]$TokenResp.refresh_token }
    $script:GraphAuthority   = $Authority
    $script:GraphTokenTenant = $script:ExoTenantId

    $claims = ConvertFrom-LTIJwt -Token $script:GraphToken
    if (-not $claims) { Write-Log "Graph token acquired (claims not readable)"; return }

    $who = [string]$claims.upn
    if (-not $who) { $who = [string]$claims.unique_name }
    if (-not $who) { $who = [string]$claims.oid }
    Write-Log "Graph token: user=$who tenant=$($claims.tid) scopes=$($claims.scp)"
    if ($Quiet) { return }

    Add-Log "  Graph sign-in: $who (tenant $($claims.tid))"

    $granted = @(([string]$claims.scp) -split ' ' | Where-Object { $_ })
    if ($granted.Count -gt 0) {
        $missing = @($script:GraphScopes | ForEach-Object { ($_ -split '/')[-1] } | Where-Object { $granted -notcontains $_ })
        if ($missing.Count -gt 0) {
            Add-Log "  [WARN] The token does not include: $($missing -join ', ')"
            Add-Log "         'Microsoft Graph Command Line Tools' needs admin consent for these in this tenant."
        }
    }

    if ($script:ExoTenantId -and $claims.tid -and ([string]$claims.tid -ne [string]$script:ExoTenantId)) {
        Add-Log "  [WARN] Graph signed in to tenant $($claims.tid), but Exchange Online is connected to $($script:ExoTenantId)."
        Add-Log "         MFA lookups will fail or describe the wrong tenant. Use Refresh MFA and sign in with an account from the tenant under investigation."
    }
}

function Update-LTIGraphToken {
    # Silent renewal with the refresh token. Returns $true on success.
    if (-not $script:GraphRefreshToken -or -not $script:GraphAuthority) { return $false }
    try {
        $resp = Invoke-RestMethod -Method Post -Uri "$($script:GraphAuthority)/oauth2/v2.0/token" -Body @{
            grant_type    = "refresh_token"
            client_id     = $script:GraphClientId
            refresh_token = $script:GraphRefreshToken
            scope         = (($script:GraphScopes -join " ") + " offline_access")
        } -ErrorAction Stop
        Set-LTIGraphToken -TokenResp $resp -Authority $script:GraphAuthority -Quiet
        Write-Log "Graph token renewed with refresh token"
        return $true
    } catch {
        $info = Get-LTIHttpErrorInfo -ErrorRecord $_
        Write-Log "Graph token renewal failed: $($info.Text)" "WARN"
        $script:GraphRefreshToken = $null
        return $false
    }
}

function Test-LTIGraphToken {
    # $true when a usable Graph token is available, renewing silently if needed.
    if ($script:GraphToken -and ([string]$script:GraphTokenTenant -ne [string]$script:ExoTenantId)) {
        Write-Log "Graph token belongs to a different Exchange connection - discarding" "WARN"
        Clear-LTIGraphToken
    }
    if ($script:GraphToken -and (Get-Date) -lt $script:GraphTokenExpiry) { return $true }
    return (Update-LTIGraphToken)
}

function Request-DeviceCode {
    param([Parameter(Mandatory = $true)][string]$Authority)

    $scopeStr = ($script:GraphScopes -join " ") + " offline_access"
    Write-Log "Device code: requesting from $Authority"
    $deviceResp = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/devicecode" -Body @{
        client_id = $script:GraphClientId
        scope     = $scopeStr
    } -ErrorAction Stop

    Write-Log "Device code issued (valid for $($deviceResp.expires_in)s)"
    return $deviceResp
}

function Open-LTIUrl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url
    )

    # Method 1: .NET ProcessStartInfo with UseShellExecute.
    # This is usually the most reliable way to open the default browser
    # from a WPF/PowerShell GUI.
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Url
        $psi.UseShellExecute = $true
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        Add-Log "  [OK] Browser opened: $Url"
        return $true
    } catch {
        Add-Log "  [WARN] Browser open method 1 failed: $($_.Exception.Message)"
    }

    # Method 2: rundll32 URL handler.
    try {
        Start-Process -FilePath "rundll32.exe" -ArgumentList "url.dll,FileProtocolHandler", $Url -ErrorAction Stop
        Add-Log "  [OK] Browser opened via rundll32: $Url"
        return $true
    } catch {
        Add-Log "  [WARN] Browser open method 2 failed: $($_.Exception.Message)"
    }

    # Method 3: explorer.exe URL handler.
    try {
        Start-Process -FilePath "explorer.exe" -ArgumentList $Url -ErrorAction Stop
        Add-Log "  [OK] Browser opened via explorer.exe: $Url"
        return $true
    } catch {
        Add-Log "  [WARN] Browser open method 3 failed: $($_.Exception.Message)"
    }

    # Method 4: cmd.exe start with proper quoting.
    try {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c start `"`" `"$Url`"" -WindowStyle Hidden -ErrorAction Stop
        Add-Log "  [OK] Browser opened via cmd start: $Url"
        return $true
    } catch {
        Add-Log "  [WARN] Browser open method 4 failed: $($_.Exception.Message)"
    }

    Add-Log "  [ERROR] Could not automatically open browser."
    Add-Log "  Manually open this URL: $Url"
    return $false
}

function ConvertTo-LTIUtcDateTime {
    # Returns a UTC [DateTime] or $null. Accepts ISO-8601 strings (Windows
    # PowerShell 5.1 leaves Graph timestamps as strings), [DateTime] and
    # [DateTimeOffset] (PowerShell 7 converts them automatically), and this
    # script's own "yyyy-MM-dd HH:mm:ss UTC" output format.
    param([object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }

    $text = ([string]$Value).Trim()
    if ($text.Length -eq 0) { return $null }
    $text = $text -replace '\s+UTC$', 'Z'

    $parsed = [DateTimeOffset]::MinValue
    $ok = [DateTimeOffset]::TryParse(
        $text,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$parsed)
    if ($ok) { return $parsed.UtcDateTime }
    return $null
}

function Format-LTIDateTime {
    param([object]$Value)

    $utc = ConvertTo-LTIUtcDateTime -Value $Value
    if ($null -eq $utc) {
        if ($null -eq $Value) { return "" }
        return ([string]$Value).Trim()
    }
    return $utc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
}

# -----------------------------------------------------------------------------
#  MFA: TENANT-LEVEL LOOKUPS (each one is optional - a failure here never
#  stops the per-user MFA check, it only leaves the related columns blank)
# -----------------------------------------------------------------------------
function Get-GraphAuthenticationMethodAuditEvents {
    # Entra directory audit events written by the Authentication Methods
    # service: who registered, changed, reset or deleted security info / MFA
    # methods, and when. Limited by audit retention (7 days on Entra ID Free,
    # 30 days with P1/P2). ALWAYS returns an array, even when empty.
    param([int]$DaysBack = 30)

    $events = [System.Collections.Generic.List[object]]::new()

    try {
        Add-Log "  Fetching MFA configuration audit events for the last $DaysBack day(s)..."

        $startUtc = (Get-Date).ToUniversalTime().AddDays(-1 * $DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $filter = "loggedByService eq 'Authentication Methods' and activityDateTime ge $startUtc"
        $uri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=' + [Uri]::EscapeDataString($filter)

        foreach ($item in (Get-LTIGraphPaged -Uri $uri)) {
            $activity = [string]$item.activityDisplayName

            # Keep the events that normally represent MFA/security-info registration,
            # updates, resets, deletes, or default-method changes.
            if ($activity -match '(security info|authentication method|authenticator|phone|FIDO|passkey|Temporary Access Pass|passwordless|MFA|multifactor|strong authentication)') {
                $events.Add($item)
            }
        }

        Add-Log "  [OK] Loaded $($events.Count) MFA/security-info audit event(s)"
    } catch {
        Add-Log "  [WARN] MFA configuration audit events unavailable: $($_.Exception.Message)"
        if ([int]$_.Exception.Data['LTIStatus'] -eq 403) {
            Add-Log "         Needs AuditLog.Read.All plus Reports Reader, Security Reader, Global Reader or Global Admin."
        }
        Add-Log "         MFA config date columns will be blank. MFA status itself is not affected."
        Write-Log "Get-GraphAuthenticationMethodAuditEvents failed: $_" "WARN"
    }

    return , $events.ToArray()
}

function Get-LTIDirectoryUserMap {
    # UPN (lower case) -> directory user (id, accountEnabled). Lets the MFA
    # check tell "no MFA on a live account" apart from "no MFA on a shared or
    # room mailbox whose sign-in is blocked", and gives stable object IDs for
    # audit-event matching.
    $map = @{}
    try {
        $users = Get-LTIGraphPaged -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,accountEnabled&$top=999'
        foreach ($u in $users) {
            if ($u.userPrincipalName) { $map[([string]$u.userPrincipalName).ToLowerInvariant()] = $u }
        }
        Add-Log "  [OK] Loaded sign-in state for $($map.Count) directory account(s)"
    } catch {
        Add-Log "  [WARN] Could not read directory accounts: $($_.Exception.Message)"
        Add-Log "         'Sign-In Allowed' will be blank. MFA status itself is not affected."
        Write-Log "Get-LTIDirectoryUserMap failed: $_" "WARN"
    }
    return $map
}

function Get-LTIRegistrationDetailsMap {
    # UPN (lower case) -> Entra userRegistrationDetails row. Only used for the
    # real default MFA method. This report needs Entra ID P1/P2; on tenants
    # without it the call is refused and Default Method stays blank.
    $map = @{}
    try {
        $rows = Get-LTIGraphPaged -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails'
        foreach ($r in $rows) {
            if ($r.userPrincipalName) { $map[([string]$r.userPrincipalName).ToLowerInvariant()] = $r }
        }
        Add-Log "  [OK] Loaded Entra registration report for $($map.Count) user(s)"
    } catch {
        Add-Log "  [INFO] Entra registration report not available (needs Entra ID P1/P2) - Default Method will be blank"
        Write-Log "Get-LTIRegistrationDetailsMap failed: $_" "WARN"
    }
    return $map
}

function Get-LTIDefaultMethodText {
    param($Registration)

    if (-not $Registration) { return "" }
    $names = @{
        push = 'Authenticator push'; oath = 'OATH code'; sms = 'SMS'; none = 'None'
        voiceMobile = 'Voice call (mobile)'; voiceAlternateMobile = 'Voice call (alt mobile)'; voiceOffice = 'Voice call (office)'
    }

    $sys = @($Registration.systemPreferredAuthenticationMethods | Where-Object { $_ })
    if ($Registration.isSystemPreferredAuthenticationMethodEnabled -eq $true -and $sys.Count -gt 0) {
        $label = @($sys | ForEach-Object { if ($names.ContainsKey([string]$_)) { $names[[string]$_] } else { [string]$_ } }) -join ' / '
        return "System-preferred: $label"
    }

    $pref = [string]$Registration.userPreferredMethodForSecondaryAuthentication
    if ([string]::IsNullOrWhiteSpace($pref)) { return "" }
    if ($names.ContainsKey($pref)) { return $names[$pref] }
    return $pref
}

function Get-LTIAuditTargetKeys {
    param([object]$AuditEvent)

    $keys = [System.Collections.Generic.List[string]]::new()

    foreach ($target in @($AuditEvent.targetResources)) {
        if ($null -eq $target) { continue }

        # UPN and object ID only. Display names are not unique, and attributing
        # another user's MFA change to this mailbox would mislead an investigation.
        foreach ($prop in @("userPrincipalName", "id")) {
            try {
                $value = [string]$target.$prop
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    $keys.Add($value.ToLowerInvariant())
                }
            } catch {}
        }

        # Some audit events include the affected user in modifiedProperties.
        foreach ($mp in @($target.modifiedProperties)) {
            if ($null -eq $mp) { continue }
            foreach ($field in @("newValue", "oldValue")) {
                try {
                    $value = [string]$mp.$field
                    if (-not [string]::IsNullOrWhiteSpace($value)) {
                        $cleanValue = $value.Trim('"').ToLowerInvariant()
                        if ($cleanValue -match '@') {
                            $keys.Add($cleanValue)
                        }
                    }
                } catch {}
            }
        }
    }

    return @($keys | Select-Object -Unique)
}

function Get-LTIMFAConfigAuditSummary {
    # Returns an object with:
    #   Summary - hashtable: UPN (lower case) -> first/last MFA config event
    #   Rows    - one flat row per (event, affected mailbox) for CSV export
    #
    # None of the parameters are mandatory. An EMPTY event list is the normal
    # case for a tenant with no recent MFA changes; the previous build declared
    # -AuditEvents as Mandatory, which PowerShell refuses to bind to an empty
    # array, and that is what aborted the whole MFA scan.
    param(
        [object[]]$AuditEvents = @(),
        [object[]]$Mailboxes = @(),
        [hashtable]$DirectoryByUpn = @{}
    )

    $summary = @{}
    $rows = [System.Collections.Generic.List[object]]::new()
    $result = [PSCustomObject]@{ Summary = $summary; Rows = $rows }

    if ($null -eq $AuditEvents -or $AuditEvents.Count -eq 0) { return $result }
    if ($null -eq $DirectoryByUpn) { $DirectoryByUpn = @{} }

    # Audit targets are matched to mailboxes by UPN or Entra object ID.
    $lookup = @{}
    $displayUpn = @{}
    foreach ($mb in @($Mailboxes)) {
        if ($null -eq $mb) { continue }
        $upn = [string]$mb.UserPrincipalName
        if ([string]::IsNullOrWhiteSpace($upn)) { continue }

        $upnLower = $upn.ToLowerInvariant()
        $lookup[$upnLower] = $upnLower
        $displayUpn[$upnLower] = $upn

        $objectId = [string]$mb.ExternalDirectoryObjectId
        if ([string]::IsNullOrWhiteSpace($objectId) -and $DirectoryByUpn.ContainsKey($upnLower)) {
            $objectId = [string]$DirectoryByUpn[$upnLower].id
        }
        if (-not [string]::IsNullOrWhiteSpace($objectId)) { $lookup[$objectId.ToLowerInvariant()] = $upnLower }
    }

    $eventsByUpn = @{}
    foreach ($ev in $AuditEvents) {
        if ($null -eq $ev) { continue }

        $matched = @{}
        foreach ($key in (Get-LTIAuditTargetKeys -AuditEvent $ev)) {
            if ($lookup.ContainsKey($key)) { $matched[$lookup[$key]] = $true }
        }

        foreach ($upnLower in @($matched.Keys)) {
            if (-not $eventsByUpn.ContainsKey($upnLower)) {
                $eventsByUpn[$upnLower] = [System.Collections.Generic.List[object]]::new()
            }
            $eventsByUpn[$upnLower].Add($ev)
        }
    }

    foreach ($upnLower in @($eventsByUpn.Keys)) {
        $events = @($eventsByUpn[$upnLower] | Sort-Object {
            $d = ConvertTo-LTIUtcDateTime -Value $_.activityDateTime
            if ($null -eq $d) { [DateTime]::MinValue } else { $d }
        })
        if ($events.Count -eq 0) { continue }

        $first = $events[0]
        $last = $events[-1]

        $summary[$upnLower] = [PSCustomObject]@{
            FirstConfigSeen = Format-LTIDateTime -Value $first.activityDateTime
            LastConfig      = Format-LTIDateTime -Value $last.activityDateTime
            LastEvent       = [string]$last.activityDisplayName
            EventCount      = $events.Count
        }

        foreach ($ev in $events) {
            $actor = ""; $ip = ""
            if ($ev.initiatedBy -and $ev.initiatedBy.user) {
                $actor = [string]$ev.initiatedBy.user.userPrincipalName
                if (-not $actor) { $actor = [string]$ev.initiatedBy.user.displayName }
                $ip = [string]$ev.initiatedBy.user.ipAddress
            }
            if (-not $actor -and $ev.initiatedBy -and $ev.initiatedBy.app) {
                $actor = "App: " + [string]$ev.initiatedBy.app.displayName
            }

            $rows.Add([PSCustomObject]@{
                UPN           = $displayUpn[$upnLower]
                Timestamp     = Format-LTIDateTime -Value $ev.activityDateTime
                Activity      = [string]$ev.activityDisplayName
                Result        = [string]$ev.result
                ResultReason  = [string]$ev.resultReason
                InitiatedBy   = $actor
                InitiatedByIP = $ip
                CorrelationId = [string]$ev.correlationId
            })
        }
    }

    return $result
}

function Get-LTIMFAContext {
    # Everything that is fetched once per tenant rather than once per user.
    param([object[]]$Mailboxes = @())

    $dir         = Get-LTIDirectoryUserMap
    $auditEvents = Get-GraphAuthenticationMethodAuditEvents -DaysBack 30
    $audit       = Get-LTIMFAConfigAuditSummary -AuditEvents $auditEvents -Mailboxes $Mailboxes -DirectoryByUpn $dir
    $reg         = Get-LTIRegistrationDetailsMap

    return @{
        DirectoryByUpn    = $dir
        AuditByUpn        = $audit.Summary
        AuditRows         = $audit.Rows
        RegistrationByUpn = $reg
    }
}

# -----------------------------------------------------------------------------
#  MFA: PER-USER METHODS
# -----------------------------------------------------------------------------
function ConvertTo-LTIMethodInfo {
    # One Graph authenticationMethod -> a flat row. Returns $null for the
    # password "method", which every account has and which is not MFA.
    param($Method)

    $type = ([string]$Method.'@odata.type') -replace '^#microsoft\.graph\.', ''
    if ([string]::IsNullOrWhiteSpace($type) -or $type -eq 'passwordAuthenticationMethod') { return $null }

    $def = $script:LTIMethodTypes[$type]
    if ($def) {
        $label = $def.Label
        $isMfa = [bool]$def.MFA
    } else {
        # A type this build does not know. Show it, but do not let an unknown
        # method turn a user "Enabled" - a false alarm is safer than false comfort.
        $label = $type -replace 'AuthenticationMethod$', ''
        $isMfa = $false
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($p in @('displayName', 'phoneNumber', 'phoneType', 'emailAddress', 'model', 'deviceTag', 'phoneAppVersion', 'platform', 'keyStrength')) {
        $v = [string]$Method.$p
        if (-not [string]::IsNullOrWhiteSpace($v)) { $parts.Add("$p=$v") }
    }
    if ($type -eq 'temporaryAccessPassAuthenticationMethod') {
        foreach ($p in @('isUsable', 'isUsableOnce', 'lifetimeInMinutes', 'startDateTime')) {
            if ($null -ne $Method.$p) {
                $v = $Method.$p
                if ($p -eq 'startDateTime') { $v = Format-LTIDateTime -Value $v }
                $parts.Add("$p=$v")
            }
        }
    }

    # Graph documents createdDateTime; some FIDO2 responses use creationDateTime.
    $created = $Method.createdDateTime
    if ($null -eq $created -or [string]::IsNullOrWhiteSpace([string]$created)) { $created = $Method.creationDateTime }

    return [PSCustomObject]@{
        Label       = $label
        MethodType  = $type
        CountsAsMFA = $isMfa
        Detail      = ($parts -join '; ')
        Created     = Format-LTIDateTime -Value $created
        LastUsed    = Format-LTIDateTime -Value $Method.lastUsedDateTime
        MethodId    = [string]$Method.id
    }
}

function Get-LTIMFARecord {
    # Builds the MFA grid/CSV row for one mailbox, plus one detail row per
    # registered method. With -SkipReason no Graph call is made and the user is
    # recorded as Unknown (used once the scan has been aborted).
    param(
        [Parameter(Mandatory = $true)]$Mailbox,
        [hashtable]$Context,
        [string]$SkipReason
    )

    if ($null -eq $Context) { $Context = @{} }
    $upn    = [string]$Mailbox.UserPrincipalName
    $upnKey = $upn.ToLowerInvariant()

    $audit = $null; $dir = $null; $reg = $null
    if ($Context.AuditByUpn)        { $audit = $Context.AuditByUpn[$upnKey] }
    if ($Context.DirectoryByUpn)    { $dir   = $Context.DirectoryByUpn[$upnKey] }
    if ($Context.RegistrationByUpn) { $reg   = $Context.RegistrationByUpn[$upnKey] }

    $signIn = ""
    if ($dir -and $null -ne $dir.accountEnabled) { $signIn = [string][bool]$dir.accountEnabled }

    $rec = [ordered]@{
        DisplayName        = $Mailbox.DisplayName
        UPN                = $upn
        MFAStatus          = "Unknown"
        MFAMethods         = ""
        MFAFirstConfigSeen = ""
        MFALastConfig      = ""
        MFALastConfigEvent = ""
        DefaultMethod      = Get-LTIDefaultMethodText -Registration $reg
        NewestMethodAdded  = ""
        AccountEnabled     = $signIn
        MailboxType        = [string]$Mailbox.RecipientTypeDetails
    }
    if ($audit) {
        $rec.MFAFirstConfigSeen = $audit.FirstConfigSeen
        $rec.MFALastConfig      = $audit.LastConfig
        $rec.MFALastConfigEvent = $audit.LastEvent
    }

    $details = [System.Collections.Generic.List[object]]::new()
    $httpStatus = 0
    $ok = $false

    if ($SkipReason) {
        $rec.MFAMethods = "Error: $SkipReason"
    } else {
        try {
            # Prefer the object ID - it avoids every UPN escaping edge case.
            $userRef = [Uri]::EscapeDataString($upn)
            if ($dir -and $dir.id) { $userRef = [string]$dir.id }

            $resp  = Invoke-LTIGraphGet -Uri "https://graph.microsoft.com/v1.0/users/$userRef/authentication/methods"
            $infos = @(@($resp.value) | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-LTIMethodInfo -Method $_ } | Where-Object { $null -ne $_ })

            # "Authenticator App (2), Phone (SMS/Call)" - first-seen order, with counts.
            $order = [System.Collections.Generic.List[string]]::new()
            $count = @{}
            $newest = $null
            foreach ($i in $infos) {
                if (-not $count.ContainsKey($i.Label)) { $order.Add($i.Label); $count[$i.Label] = 0 }
                $count[$i.Label]++

                $c = ConvertTo-LTIUtcDateTime -Value $i.Created
                if ($null -ne $c -and ($null -eq $newest -or $c -gt $newest)) { $newest = $c }

                $details.Add([PSCustomObject]@{
                    DisplayName = $Mailbox.DisplayName
                    UPN         = $upn
                    Method      = $i.Label
                    CountsAsMFA = $i.CountsAsMFA
                    Detail      = $i.Detail
                    Created     = $i.Created
                    LastUsed    = $i.LastUsed
                    MethodType  = $i.MethodType
                    MethodId    = $i.MethodId
                })
            }

            if ($order.Count -gt 0) {
                $rec.MFAMethods = @($order | ForEach-Object { if ($count[$_] -gt 1) { "$_ ($($count[$_]))" } else { $_ } }) -join ", "
            } else {
                $rec.MFAMethods = "None registered"
            }
            if ($null -ne $newest) { $rec.NewestMethodAdded = Format-LTIDateTime -Value $newest }

            # Enabled = at least one method that can satisfy an MFA prompt.
            # Email (password reset only), Temporary Access Pass and QR code do not count.
            if (@($infos | Where-Object { $_.CountsAsMFA }).Count -gt 0) { $rec.MFAStatus = "Enabled" } else { $rec.MFAStatus = "Disabled" }
            $ok = $true
        } catch {
            $httpStatus = [int]$_.Exception.Data['LTIStatus']
            $rec.MFAMethods = "Error: $($_.Exception.Message)"
            Write-Log "MFA lookup failed for ${upn}: $($_.Exception.Message)" "WARN"
        }
    }

    return [PSCustomObject]@{
        Record     = [PSCustomObject]$rec
        Details    = $details
        HttpStatus = $httpStatus
        Success    = $ok
    }
}

function Add-LTIMFARecords {
    # Queries MFA for the given mailboxes and appends the results to the
    # script-level caches. Needs a valid Graph token and $script:MFAContext.
    #
    # Fail-fast: if the first five lookups are all refused (401/403) and none
    # has succeeded, the problem is the sign-in (role or consent), not the
    # users. The scan stops there with one clear explanation instead of
    # hammering Graph with hundreds of requests that will all fail the same way.
    param([object[]]$Mailboxes = @())

    $total = @($Mailboxes).Count
    $done = 0; $okCount = 0; $refused = 0
    $abortReason = $null

    foreach ($mb in @($Mailboxes)) {
        if ($null -eq $mb) { continue }
        $done++
        if ($done % 5 -eq 0 -or $done -eq $total) {
            $lblProgress.Text = "MFA query: $done / $total"
            Flush-UI
        }

        if ($abortReason) {
            $res = Get-LTIMFARecord -Mailbox $mb -Context $script:MFAContext -SkipReason $abortReason
            $script:allMFAData.Add($res.Record)
            continue
        }

        # Long tenant + throttling can outlive the access token - renew quietly.
        if ((Get-Date) -ge $script:GraphTokenExpiry) { [void](Update-LTIGraphToken) }

        $res = Get-LTIMFARecord -Mailbox $mb -Context $script:MFAContext
        $script:allMFAData.Add($res.Record)
        foreach ($d in $res.Details) { $script:allMFAMethodDetails.Add($d) }

        if ($res.Success) {
            $okCount++
        } elseif (@(401, 403) -contains $res.HttpStatus) {
            $refused++
            if ($okCount -eq 0 -and $refused -ge 5) {
                $abortReason = "MFA scan stopped - Graph refused the first $refused lookups (" + ($res.Record.MFAMethods -replace '^Error:\s*', '') + ")"
                Add-Log "  [ERROR] Graph refused the first $refused MFA lookups - stopping the scan."
                Add-Log "          $($res.Record.MFAMethods -replace '^Error:\s*', '')"
                Add-Log "          The signed-in account needs Global Reader, Authentication Administrator,"
                Add-Log "          Privileged Authentication Administrator or Global Admin IN THIS TENANT, and"
                Add-Log "          'Microsoft Graph Command Line Tools' needs admin consent for"
                Add-Log "          UserAuthenticationMethod.Read.All. Fix that, then click Refresh MFA."
                # Do not keep reusing a token that cannot do the job.
                Clear-LTIGraphToken
            }
        }
    }

    return [PSCustomObject]@{ Total = $total; Succeeded = $okCount; Refused = $refused; Aborted = [bool]$abortReason }
}

# -----------------------------------------------------------------------------
#  MFA: SIGN-IN POLLING + PANEL REFRESH
# -----------------------------------------------------------------------------
function Start-MFAPolling {
    # Stores the device response, starts a DispatcherTimer that polls
    # the token endpoint every few seconds without blocking the UI.
    param($DeviceResp, [string]$Authority)

    $script:MFADeviceResp = $DeviceResp
    $script:MFAAuthority = $Authority
    $script:MFAPollDeadline = (Get-Date).AddSeconds([int]$DeviceResp.expires_in)
    $script:MFAPollInterval = [Math]::Max([int]$DeviceResp.interval, 5)

    # Show the code prominently in the log
    Add-Log ""
    Add-Log "  ============================================================"
    Add-Log "  GRAPH SIGN-IN REQUIRED"
    Add-Log "  ------------------------------------------------------------"
    Add-Log "  1. Browser URL: $($DeviceResp.verification_uri)"
    Add-Log "  2. Enter this code: $($DeviceResp.user_code)"
    Add-Log "     (code has been copied to your clipboard)"
    Add-Log "  3. Sign in with an admin account FROM THE TENANT BEING INVESTIGATED"
    Add-Log "     - results appear here automatically"
    Add-Log "  ============================================================"
    Add-Log ""

    try { Set-Clipboard -Value $DeviceResp.user_code } catch { Write-Log "Clipboard copy failed: $_" "WARN" }

    # Try to open browser using dedicated helper.
    # If browser launch fails, copy the URL to the clipboard so the user can paste it manually.
    $url = $DeviceResp.verification_uri

    if ([string]::IsNullOrWhiteSpace($url)) {
        $url = "https://microsoft.com/devicelogin"
    }

    $opened = Open-LTIUrl -Url $url

    if (-not $opened) {
        try {
            Set-Clipboard -Value $url
            Add-Log "  URL has been copied to clipboard."
        } catch {
            Add-Log "  [WARN] Could not copy URL to clipboard: $($_.Exception.Message)"
        }
    }

    $lblProgress.Text = "Waiting for sign-in (code: $($DeviceResp.user_code))"

    # DispatcherTimer runs on UI thread but only briefly each tick - non-blocking
    $script:MFATimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:MFATimer.Interval = [TimeSpan]::FromSeconds($script:MFAPollInterval)
    $script:MFATimer.Add_Tick({
        try {
            if ((Get-Date) -gt $script:MFAPollDeadline) {
                $script:MFATimer.Stop()
                Add-Log "  [ERROR] Device code expired before sign-in completed."
                Add-Log "          If the browser showed a block or consent error, that message is the real cause."
                $lblProgress.Text = "Sign-in timed out"
                Reset-MFAButtons
                return
            }

            $tokenResp = $null
            try {
                $tokenResp = Invoke-RestMethod -Method Post -Uri "$($script:MFAAuthority)/oauth2/v2.0/token" -Body @{
                    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                    client_id   = $script:GraphClientId
                    device_code = $script:MFADeviceResp.device_code
                } -ErrorAction Stop
            } catch {
                $info = Get-LTIHttpErrorInfo -ErrorRecord $_

                if ($info.Code -eq "authorization_pending") {
                    return  # keep polling
                }
                if ($info.Code -eq "slow_down") {
                    $script:MFATimer.Interval = [TimeSpan]::FromSeconds($script:MFATimer.Interval.TotalSeconds + 5)
                    return
                }
                # Terminal error
                $script:MFATimer.Stop()
                Write-Log "Device code terminal error: $($info.Text)" "ERROR"
                Add-Log "  [ERROR] Sign-in failed: $($info.Code)"
                Add-Log "          $($info.Message)"
                if ($info.Message -match 'AADSTS(53003|530033|50158)|Conditional Access') {
                    Add-Log "          A Conditional Access policy blocked this sign-in. Many tenants now block"
                    Add-Log "          device code flow - this admin account needs an exclusion from that policy."
                } elseif ($info.Message -match 'AADSTS(65001|65004|90094|90008)') {
                    Add-Log "          'Microsoft Graph Command Line Tools' needs admin consent in this tenant."
                }
                $lblProgress.Text = "Sign-in failed"
                Reset-MFAButtons
                return
            }

            # Got the token - stop the timer and run the queries
            $script:MFATimer.Stop()
            Add-Log "  [OK] Signed in successfully"
            Set-LTIGraphToken -TokenResp $tokenResp -Authority $script:MFAAuthority
            Complete-MFAFetch
        } catch {
            $script:MFATimer.Stop()
            Write-Log "MFA timer tick error: $_" "ERROR"
            Add-Log "  [ERROR] Polling error: $_"
            Reset-MFAButtons
        }
    })
    $script:MFATimer.Start()
    Write-Log "DispatcherTimer started, polling every $($script:MFAPollInterval)s"
}

function Reset-MFAButtons {
    $btnRefreshMFA.IsEnabled    = ($script:allMailboxes.Count -gt 0)
    $btnExportMFA.IsEnabled     = ($script:allMFAData.Count -gt 0)
    $btnConnect.IsEnabled       = $true
    $btnLoadMailboxes.IsEnabled = $script:isConnected
    $btnRun.IsEnabled           = ($script:allMailboxes.Count -gt 0)
}

function Clear-LTIMFACache {
    $script:allMFAData.Clear()
    $script:allMFAMethodDetails.Clear()
    $script:allMFAAuditRows.Clear()
    $script:MFAContext = $null
}

function Complete-MFAFetch {
    # Runs after a valid Graph token is in $script:GraphToken
    try {
        $lblProgress.Text = "Querying MFA status..."
        Flush-UI

        Clear-LTIMFACache
        $script:MFAContext = Get-LTIMFAContext -Mailboxes @($script:allMailboxes)
        foreach ($row in $script:MFAContext.AuditRows) { $script:allMFAAuditRows.Add($row) }

        Add-Log "  Querying authentication methods for $($script:allMailboxes.Count) mailbox(es)..."
        $run = Add-LTIMFARecords -Mailboxes @($script:allMailboxes)

        $filterText = $cmbMFAFilter.SelectedItem.Content.ToString()
        Update-MFAGrid -Filter $filterText

        $en = @($script:allMFAData | Where-Object { $_.MFAStatus -eq "Enabled"  }).Count
        $di = @($script:allMFAData | Where-Object { $_.MFAStatus -eq "Disabled" }).Count
        $un = @($script:allMFAData | Where-Object { $_.MFAStatus -eq "Unknown"  }).Count
        Add-Log "MFA Status: $en enabled, $di disabled, $un unknown of $($script:allMFAData.Count) users"

        if ($un -gt 0 -and -not $run.Aborted) {
            $sample = $script:allMFAData | Where-Object { $_.MFAStatus -eq "Unknown" } | Select-Object -First 1
            Add-Log "  [WARN] $un lookup(s) failed. First: $($sample.UPN) - $($sample.MFAMethods)"
        }

        if ($run.Aborted)      { $lblProgress.Text = "MFA failed - see log" }
        elseif ($un -gt 0)     { $lblProgress.Text = "MFA complete ($un unknown)" }
        else                   { $lblProgress.Text = "MFA complete" }
    } catch {
        Write-Log "Complete-MFAFetch error: $_" "ERROR"
        Write-Log "Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" "ERROR"
        Add-Log "  [ERROR] MFA query failed: $_"
        $lblProgress.Text = "MFA failed"
    } finally {
        Reset-MFAButtons
    }
}

function Invoke-PopulateMFA {
    if ($script:allMailboxes.Count -eq 0) {
        Add-Log "No mailboxes loaded - load mailboxes first"
        return
    }

    Write-Log "Invoke-PopulateMFA: starting"

    # Disable buttons during fetch
    $btnRefreshMFA.IsEnabled    = $false
    $btnExportMFA.IsEnabled     = $false
    $btnConnect.IsEnabled       = $false
    $btnLoadMailboxes.IsEnabled = $false
    $btnRun.IsEnabled           = $false

    Add-Log ""; Add-Log "--- MFA Status Refresh ---"

    # Reuse the cached sign-in if it is still valid (or can be renewed silently)
    if (Test-LTIGraphToken) {
        Write-Log "Reusing cached Graph token"
        Add-Log "  Using cached Graph sign-in"
        Complete-MFAFetch
        return
    }

    # Otherwise, kick off device code flow
    try {
        $lblProgress.Text = "Requesting device code..."
        Flush-UI

        $authority = Get-LTIGraphAuthority
        $deviceResp = $null
        try {
            $deviceResp = Request-DeviceCode -Authority $authority
        } catch {
            if ($authority -match '/organizations$') { throw }
            $info = Get-LTIHttpErrorInfo -ErrorRecord $_
            Write-Log "Device code request against $authority failed ($($info.Text)) - retrying with /organizations" "WARN"
            $authority = "https://login.microsoftonline.com/organizations"
            $deviceResp = Request-DeviceCode -Authority $authority
        }

        Start-MFAPolling -DeviceResp $deviceResp -Authority $authority
    } catch {
        $info = Get-LTIHttpErrorInfo -ErrorRecord $_
        Write-Log "Device code request failed: $($info.Text)" "ERROR"
        Write-Log "Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" "ERROR"
        Add-Log "  [ERROR] Could not start sign-in: $($info.Text)"
        $lblProgress.Text = "MFA failed"
        Reset-MFAButtons
    }
}

# -----------------------------------------------------------------------------
#  BASELINE CHECKBOX TOGGLE
# -----------------------------------------------------------------------------
$chkBaseline.Add_Checked({ $txtBaselinePath.IsEnabled = $true; $btnBaselineBrowse.IsEnabled = $true; $btnBaselineClear.IsEnabled = $true })
$chkBaseline.Add_Unchecked({ $txtBaselinePath.IsEnabled = $false; $btnBaselineBrowse.IsEnabled = $false; $btnBaselineClear.IsEnabled = $false; $txtBaselinePath.Text = "" })
$btnBaselineBrowse.Add_Click({
    $dlg = [System.Windows.Forms.FolderBrowserDialog]::new()
    $dlg.Description = "Select a previous Investigation_* folder as baseline"
    $dlg.SelectedPath = $txtOutputPath.Text
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $txtBaselinePath.Text = $dlg.SelectedPath }
})
$btnBaselineClear.Add_Click({ $txtBaselinePath.Text = "" })

# Button handlers
$btnCheckAll.Add_Click({ for ($i=1;$i-le 16;$i++) { $chkSteps[$i].IsChecked=$true }; $chkSteps[17].IsChecked=$true })
$btnUncheckAll.Add_Click({ for ($i=1;$i-le 16;$i++) { $chkSteps[$i].IsChecked=$false }; $chkSteps[17].IsChecked=$false })
$btnSelectAll.Add_Click({ $lstMailboxes.SelectAll() })
$btnSelectNone.Add_Click({ $lstMailboxes.UnselectAll() })
$btnBrowse.Add_Click({
    $dlg=[System.Windows.Forms.FolderBrowserDialog]::new(); $dlg.Description="Select output folder"; $dlg.SelectedPath=$txtOutputPath.Text
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $txtOutputPath.Text=$dlg.SelectedPath }
})

# MFA filter dropdown
$cmbMFAFilter.Add_SelectionChanged({
    if ($script:allMFAData.Count -gt 0) {
        $filterText = $cmbMFAFilter.SelectedItem.Content.ToString()
        Update-MFAGrid -Filter $filterText
    }
})

# Refresh MFA button
$btnRefreshMFA.Add_Click({ Invoke-PopulateMFA })

# Export MFA CSV button
$btnExportMFA.Add_Click({
    if ($script:allMFAData.Count -eq 0) { [System.Windows.MessageBox]::Show("No MFA data to export.","Export","OK","Warning"); return }
    $dlg = [System.Windows.Forms.SaveFileDialog]::new()
    $dlg.Title = "Export MFA Status CSV"
    $dlg.Filter = "CSV Files (*.csv)|*.csv"
    $dlg.FileName = "MFA_Status_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $dlg.InitialDirectory = $txtOutputPath.Text
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        @($script:allMFAData) | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
        Add-Log "MFA CSV exported: $($dlg.FileName)"
        [System.Windows.MessageBox]::Show("Exported $($script:allMFAData.Count) records.`n$($dlg.FileName)","Export Complete","OK","Information")
    }
})

# Connect
$btnConnect.Add_Click({
    try {
        $lblConnectionStatus.Text="Status: Connecting..."; $lblConnectionStatus.Foreground=[System.Windows.Media.Brushes]::Orange
        $ok=$false; try { Get-OrganizationConfig -ErrorAction Stop | Out-Null; $ok=$true } catch {}
        if (-not $ok) {
            # Allocate a hidden console so EXO's GetConsoleWindow() call gets a
            # valid HWND for MSAL/WAM. Hide it immediately so it never flashes.
            $allocated = [LTIConsoleSupport]::AllocConsole()
            if ($allocated) {
                $hWnd = [LTIConsoleSupport]::GetConsoleWindow()
                if ($hWnd -ne [IntPtr]::Zero) {
                    [LTIConsoleSupport]::ShowWindow($hWnd, [LTIConsoleSupport]::SW_HIDE) | Out-Null
                }
            }
            try {
                Connect-ExchangeOnline -ShowBanner:$false
            } finally {
                if ($allocated) { [LTIConsoleSupport]::FreeConsole() | Out-Null }
            }
        }
        $org=(Get-OrganizationConfig -ErrorAction Stop).DisplayName; $script:isConnected=$true
        $lblConnectionStatus.Text="Status: Connected to $org"; $lblConnectionStatus.Foreground=[System.Windows.Media.Brushes]::LightGreen
        $btnLoadMailboxes.IsEnabled=$true; Add-Log "Connected to Exchange Online ($org)"

        # Remember which tenant this is so the Graph (MFA) sign-in targets the same one.
        $script:ExoTenantId = $null
        try {
            $ci = Get-ConnectionInformation -ErrorAction Stop | Where-Object { $_.State -eq 'Connected' -and -not $_.IsEopSession } | Select-Object -First 1
            if ($ci -and $ci.TenantID) { $script:ExoTenantId = [string]$ci.TenantID }
        } catch { Write-Log "Get-ConnectionInformation failed: $_" "WARN" }
        Write-Log "Exchange Online tenant ID: $($script:ExoTenantId)"
        if ([string]::IsNullOrWhiteSpace($txtDomain.Text)) {
            $dd=(Get-AcceptedDomain|Where-Object{$_.Default -eq $true}).DomainName
            if ($dd) { $txtDomain.Text=$dd; Add-Log "Default domain: $dd" }
        }
    } catch { $lblConnectionStatus.Text="Status: Connection failed"; $lblConnectionStatus.Foreground=[System.Windows.Media.Brushes]::Red; Add-Log "Connection failed: $_" }
})

# Load Mailboxes - also triggers MFA population
$btnLoadMailboxes.Add_Click({
    $domain=$txtDomain.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($domain)) { [System.Windows.MessageBox]::Show("Please enter a domain.","Required","OK","Warning"); return }
    try {
        Add-Log "Loading mailboxes for $domain ..."; $lblProgress.Text="Loading mailboxes..."; $lstMailboxes.Items.Clear()
        $suffix="@"+$domain
        $mbs = $null
        try {
            $mbs = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop |
                   Where-Object { $_.PrimarySmtpAddress -like "*$suffix" } |
                   Select-Object DisplayName,UserPrincipalName,PrimarySmtpAddress,RecipientTypeDetails,ExternalDirectoryObjectId |
                   Sort-Object DisplayName
        } catch {
            Add-Log "  [ERROR] Get-Mailbox failed: $_"
            [System.Windows.MessageBox]::Show("Get-Mailbox failed:`n$_","Error","OK","Error")
            $lblProgress.Text="Ready"
            return
        }

        $script:allMailboxes = @($mbs)

        # A new mailbox list invalidates whatever the MFA panel was showing.
        Clear-LTIMFACache
        Update-MFAGrid -Filter ($cmbMFAFilter.SelectedItem.Content.ToString())
        $lblMFAEnabled.Text = "Enabled: -"; $lblMFADisabled.Text = "Disabled: -"; $lblMFATotal.Text = "Total: -"
        $btnExportMFA.IsEnabled = $false

        foreach ($mb in $script:allMailboxes) {
            $lstMailboxes.Items.Add("$($mb.DisplayName)  <$($mb.UserPrincipalName)>  [$($mb.RecipientTypeDetails)]") | Out-Null
        }
        $c = $script:allMailboxes.Count
        $lblMailboxCount.Text = "$c mailboxes loaded"
        $btnSelectAll.IsEnabled = $true
        $btnSelectNone.IsEnabled = $true
        $btnRun.IsEnabled = ($c -gt 0)
        Add-Log "Loaded $c mailboxes from $domain"
        $lblProgress.Text = "Ready"

        # MFA is populated on demand - user clicks "Refresh MFA" when ready.
        # This avoids any auto-fetch crashes and gives them control over when
        # to trigger the second sign-in for Graph.
        $btnRefreshMFA.IsEnabled = ($c -gt 0)
        Add-Log "Click 'Refresh MFA' to fetch MFA status (requires Graph sign-in)"

    } catch {
        Add-Log "  [ERROR] Load Mailboxes: $_"
        $lblProgress.Text = "Error"
        [System.Windows.MessageBox]::Show("Unexpected error:`n$_","Error","OK","Error")
    }
})

# Filter
$txtFilter.Add_TextChanged({
    $ft=$txtFilter.Text.Trim().ToLower(); $lstMailboxes.Items.Clear()
    foreach ($mb in $script:allMailboxes) {
        $e="$($mb.DisplayName)  <$($mb.UserPrincipalName)>  [$($mb.RecipientTypeDetails)]"
        if ([string]::IsNullOrWhiteSpace($ft) -or $e.ToLower().Contains($ft)) { $lstMailboxes.Items.Add($e)|Out-Null }
    }
})

# -----------------------------------------------------------------------------
#  INVESTIGATION HELPERS
# -----------------------------------------------------------------------------
function Search-UnifiedAuditLogPaged { param([hashtable]$Params,[int]$PageSize=5000)
    $sid=[guid]::NewGuid().ToString(); $Params["SessionId"]=$sid; $Params["SessionCommand"]="ReturnLargeSet"; $Params["ResultSize"]=$PageSize
    $all=[System.Collections.Generic.List[object]]::new(); $pg=1
    do { Add-Log "    Audit log query page $pg ..."; Flush-UI; $r=Search-UnifiedAuditLog @Params
        if ($null -eq $r -or @($r).Count -eq 0) { Add-Log "    No results."; break }
        $bc=@($r).Count; $all.AddRange(@($r)); Add-Log "    Page ${pg}: $bc record(s) (total: $($all.Count))"
        if ($bc -lt $PageSize) { break }; $pg++; if ($all.Count -ge 50000) { Add-Log "    [WARN] 50k cap reached."; break }
    } while ($true); return $all
}

function Search-UnifiedAuditLogAll { param([DateTime]$Start,[DateTime]$End,[string[]]$RecordTypes,[string[]]$Operations,[string]$UserIds,[string]$FreeText,[int]$PageSize=5000)
    $bp=@{StartDate=$Start;EndDate=$End}; if($UserIds){$bp["UserIds"]=$UserIds}; if($Operations){$bp["Operations"]=$Operations}; if($FreeText){$bp["FreeText"]=$FreeText}
    $all=[System.Collections.Generic.List[object]]::new()
    if ($RecordTypes -and $RecordTypes.Count -gt 0) { foreach ($rt in $RecordTypes) { Add-Log "    RecordType: $rt"; Flush-UI; $qp=$bp.Clone(); $qp["RecordType"]=$rt; $b=Search-UnifiedAuditLogPaged -Params $qp -PageSize $PageSize; if($b -and @($b).Count -gt 0){$all.AddRange(@($b))} } }
    else { $b=Search-UnifiedAuditLogPaged -Params $bp -PageSize $PageSize; if($b -and @($b).Count -gt 0){$all.AddRange(@($b))} }
    return $all
}

function Get-MessageTraceV2All { param([string]$SenderAddress,[string]$RecipientAddress,[DateTime]$Start,[DateTime]$End,[int]$MaxRounds=20)
    # Get-MessageTraceV2 accepts at most 10 days per query, so a 14- or 30-day
    # investigation is walked in windows of just under 10 days, newest first.
    # Inside each window the 5000-row pages are followed the way Microsoft
    # documents: EndDate = Received of the last row, plus StartingRecipientAddress.
    $all=[System.Collections.Generic.List[object]]::new()
    $windowEnd=$End; $windowNo=0
    while ($windowEnd -gt $Start) {
        $windowNo++
        $windowStart=$windowEnd.AddDays(-10).AddMinutes(1); if($windowStart -lt $Start){$windowStart=$Start}
        if ($windowNo -gt 1 -or $windowStart -gt $Start) { Add-Log "    Trace window ${windowNo}: $($windowStart.ToString('yyyy-MM-dd HH:mm')) to $($windowEnd.ToString('yyyy-MM-dd HH:mm'))"; Flush-UI }
        $ce=$windowEnd; $sr=$null
        $bp=@{StartDate=$windowStart;ResultSize=5000}; if($SenderAddress){$bp["SenderAddress"]=$SenderAddress}; if($RecipientAddress){$bp["RecipientAddress"]=$RecipientAddress}
        $rd=1; do { $qp=$bp.Clone(); $qp["EndDate"]=$ce; if($sr){$qp["StartingRecipientAddress"]=$sr}
            $r=Get-MessageTraceV2 @qp -ErrorAction Stop; if($null -eq $r -or @($r).Count -eq 0){break}; $b=@($r); $all.AddRange($b)
            Add-Log "    Trace round ${rd}: $($b.Count) record(s)"; if($b.Count -lt 5000){break}; $lr=$b[-1]; $ce=$lr.Received; $sr=$lr.RecipientAddress; $rd++; if($rd -gt $MaxRounds){Add-Log "    [WARN] Trace page limit reached for this window - results are truncated."; break}
        } while ($true)
        $windowEnd=$windowStart
    }
    return $all
}

function Export-ResultSet { param([string]$Name,[string]$FileName,[string]$OutFolder,$Data)
    $fp=Join-Path $OutFolder $FileName
    if ($null -eq $Data -or ($Data -is [System.Collections.IEnumerable] -and @($Data).Count -eq 0)) {
        $ep=$fp -replace '\.csv$','_EMPTY.txt'; ("NO DATA FOUND - " + (Get-Date -Format 'u'))|Out-File -FilePath $ep -Encoding UTF8; Add-Log "  [WARN] No data: $Name"; return 0 }
    if ($Data -is [string]) { $tp=$fp -replace '\.csv$','.txt'; $Data|Out-File -FilePath $tp -Encoding UTF8; Add-Log "  [OK] $Name - 1 record -> $FileName"; return 1 }
    else { $c=@($Data).Count; @($Data)|Export-Csv -Path $fp -NoTypeInformation -Encoding UTF8; Add-Log "  [OK] $Name - $c record(s) -> $FileName"; return $c }
}

# -----------------------------------------------------------------------------
#  BASELINE COMPARISON FUNCTION
# -----------------------------------------------------------------------------
function Compare-BaselineCSV {
    param(
        [string]$Label,
        [string]$BaselineFile,
        [string]$CurrentFile,
        [string[]]$KeyColumns,
        [string[]]$CompareColumns,
        # Optional: only compare rows where this column equals this value. Used
        # for tenant-level files so one user's report lists only that user's rows.
        [string]$FilterColumn,
        [string]$FilterValue
    )

    $changes = [System.Collections.Generic.List[string]]::new()

    $baseExists = Test-Path $BaselineFile
    $currExists = Test-Path $CurrentFile
    $baseEmpty = Test-Path ($BaselineFile -replace '\.csv$','_EMPTY.txt')
    $currEmpty = Test-Path ($CurrentFile -replace '\.csv$','_EMPTY.txt')

    if (-not $baseExists -and -not $baseEmpty) { return $changes }
    if ($baseEmpty -and $currEmpty) { return $changes }

    $baseData = @()
    $currData = @()

    if ($baseExists) { $baseData = @(Import-Csv -Path $BaselineFile -Encoding UTF8) }
    if ($currExists) { $currData = @(Import-Csv -Path $CurrentFile -Encoding UTF8) }

    if ($FilterColumn) {
        $baseData = @($baseData | Where-Object { $_.$FilterColumn -eq $FilterValue })
        $currData = @($currData | Where-Object { $_.$FilterColumn -eq $FilterValue })
        if ($baseData.Count -eq 0 -and $currData.Count -eq 0) { return $changes }
    }

    if ($baseEmpty -and $currData.Count -gt 0) {
        $changes.Add("[NEW] ${Label}: $($currData.Count) item(s) added (none existed in baseline)")
        foreach ($row in $currData) {
            $keyVal = ($KeyColumns | ForEach-Object { $row.$_ }) -join ' / '
            $changes.Add("  + ADDED: $keyVal")
        }
        return $changes
    }

    if ($currEmpty -and $baseData.Count -gt 0) {
        $changes.Add("[REMOVED] ${Label}: All $($baseData.Count) item(s) removed since baseline")
        foreach ($row in $baseData) {
            $keyVal = ($KeyColumns | ForEach-Object { $row.$_ }) -join ' / '
            $changes.Add("  - REMOVED: $keyVal")
        }
        return $changes
    }

    $baseHash = @{}
    foreach ($row in $baseData) {
        $key = ($KeyColumns | ForEach-Object { $row.$_ }) -join '||'
        $baseHash[$key] = $row
    }

    $currHash = @{}
    foreach ($row in $currData) {
        $key = ($KeyColumns | ForEach-Object { $row.$_ }) -join '||'
        $currHash[$key] = $row
    }

    foreach ($key in $currHash.Keys) {
        if (-not $baseHash.ContainsKey($key)) {
            $dispKey = $key -replace '\|\|',' / '
            $changes.Add("  + ADDED: $dispKey")
        }
    }

    foreach ($key in $baseHash.Keys) {
        if (-not $currHash.ContainsKey($key)) {
            $dispKey = $key -replace '\|\|',' / '
            $changes.Add("  - REMOVED: $dispKey")
        }
    }

    foreach ($key in $currHash.Keys) {
        if ($baseHash.ContainsKey($key)) {
            $diffs = @()
            foreach ($col in $CompareColumns) {
                $oldVal = "$($baseHash[$key].$col)"
                $newVal = "$($currHash[$key].$col)"
                if ($oldVal -ne $newVal) {
                    $diffs += "$col : '$oldVal' -> '$newVal'"
                }
            }
            if ($diffs.Count -gt 0) {
                $dispKey = $key -replace '\|\|',' / '
                $changes.Add("  ~ MODIFIED: $dispKey")
                foreach ($d in $diffs) { $changes.Add("      $d") }
            }
        }
    }

    if ($changes.Count -gt 0) {
        $changes.Insert(0, "[$Label] $($changes.Count) change(s) detected:")
    }

    return $changes
}

function Invoke-BaselineComparison {
    param(
        [string]$BaselineUserFolder,
        [string]$CurrentUserFolder,
        [string]$UPN
    )

    $report = [System.Collections.Generic.List[string]]::new()
    $report.Add("Baseline Comparison Report: $UPN")
    $report.Add("=" * 60)
    $report.Add("Baseline : $BaselineUserFolder")
    $report.Add("Current  : $CurrentUserFolder")
    $report.Add("Generated: $(Get-Date -Format 'u')")
    $report.Add("")

    $totalChanges = 0

    $c = Compare-BaselineCSV -Label "Inbox Rules" `
        -BaselineFile (Join-Path $BaselineUserFolder "03_Inbox_Rules.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "03_Inbox_Rules.csv") `
        -KeyColumns @("Name","RuleIdentity") `
        -CompareColumns @("Enabled","ForwardTo","ForwardAsAttachmentTo","RedirectTo","DeleteMessage","MoveToFolder","MarkAsRead","SubjectContains","BodyContains","FromAddress","SentTo")
    if ($c.Count -gt 0) { $report.AddRange($c); $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Mailbox Forwarding" `
        -BaselineFile (Join-Path $BaselineUserFolder "04_Mailbox_Forwarding.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "04_Mailbox_Forwarding.csv") `
        -KeyColumns @("UserPrincipalName") `
        -CompareColumns @("ForwardingAddress","ForwardingSmtpAddress","DeliverToMailboxAndForward")
    if ($c.Count -gt 0) { $report.AddRange($c); $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Transport Rules" `
        -BaselineFile (Join-Path $BaselineUserFolder "05_Transport_Rules.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "05_Transport_Rules.csv") `
        -KeyColumns @("Name") `
        -CompareColumns @("State","Priority","Description","Mode")
    if ($c.Count -gt 0) { $report.AddRange($c); $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Full Access Permissions" `
        -BaselineFile (Join-Path $BaselineUserFolder "06a_FullAccess_Permissions.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "06a_FullAccess_Permissions.csv") `
        -KeyColumns @("User") `
        -CompareColumns @("AccessRights","Deny")
    if ($c.Count -gt 0) { $report.AddRange($c); $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Send-As Permissions" `
        -BaselineFile (Join-Path $BaselineUserFolder "06b_SendAs_Permissions.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "06b_SendAs_Permissions.csv") `
        -KeyColumns @("Trustee") `
        -CompareColumns @("AccessControlType","AccessRights")
    if ($c.Count -gt 0) { $report.AddRange($c); $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Send on Behalf" `
        -BaselineFile (Join-Path $BaselineUserFolder "06c_SendOnBehalf.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "06c_SendOnBehalf.csv") `
        -KeyColumns @("GrantSendOnBehalfTo") `
        -CompareColumns @("GrantSendOnBehalfTo")
    if ($c.Count -gt 0) { $report.AddRange($c); $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Calendar Delegates" `
        -BaselineFile (Join-Path $BaselineUserFolder "06d_Calendar_Delegates.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "06d_Calendar_Delegates.csv") `
        -KeyColumns @("User") `
        -CompareColumns @("AccessRights","SharingPermissionFlags")
    if ($c.Count -gt 0) { $report.AddRange($c); $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Auto-Reply / OOF" `
        -BaselineFile (Join-Path $BaselineUserFolder "07_AutoReply_OOF.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "07_AutoReply_OOF.csv") `
        -KeyColumns @("AutoReplyState") `
        -CompareColumns @("AutoReplyState","InternalMessage","ExternalMessage","ExternalAudience","StartTime","EndTime")
    if ($c.Count -gt 0) { $report.AddRange($c); $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Mobile Devices" `
        -BaselineFile (Join-Path $BaselineUserFolder "08_Mobile_Devices.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "08_Mobile_Devices.csv") `
        -KeyColumns @("DeviceId") `
        -CompareColumns @("FriendlyName","DeviceModel","DeviceOS","DeviceAccessState")
    if ($c.Count -gt 0) { $report.AddRange($c); $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Mailbox Audit Config" `
        -BaselineFile (Join-Path $BaselineUserFolder "15_Mailbox_Audit_Config.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "15_Mailbox_Audit_Config.csv") `
        -KeyColumns @("UserPrincipalName") `
        -CompareColumns @("AuditEnabled","AuditLogAgeLimit","AuditAdmin","AuditDelegate","AuditOwner")
    if ($c.Count -gt 0) { $report.AddRange($c); $report.Add(""); $totalChanges += $c.Count }

    # MFA baseline comparison. 17_MFA_Status.csv is a tenant-level file, so it is
    # filtered to this user - otherwise every user's report lists everyone's changes.
    $c = Compare-BaselineCSV -Label "MFA Status" `
        -BaselineFile (Join-Path (Split-Path $BaselineUserFolder -Parent) "17_MFA_Status.csv") `
        -CurrentFile (Join-Path (Split-Path $CurrentUserFolder -Parent) "17_MFA_Status.csv") `
        -KeyColumns @("UPN") `
        -CompareColumns @("MFAStatus","MFAMethods","MFAFirstConfigSeen","MFALastConfig","MFALastConfigEvent","DefaultMethod") `
        -FilterColumn "UPN" -FilterValue $UPN
    if ($c.Count -gt 0) { $report.AddRange($c); $report.Add(""); $totalChanges += $c.Count }

    if ($totalChanges -eq 0) {
        $report.Add("[NO CHANGES] Configuration is identical to baseline.")
    } else {
        $report.Insert(6, "TOTAL CHANGES: $totalChanges")
    }

    return [PSCustomObject]@{
        UPN          = $UPN
        TotalChanges = $totalChanges
        Report       = $report
    }
}

# -----------------------------------------------------------------------------
#  CORE INVESTIGATION FUNCTION (per mailbox, step-aware)
# -----------------------------------------------------------------------------
function Invoke-MailboxInvestigation { param([string]$UPN,[DateTime]$StartDate,[DateTime]$EndDate,[string]$OutputFolder,[hashtable]$EnabledSteps)
    if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
    $findings=[PSCustomObject]@{UPN=$UPN;DisplayName="";SignInsOK=0;SignInsFailed=0;UniqueIPs=0;ForwardingActive=$false;ForwardingTarget="";SuspiciousRules=0;TotalRules=0;OAuthConsents=0;AdminActions=0;FileEvents=0;OutboundMail=0;AuditEnabled=$null;MFAStatus="NotChecked";MFAMethods="";NewMFAMethods=0;AccountEnabled="";Errors=[System.Collections.Generic.List[string]]::new()}
    # AuditEnabled stays $null and MFAStatus stays "NotChecked" until the relevant check
    # actually runs, so a skipped or failed check is never reported as "off".

    Add-Log "Verifying mailbox: $UPN"; Flush-UI
    try { $mbx=Get-Mailbox -Identity $UPN -ErrorAction Stop; $findings.DisplayName=$mbx.DisplayName; Add-Log "  [OK] Mailbox: $($mbx.DisplayName) [$($mbx.PrimarySmtpAddress)]" }
    catch { Add-Log "  [ERROR] Not found: $_"; $findings.Errors.Add("Not found: $_"); return $findings }

    if ($EnabledSteps[1]) { Add-Log "======================================================================"; Add-Log "  1. Sign-In and Authentication Events"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("UserLoggedIn","UserLoginFailed","ForeignRealmIndexLogonInitialAuthUsingADFSFederatedToken","PasswordLogonInitialAuthUsingPassword")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=$_.CreationDate;Operation=$a.Operation;ResultStatus=$a.ResultStatus;LogonError=$a.LogonError;ClientIP=$a.ClientIPAddress;UserAgent=$a.ExtendedProperties|Where-Object{$_.Name -eq "UserAgent"}|Select-Object -ExpandProperty Value -ErrorAction SilentlyContinue;RequestType=$a.ExtendedProperties|Where-Object{$_.Name -eq "RequestType"}|Select-Object -ExpandProperty Value -ErrorAction SilentlyContinue;Application=$a.ApplicationId;Workload=$a.Workload}}
            Export-ResultSet -Name "Sign-In Events" -FileName "01_SignIn_Events.csv" -OutFolder $OutputFolder -Data $parsed
            $findings.SignInsOK=@($parsed|Where-Object{$_.Operation -eq "UserLoggedIn"}).Count; $findings.SignInsFailed=@($parsed|Where-Object{$_.Operation -eq "UserLoginFailed"}).Count; $findings.UniqueIPs=@($parsed|Where-Object{$_.ClientIP}|Select-Object -ExpandProperty ClientIP -Unique).Count
            Add-Log "  Sign-ins: $($findings.SignInsOK) ok, $($findings.SignInsFailed) failed, $($findings.UniqueIPs) IPs"
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Sign-ins: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 1" }

    if ($EnabledSteps[2]) { Add-Log "======================================================================"; Add-Log "  2. Mailbox Activity"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("MailboxLogin","MailItemsAccessed","Send","SendAs","SendOnBehalf","Create","HardDelete","SoftDelete","MoveToDeletedItems","Update","Copy","Move")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops -RecordTypes @("ExchangeItem","ExchangeItemAggregated")
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=$_.CreationDate;Operation=$a.Operation;ClientIP=$a.ClientIPAddress;ClientInfo=$a.ClientInfoString;ItemSubject=$a.Item.Subject;Folder=$a.Item.ParentFolder.Path;ResultStatus=$a.ResultStatus}}
            Export-ResultSet -Name "Mailbox Activity" -FileName "02_Mailbox_Activity.csv" -OutFolder $OutputFolder -Data $parsed
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Mailbox: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 2" }

    if ($EnabledSteps[3]) { Add-Log "======================================================================"; Add-Log "  3. Inbox Rules"; Add-Log "======================================================================"; Flush-UI
        try { $rules=Get-InboxRule -Mailbox $UPN -IncludeHidden|Select-Object Name,Description,Enabled,Priority,@{N='ForwardTo';E={($_.ForwardTo -join '; ')}},@{N='ForwardAsAttachmentTo';E={($_.ForwardAsAttachmentTo -join '; ')}},@{N='RedirectTo';E={($_.RedirectTo -join '; ')}},@{N='DeleteMessage';E={$_.DeleteMessage}},@{N='MoveToFolder';E={$_.MoveToFolder}},@{N='MarkAsRead';E={$_.MarkAsRead}},@{N='SubjectContains';E={($_.SubjectContainsWords -join '; ')}},@{N='BodyContains';E={($_.BodyContainsWords -join '; ')}},@{N='FromAddress';E={($_.From -join '; ')}},@{N='SentTo';E={($_.SentTo -join '; ')}},Identity,RuleIdentity
            Export-ResultSet -Name "Inbox Rules" -FileName "03_Inbox_Rules.csv" -OutFolder $OutputFolder -Data $rules
            $findings.TotalRules=@($rules).Count; $sus=@($rules)|Where-Object{$_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or $_.DeleteMessage -eq $true -or $_.MarkAsRead -eq $true}; $findings.SuspiciousRules=@($sus).Count
            if ($findings.SuspiciousRules -gt 0) { Add-Log "  [WARN] *** $($findings.SuspiciousRules) SUSPICIOUS RULE(S) ***"; foreach($sr in $sus){$d="    Rule: '$($sr.Name)'"; if($sr.ForwardTo){$d+=" Fwd=$($sr.ForwardTo)"}; if($sr.RedirectTo){$d+=" Redir=$($sr.RedirectTo)"}; if($sr.DeleteMessage){$d+=" DEL"}; if($sr.MarkAsRead){$d+=" READ"}; Add-Log $d} }
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Rules: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 3" }

    if ($EnabledSteps[4]) { Add-Log "======================================================================"; Add-Log "  4. Mailbox Forwarding (SMTP)"; Add-Log "======================================================================"; Flush-UI
        try { $fw=Get-Mailbox -Identity $UPN|Select-Object DisplayName,UserPrincipalName,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward
            Export-ResultSet -Name "Forwarding" -FileName "04_Mailbox_Forwarding.csv" -OutFolder $OutputFolder -Data $fw
            if($fw.ForwardingAddress -or $fw.ForwardingSmtpAddress){$findings.ForwardingActive=$true;$findings.ForwardingTarget=if($fw.ForwardingSmtpAddress){$fw.ForwardingSmtpAddress}else{$fw.ForwardingAddress};Add-Log "  [WARN] *** FORWARDING ACTIVE -> $($findings.ForwardingTarget) ***"}else{Add-Log "  No forwarding."}
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Fwd: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 4" }

    if ($EnabledSteps[5]) { Add-Log "======================================================================"; Add-Log "  5. Transport Rules"; Add-Log "======================================================================"; Flush-UI
        try { $tr=Get-TransportRule|Where-Object{$_.SentTo -contains $UPN -or $_.From -contains $UPN -or $_.Description -match [regex]::Escape($UPN) -or $_.SentTo -contains $mbx.PrimarySmtpAddress -or $_.From -contains $mbx.PrimarySmtpAddress}|Select-Object Name,State,Priority,Description,Mode; Export-ResultSet -Name "Transport Rules" -FileName "05_Transport_Rules.csv" -OutFolder $OutputFolder -Data $tr
        } catch { Add-Log "  [WARN] $_" }; Flush-UI
    } else { Add-Log "  [SKIP] Step 5" }

    if ($EnabledSteps[6]) { Add-Log "======================================================================"; Add-Log "  6. Permissions / Delegates"; Add-Log "======================================================================"; Flush-UI
        try { $fa=Get-MailboxPermission -Identity $UPN|Where-Object{$_.IsInherited -eq $false -and $_.User -ne "NT AUTHORITY\SELF" -and $_.AccessRights -contains "FullAccess"}|Select-Object User,AccessRights,IsInherited,Deny; Export-ResultSet -Name "Full Access" -FileName "06a_FullAccess_Permissions.csv" -OutFolder $OutputFolder -Data $fa
            $sa=Get-RecipientPermission -Identity $UPN|Where-Object{$_.Trustee -ne "NT AUTHORITY\SELF"}|Select-Object Trustee,AccessControlType,AccessRights; Export-ResultSet -Name "Send-As" -FileName "06b_SendAs_Permissions.csv" -OutFolder $OutputFolder -Data $sa
            $sob=Get-Mailbox -Identity $UPN|Select-Object @{N='GrantSendOnBehalfTo';E={($_.GrantSendOnBehalfTo -join '; ')}}; Export-ResultSet -Name "Send on Behalf" -FileName "06c_SendOnBehalf.csv" -OutFolder $OutputFolder -Data $sob
            try { $cid=$UPN+":\Calendar"; $cd=Get-MailboxFolderPermission -Identity $cid -ErrorAction Stop|Where-Object{$_.User.DisplayName -ne "Default" -and $_.User.DisplayName -ne "Anonymous"}|Select-Object @{N='User';E={$_.User.DisplayName}},AccessRights,SharingPermissionFlags; Export-ResultSet -Name "Calendar" -FileName "06d_Calendar_Delegates.csv" -OutFolder $OutputFolder -Data $cd } catch { Add-Log "  [WARN] Calendar: $_" }
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Perms: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 6" }

    if ($EnabledSteps[7]) { Add-Log "======================================================================"; Add-Log "  7. Auto-Reply / OOF"; Add-Log "======================================================================"; Flush-UI
        try { $oof=Get-MailboxAutoReplyConfiguration -Identity $UPN|Select-Object AutoReplyState,StartTime,EndTime,@{N='InternalMessage';E={$s=$_.InternalMessage -replace '<[^>]+>','';if($s.Length -gt 500){$s.Substring(0,500)}else{$s}}},@{N='ExternalMessage';E={$s=$_.ExternalMessage -replace '<[^>]+>','';if($s.Length -gt 500){$s.Substring(0,500)}else{$s}}},ExternalAudience
            Export-ResultSet -Name "Auto-Reply" -FileName "07_AutoReply_OOF.csv" -OutFolder $OutputFolder -Data $oof
            if($oof.AutoReplyState -ne "Disabled"){Add-Log "  [WARN] Auto-Reply ENABLED"}else{Add-Log "  Disabled."}
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("OOF: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 7" }

    if ($EnabledSteps[8]) { Add-Log "======================================================================"; Add-Log "  8. Mobile Devices"; Add-Log "======================================================================"; Flush-UI
        try { $md=Get-MobileDevice -Mailbox $UPN -ErrorAction Stop|Select-Object FriendlyName,DeviceModel,DeviceOS,DeviceType,DeviceId,FirstSyncTime,DeviceAccessState,DeviceAccessStateReason,@{N='LastSync';E={$_.LastSyncAttemptTime}}; Export-ResultSet -Name "Mobile Devices" -FileName "08_Mobile_Devices.csv" -OutFolder $OutputFolder -Data $md } catch { Add-Log "  [WARN] $_" }; Flush-UI
    } else { Add-Log "  [SKIP] Step 8" }

    if ($EnabledSteps[9]) { Add-Log "======================================================================"; Add-Log "  9. OAuth / App Consent"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("Consent to application.","Add OAuth2PermissionGrant.","Add app role assignment grant to user.","Add delegated permission grant.","Add application.")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops -RecordTypes @("AzureActiveDirectory")
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=$_.CreationDate;Operation=$a.Operation;Target=($a.Target|ForEach-Object{$_.Id}) -join '; ';ModifiedProps=($a.ModifiedProperties|ForEach-Object{"$($_.Name)=$($_.NewValue)"}) -join '; ';ClientIP=$a.ClientIPAddress;ResultStatus=$a.ResultStatus;ActorUPN=$a.UserId}}
            Export-ResultSet -Name "OAuth" -FileName "09_OAuth_App_Consent.csv" -OutFolder $OutputFolder -Data $parsed; $findings.OAuthConsents=@($parsed).Count
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("OAuth: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 9" }

    if ($EnabledSteps[10]) { Add-Log "======================================================================"; Add-Log "  10. Rule Changes"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("New-InboxRule","Set-InboxRule","Enable-InboxRule","Remove-InboxRule","UpdateInboxRules","New-TransportRule","Set-TransportRule")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=$_.CreationDate;Operation=$a.Operation;Parameters=($a.Parameters|ForEach-Object{"$($_.Name)=$($_.Value)"}) -join '; ';ClientIP=$a.ClientIPAddress;SessionId=$a.SessionId}}
            Export-ResultSet -Name "Rule Changes" -FileName "10_Rule_Changes.csv" -OutFolder $OutputFolder -Data $parsed
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("RuleChg: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 10" }

    if ($EnabledSteps[11]) { Add-Log "======================================================================"; Add-Log "  11. File Activity"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("FileDownloaded","FileUploaded","FileDeleted","FileModified","FileRenamed","FileMoved","FileCopied","SharingSet","AnonymousLinkCreated","CompanyLinkCreated","SharingInvitationCreated","AddedToSecureLink")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops -RecordTypes @("SharePointFileOperation")
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=$_.CreationDate;Operation=$a.Operation;FileName=$a.SourceFileName;FileUrl=$a.ObjectId;SiteUrl=$a.SiteUrl;ClientIP=$a.ClientIPAddress;UserAgent=$a.UserAgent}}
            Export-ResultSet -Name "File Activity" -FileName "11_File_Activity.csv" -OutFolder $OutputFolder -Data $parsed; $findings.FileEvents=@($parsed).Count
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Files: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 11" }

    if ($EnabledSteps[12]) { Add-Log "======================================================================"; Add-Log "  12. Admin Actions"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("Add member to role.","Add user.","Reset user password.","Set force change user password.","Update user.","Delete user.","Set-Mailbox","Add-MailboxPermission","Remove-MailboxPermission","New-ManagementRoleAssignment")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=$_.CreationDate;Operation=$a.Operation;Target=($a.Target|ForEach-Object{$_.Id}) -join '; ';Parameters=($a.Parameters|ForEach-Object{"$($_.Name)=$($_.Value)"}) -join '; ';ClientIP=$a.ClientIPAddress;ResultStatus=$a.ResultStatus}}
            Export-ResultSet -Name "Admin Actions" -FileName "12_Admin_Actions.csv" -OutFolder $OutputFolder -Data $parsed; $findings.AdminActions=@($parsed).Count
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Admin: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 12" }

    if ($EnabledSteps[13]) { Add-Log "======================================================================"; Add-Log "  13. eDiscovery"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("SearchStarted","SearchExportDownloaded","New-ComplianceSearch","New-ComplianceSearchAction","CaseAdded")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=$_.CreationDate;Operation=$a.Operation;Parameters=($a.Parameters|ForEach-Object{"$($_.Name)=$($_.Value)"}) -join '; ';ClientIP=$a.ClientIPAddress}}
            Export-ResultSet -Name "eDiscovery" -FileName "13_eDiscovery_Activity.csv" -OutFolder $OutputFolder -Data $parsed
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("eDisc: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 13" }

    if ($EnabledSteps[14]) { Add-Log "======================================================================"; Add-Log "  14. Message Trace"; Add-Log "======================================================================"; Flush-UI
        try { Add-Log "  Outbound..."; Flush-UI; $ob=Get-MessageTraceV2All -SenderAddress $UPN -Start $StartDate -End $EndDate
            $obs=$ob|Select-Object Received,SenderAddress,RecipientAddress,Subject,Status,@{N='FromIP';E={$_.FromIP}},Size,MessageId; Export-ResultSet -Name "Outbound" -FileName "14a_MessageTrace_Outbound.csv" -OutFolder $OutputFolder -Data $obs; $findings.OutboundMail=@($ob).Count
            Add-Log "  Inbound..."; Flush-UI; $ib=Get-MessageTraceV2All -RecipientAddress $UPN -Start $StartDate -End $EndDate
            $ibs=$ib|Select-Object Received,SenderAddress,RecipientAddress,Subject,Status,@{N='FromIP';E={$_.FromIP}},Size,MessageId; Export-ResultSet -Name "Inbound" -FileName "14b_MessageTrace_Inbound.csv" -OutFolder $OutputFolder -Data $ibs
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Trace: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 14" }

    if ($EnabledSteps[15]) { Add-Log "======================================================================"; Add-Log "  15. Audit Config"; Add-Log "======================================================================"; Flush-UI
        try { $ac=Get-Mailbox -Identity $UPN|Select-Object DisplayName,UserPrincipalName,AuditEnabled,AuditLogAgeLimit,@{N='AuditAdmin';E={($_.AuditAdmin -join ', ')}},@{N='AuditDelegate';E={($_.AuditDelegate -join ', ')}},@{N='AuditOwner';E={($_.AuditOwner -join ', ')}}
            Export-ResultSet -Name "Audit Config" -FileName "15_Mailbox_Audit_Config.csv" -OutFolder $OutputFolder -Data $ac; $findings.AuditEnabled=$ac.AuditEnabled
            if($ac.AuditEnabled -ne $true){Add-Log "  [WARN] AUDITING DISABLED"}else{Add-Log "  Auditing enabled."}
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Audit: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 15" }

    if ($EnabledSteps[16]) { Add-Log "======================================================================"; Add-Log "  16. Catch-All Audit"; Add-Log "======================================================================"; Add-Log "  Pulling ALL records..."; Flush-UI
        try { $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=$_.CreationDate;RecordType=$_.RecordType;Operation=$a.Operation;Workload=$a.Workload;ClientIP=$a.ClientIPAddress;ResultStatus=$a.ResultStatus;ObjectId=$a.ObjectId}}
            Export-ResultSet -Name "All Audit" -FileName "16_All_Audit_Activity.csv" -OutFolder $OutputFolder -Data $parsed
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("CatchAll: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 16" }

    # MFA findings come from the MFA cache (Refresh MFA / step 17). No cache entry = "NotChecked".
    $cachedMFA = $script:allMFAData | Where-Object { $_.UPN -eq $UPN } | Select-Object -First 1
    if ($cachedMFA) {
        $findings.MFAStatus      = [string]$cachedMFA.MFAStatus
        $findings.MFAMethods     = [string]$cachedMFA.MFAMethods
        $findings.AccountEnabled = [string]$cachedMFA.AccountEnabled

        # An MFA method registered inside the investigation window is one of the
        # strongest account-takeover indicators there is: it is how an attacker
        # keeps access after the password is reset.
        $windowStartUtc = $StartDate.ToUniversalTime()
        $newMethods = @($script:allMFAMethodDetails | Where-Object { $_.UPN -eq $UPN } | Where-Object {
            $created = ConvertTo-LTIUtcDateTime -Value $_.Created
            ($null -ne $created) -and ($created -ge $windowStartUtc)
        })
        $findings.NewMFAMethods = $newMethods.Count
        if ($newMethods.Count -gt 0) {
            Add-Log "  [WARN] *** $($newMethods.Count) MFA METHOD(S) ADDED IN THE INVESTIGATION WINDOW ***"
            foreach ($nm in $newMethods) { Add-Log "    $($nm.Created)  $($nm.Method)  $($nm.Detail)" }
        }
    }

    return $findings
}

function Get-LTIMFAVerdict {
    # One place that decides how a mailbox's MFA finding is worded and whether
    # it is an alert, so the log, the master CSV and the master TXT always agree.
    #   NoMFA       - $true only when MFA was checked, nothing MFA-capable is
    #                 registered, and the account can actually sign in
    #   Verified    - $true when the lookup succeeded (Enabled or Disabled)
    #   EnabledText - "True" / "False" / "" for the master CSV
    param($Findings)

    $status  = [string]$Findings.MFAStatus
    $methods = [string]$Findings.MFAMethods
    $blocked = ([string]$Findings.AccountEnabled -eq "False")

    switch ($status) {
        "Enabled" {
            return [PSCustomObject]@{ NoMFA = $false; Verified = $true; EnabledText = "True"; Text = "Enabled - $methods" }
        }
        "Disabled" {
            if ($blocked) {
                return [PSCustomObject]@{ NoMFA = $false; Verified = $true; EnabledText = "False"; Text = "No MFA method registered (sign-in is blocked for this account, so not flagged)" }
            }
            $detail = "no MFA method registered"
            if ($methods -and $methods -ne "None registered") { $detail = "no MFA-capable method; has: $methods" }
            return [PSCustomObject]@{ NoMFA = $true; Verified = $true; EnabledText = "False"; Text = "*** DISABLED *** ($detail)" }
        }
        "Unknown" {
            return [PSCustomObject]@{ NoMFA = $false; Verified = $false; EnabledText = ""; Text = "UNKNOWN - lookup failed ($($methods -replace '^Error:\s*', ''))" }
        }
        default {
            return [PSCustomObject]@{ NoMFA = $false; Verified = $false; EnabledText = ""; Text = "NOT CHECKED (click 'Refresh MFA' before running)" }
        }
    }
}

# -----------------------------------------------------------------------------
#  RUN BUTTON
# -----------------------------------------------------------------------------
$btnRun.Add_Click({
    if ($lstMailboxes.SelectedItems.Count -eq 0) { [System.Windows.MessageBox]::Show("Select at least one mailbox.","Required","OK","Warning"); return }
    $enabledSteps=@{}; $enabledCount=0
    for($i=1;$i-le 16;$i++){$enabledSteps[$i]=($chkSteps[$i].IsChecked -eq $true);if($enabledSteps[$i]){$enabledCount++}}
    $enabledSteps[17]=($chkSteps[17].IsChecked -eq $true); if($enabledSteps[17]){$enabledCount++}
    if ($enabledCount -eq 0) { [System.Windows.MessageBox]::Show("Select at least one step.","Required","OK","Warning"); return }

    $selectedUPNs=[System.Collections.Generic.List[string]]::new()
    foreach ($si in $lstMailboxes.SelectedItems) { if($si -match '<(.+?)>'){$selectedUPNs.Add($Matches[1])} }
    if ($selectedUPNs.Count -eq 0) { [System.Windows.MessageBox]::Show("Could not parse mailboxes.","Error","OK","Error"); return }

    $baselinePath = ""
    $doComparison = ($chkBaseline.IsChecked -eq $true -and -not [string]::IsNullOrWhiteSpace($txtBaselinePath.Text))
    if ($doComparison) { $baselinePath = $txtBaselinePath.Text }

    $daysBack=[int]($cmbDaysBack.SelectedItem.Content); $startDate=(Get-Date).AddDays(-$daysBack); $endDate=Get-Date
    $ts=Get-Date -Format "yyyyMMdd_HHmmss"; $rootFolder=Join-Path $txtOutputPath.Text "Investigation_$ts"
    if (-not (Test-Path $rootFolder)) { New-Item -ItemType Directory -Path $rootFolder -Force|Out-Null }

    $btnRun.IsEnabled=$false; $btnConnect.IsEnabled=$false; $btnLoadMailboxes.IsEnabled=$false; $btnRefreshMFA.IsEnabled=$false; $btnRun.Content="Running..."
    $total=$selectedUPNs.Count; $allFindings=[System.Collections.Generic.List[PSCustomObject]]::new()

    # Everything from here to the end of the handler runs inside try/finally so an
    # unexpected error can never leave the window stuck on "Running..." with the
    # buttons disabled. (Body is not re-indented, to keep this change easy to diff.)
    try {

    Add-Log "=========================================="; Add-Log "LTI MS365 Investigation Utility"; Add-Log "=========================================="
    Add-Log "Mailboxes: $total | Steps: $enabledCount | Days: $daysBack"
    Add-Log "Output: $rootFolder"
    if ($doComparison) { Add-Log "Baseline: $baselinePath" }

    # --- Step 17: MFA Status Export (tenant-level, runs once) ---
    if ($enabledSteps[17]) {
        Add-Log ""; Add-Log "======================================================================"; Add-Log "  17. MFA Status Export"; Add-Log "======================================================================"
        $selectedMailboxObjs = @($script:allMailboxes | Where-Object { $selectedUPNs -contains $_.UserPrincipalName })

        # Fill in any selected user the MFA panel has not covered yet. This only
        # works when a Graph sign-in already exists (or can be renewed silently):
        # the device-code prompt cannot run in the middle of an investigation.
        $cachedUPNs = @($script:allMFAData | ForEach-Object { $_.UPN })
        $missingMailboxes = @($selectedMailboxObjs | Where-Object { $cachedUPNs -notcontains $_.UserPrincipalName })
        if ($missingMailboxes.Count -gt 0) {
            if (Test-LTIGraphToken) {
                Add-Log "  Fetching MFA status for $($missingMailboxes.Count) selected user(s) not yet in the MFA panel..."
                try {
                    if (-not $script:MFAContext) {
                        $script:MFAContext = Get-LTIMFAContext -Mailboxes @($script:allMailboxes)
                        foreach ($row in $script:MFAContext.AuditRows) { $script:allMFAAuditRows.Add($row) }
                    }
                    $null = Add-LTIMFARecords -Mailboxes $missingMailboxes
                    Update-MFAGrid -Filter ($cmbMFAFilter.SelectedItem.Content.ToString())
                } catch {
                    Add-Log "  [ERROR] MFA fetch failed: $_"
                }
            } else {
                Add-Log "  [WARN] MFA has NOT been checked for $($missingMailboxes.Count) of $($selectedMailboxObjs.Count) selected user(s)."
                Add-Log "         They are reported as 'not checked' - not as disabled."
                Add-Log "         Click 'Refresh MFA', complete the sign-in, then run the investigation again."
            }
        }

        $mfaExportData = @($script:allMFAData | Where-Object { $selectedUPNs -contains $_.UPN })
        if ($mfaExportData.Count -gt 0) {
            $mfaExportData | Export-Csv -Path (Join-Path $rootFolder "17_MFA_Status.csv") -NoTypeInformation -Encoding UTF8
            Add-Log "  [OK] MFA Status - $($mfaExportData.Count) user(s) -> 17_MFA_Status.csv"
            $null = Export-ResultSet -Name "MFA Method Details" -FileName "17a_MFA_Method_Details.csv" -OutFolder $rootFolder -Data @($script:allMFAMethodDetails | Where-Object { $selectedUPNs -contains $_.UPN })
            $null = Export-ResultSet -Name "MFA Config Audit Events" -FileName "17b_MFA_Config_Audit_Events.csv" -OutFolder $rootFolder -Data @($script:allMFAAuditRows | Where-Object { $selectedUPNs -contains $_.UPN })
        } else {
            # Deliberately NOT an empty 17_MFA_Status.csv: "no rows" reads as "nobody has MFA".
            ("MFA WAS NOT CHECKED - " + (Get-Date -Format 'u') + "`r`nNo Microsoft Graph sign-in was completed before this run, so there is no MFA data for the selected mailboxes.`r`nClick 'Refresh MFA' in the utility, complete the sign-in, and run the investigation again.") |
                Out-File -FilePath (Join-Path $rootFolder "17_MFA_Status_NOT_CHECKED.txt") -Encoding UTF8
            Add-Log "  [WARN] No MFA data for the selected mailboxes -> 17_MFA_Status_NOT_CHECKED.txt"
        }

        $mfaNone    = @($mfaExportData | Where-Object { $_.MFAStatus -eq "Disabled" -and $_.AccountEnabled -ne "False" })
        $mfaBlocked = @($mfaExportData | Where-Object { $_.MFAStatus -eq "Disabled" -and $_.AccountEnabled -eq "False" })
        $mfaUnknown = @($mfaExportData | Where-Object { $_.MFAStatus -eq "Unknown" })
        if ($mfaNone.Count -gt 0) {
            Add-Log "  [WARN] *** $($mfaNone.Count) USER(S) HAVE NO MFA METHOD REGISTERED ***"
            foreach ($u in $mfaNone) { Add-Log "    - $($u.DisplayName) ($($u.UPN))" }
        }
        if ($mfaBlocked.Count -gt 0) {
            Add-Log "  $($mfaBlocked.Count) mailbox(es) have no MFA method but sign-in is blocked (shared/room/disabled) - not flagged."
        }
        if ($mfaUnknown.Count -gt 0) {
            Add-Log "  [WARN] MFA lookup failed for $($mfaUnknown.Count) user(s) - status Unknown. First: $($mfaUnknown[0].UPN) - $($mfaUnknown[0].MFAMethods)"
        }
        Flush-UI
    } else { Add-Log "  [SKIP] Step 17" }

    $cur=0
    foreach ($upn in $selectedUPNs) {
        $cur++; $pct=[math]::Round(($cur/$total)*100); $progressBar.Value=$pct; $lblProgress.Text="[$cur/$total] $upn"
        Add-Log ""; Add-Log "######################################################################"; Add-Log "  INVESTIGATING: $upn ($cur of $total)"; Add-Log "######################################################################"
        $safe=$upn -replace '[\\/:*?"<>|@]','_'; $uf=Join-Path $rootFolder $safe
        if (-not (Test-Path $uf)) { New-Item -ItemType Directory -Path $uf -Force|Out-Null }
        Flush-UI
        try {
            # Invoke-MailboxInvestigation also emits the record counts returned by
            # Export-ResultSet; the findings object is always the LAST thing it outputs.
            $result=@(Invoke-MailboxInvestigation -UPN $upn -StartDate $startDate -EndDate $endDate -OutputFolder $uf -EnabledSteps $enabledSteps) | Select-Object -Last 1
            $allFindings.Add($result)
            $mfa=Get-LTIMFAVerdict -Findings $result
            $flags=@(); if($result.ForwardingActive){$flags+="FORWARDING"}; if($result.SuspiciousRules -gt 0){$flags+="$($result.SuspiciousRules) SUSPECT RULES"}
            if($result.SignInsFailed -gt 10){$flags+="$($result.SignInsFailed) FAILED LOGINS"}; if($result.OAuthConsents -gt 0){$flags+="$($result.OAuthConsents) OAUTH"}
            if($result.AuditEnabled -eq $false){$flags+="AUDIT OFF"}
            if($mfa.NoMFA){$flags+="MFA OFF"}elseif($enabledSteps[17] -and -not $mfa.Verified){$flags+="MFA NOT VERIFIED"}
            if($result.NewMFAMethods -gt 0){$flags+="$($result.NewMFAMethods) MFA METHOD(S) ADDED IN WINDOW"}
            if($result.Errors.Count -gt 0){$flags+="$($result.Errors.Count) ERRORS"}
            Add-Log ""; if($flags.Count -gt 0){Add-Log "  >> ALERTS: $($flags -join ' | ')"}else{Add-Log "  >> No major alerts."}
        } catch { Add-Log "  >> FAILED: $_" }
        Flush-UI
    }

    # --- Master CSV ---
    $csvPath=Join-Path $rootFolder "_MASTER_SUMMARY.csv"
    # MFAEnabled is True / False, or blank when MFA was not checked or the lookup failed (see MFAStatus).
    $csvData=foreach($f in $allFindings){$mfa=Get-LTIMFAVerdict -Findings $f;[PSCustomObject]@{UPN=$f.UPN;DisplayName=$f.DisplayName;MFAEnabled=$mfa.EnabledText;MFAStatus=$f.MFAStatus;MFAMethods=$f.MFAMethods;NewMFAMethods=$f.NewMFAMethods;SignInAllowed=$f.AccountEnabled;SignInsOK=$f.SignInsOK;SignInsFailed=$f.SignInsFailed;UniqueIPs=$f.UniqueIPs;ForwardingActive=$f.ForwardingActive;ForwardingTarget=$f.ForwardingTarget;SuspiciousRules=$f.SuspiciousRules;TotalRules=$f.TotalRules;OAuthConsents=$f.OAuthConsents;AdminActions=$f.AdminActions;FileEvents=$f.FileEvents;OutboundMail=$f.OutboundMail;AuditEnabled=$f.AuditEnabled;Errors=($f.Errors -join '; ')}}
    @($csvData)|Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8; Add-Log "Master CSV: $csvPath"

    # --- Master TXT ---
    $txtPath=Join-Path $rootFolder "_MASTER_SUMMARY.txt"; $sl=[System.Collections.Generic.List[string]]::new()
    $sl.Add("LTI MS365 Investigation Utility - Master Summary"); $sl.Add("================================================")
    $sl.Add("Generated : $(Get-Date -Format 'u')"); $sl.Add("Date Range: $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd'))")
    $sl.Add("Steps Run : $enabledCount"); $sl.Add("Mailboxes : $total investigated"); $sl.Add("")
    $alertCount=0
    foreach($f in $allFindings){$mfa=Get-LTIMFAVerdict -Findings $f
        $ha=$f.ForwardingActive -or $f.SuspiciousRules -gt 0 -or $f.SignInsFailed -gt 10 -or $f.OAuthConsents -gt 0 -or $mfa.NoMFA -or $f.NewMFAMethods -gt 0; if($ha){$alertCount++}
        $m=if($ha){"[!!!]"}else{"[OK] "}; $sl.Add("$m $($f.UPN) ($($f.DisplayName))"); $sl.Add("      MFA: $($mfa.Text)")
        if($f.NewMFAMethods -gt 0){$sl.Add("      *** $($f.NewMFAMethods) MFA METHOD(S) ADDED IN THE INVESTIGATION WINDOW - see 17a_MFA_Method_Details.csv")}
        $sl.Add("      Sign-ins: $($f.SignInsOK) ok / $($f.SignInsFailed) failed / $($f.UniqueIPs) IPs")
        if($f.ForwardingActive){$sl.Add("      *** FORWARDING -> $($f.ForwardingTarget)")}; if($f.SuspiciousRules -gt 0){$sl.Add("      *** $($f.SuspiciousRules) SUSPICIOUS RULES")}
        if($f.OAuthConsents -gt 0){$sl.Add("      *** $($f.OAuthConsents) OAuth consents")}
        if($f.AuditEnabled -eq $false){$sl.Add("      *** Auditing DISABLED")}elseif($null -eq $f.AuditEnabled){$sl.Add("      Auditing: not checked")}
        if($f.Errors.Count -gt 0){$sl.Add("      Errors: $($f.Errors -join '; ')")}; $sl.Add("")}
    $sl.Insert(7,"ALERTS  : $alertCount mailbox(es) with suspicious findings")
    $sl.Insert(8,"MFA NOTE: 'Enabled' means an MFA-capable method is registered. It does not prove MFA is enforced (Conditional Access / Security Defaults are not checked).")
    $sl.Insert(9,"")
    ($sl -join "`r`n")|Out-File -FilePath $txtPath -Encoding UTF8

    # --- BASELINE COMPARISON ---
    if ($doComparison) {
        Add-Log ""; Add-Log "======================================================================"; Add-Log "  BASELINE COMPARISON"; Add-Log "======================================================================"
        $changesSummary=[System.Collections.Generic.List[PSCustomObject]]::new()
        $usersWithChanges=0

        foreach ($upn in $selectedUPNs) {
            $safe=$upn -replace '[\\/:*?"<>|@]','_'
            $baseUserFolder=Join-Path $baselinePath $safe
            $currUserFolder=Join-Path $rootFolder $safe

            if (-not (Test-Path $baseUserFolder)) {
                Add-Log "  [SKIP] No baseline data for $upn (folder not found)"
                continue
            }

            Add-Log "  Comparing: $upn"
            Flush-UI

            $compResult = Invoke-BaselineComparison -BaselineUserFolder $baseUserFolder -CurrentUserFolder $currUserFolder -UPN $upn

            $changeReportPath = Join-Path $currUserFolder "_CHANGES_FROM_BASELINE.txt"
            ($compResult.Report -join "`r`n") | Out-File -FilePath $changeReportPath -Encoding UTF8

            $changesSummary.Add([PSCustomObject]@{
                UPN          = $upn
                TotalChanges = $compResult.TotalChanges
            })

            if ($compResult.TotalChanges -gt 0) {
                $usersWithChanges++
                Add-Log "    [!!!] $($compResult.TotalChanges) change(s) detected - see _CHANGES_FROM_BASELINE.txt"
            } else {
                Add-Log "    [OK] No configuration changes from baseline."
            }
            Flush-UI
        }

        $changesCSVPath = Join-Path $rootFolder "_BASELINE_CHANGES_SUMMARY.csv"
        @($changesSummary) | Export-Csv -Path $changesCSVPath -NoTypeInformation -Encoding UTF8

        $changesTxtPath = Join-Path $rootFolder "_BASELINE_CHANGES_SUMMARY.txt"
        $cLines = [System.Collections.Generic.List[string]]::new()
        $cLines.Add("LTI MS365 Investigation Utility - Baseline Changes Summary")
        $cLines.Add("==========================================================")
        $cLines.Add("Generated : $(Get-Date -Format 'u')")
        $cLines.Add("Baseline  : $baselinePath")
        $cLines.Add("Current   : $rootFolder")
        $cLines.Add("Users with changes: $usersWithChanges of $($changesSummary.Count)")
        $cLines.Add("")
        foreach ($cs in $changesSummary) {
            $marker = if ($cs.TotalChanges -gt 0) { "[!!!]" } else { "[OK] " }
            $cLines.Add("$marker $($cs.UPN) - $($cs.TotalChanges) change(s)")
        }
        ($cLines -join "`r`n") | Out-File -FilePath $changesTxtPath -Encoding UTF8

        Add-Log ""; Add-Log "Baseline comparison complete: $usersWithChanges user(s) with changes"
        Add-Log "Changes summary: $changesCSVPath"
    }

    Add-Log ""; Add-Log "=========================================="; Add-Log "INVESTIGATION COMPLETE"
    Add-Log "$total mailbox(es), $alertCount alerts$(if($doComparison){", $usersWithChanges with config changes"})"; Add-Log "Results: $rootFolder"; Add-Log "=========================================="
    $progressBar.Value=100; $lblProgress.Text="Complete - $alertCount alert(s)"
    $btnRun.Content="Run Investigation"
    if($chkOpenFolder.IsChecked){Start-Process "explorer.exe" -ArgumentList $rootFolder}

    $compMsg = ""; if ($doComparison) { $compMsg = "`nBaseline changes: $usersWithChanges user(s)" }
    [System.Windows.MessageBox]::Show("Investigation complete!`n`n$total mailbox(es) processed`n$alertCount with alerts`nSteps: $enabledCount$compMsg`n`nResults:`n$rootFolder","LTI MS365 Investigation Utility","OK","Information") | Out-Null

    } catch {
        Write-Log "Run handler error: $_" "ERROR"
        Write-Log "Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" "ERROR"
        Add-Log ""; Add-Log "[ERROR] Investigation stopped early: $_"
        Add-Log "Partial results (if any): $rootFolder"
        $lblProgress.Text = "Stopped - see log"
        [System.Windows.MessageBox]::Show("The investigation stopped early.`n`n$_`n`nPartial results (if any):`n$rootFolder`n`nDebug log:`n$script:LogFile","LTI MS365 Investigation Utility","OK","Error") | Out-Null
    } finally {
        $btnRun.Content = "Run Investigation"
        Reset-MFAButtons
    }
})

Write-Log "Entering window.ShowDialog"
try {
    $window.ShowDialog() | Out-Null
    Write-Log "window.ShowDialog returned normally"
} catch {
    Write-Log "window.ShowDialog threw: $_" "FATAL"
    Write-Log "Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" "FATAL"
    [System.Windows.MessageBox]::Show("Fatal error in UI:`n$_`n`nLog: $script:LogFile","LTI Fatal Error","OK","Error")
}
Write-Log "Script exiting"
