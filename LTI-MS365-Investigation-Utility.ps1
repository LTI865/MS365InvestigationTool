# =============================================================================
# LTI MS365 Investigation Utility
# REV 2.5 - Log Reach, UTC Timestamps, Bulk ASN Lookup Build
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
# REV 2.5 changes
#   FIX  Report times. "Generated" and the empty-result markers printed LOCAL
#        time with a Z suffix. Every stamp is now real UTC (with local time
#        beside it), and every audit / mail-trace row uses the same
#        "yyyy-MM-dd HH:mm:ss UTC" format so timelines line up across files.
#   FIX  MFA audit events (17b) missed Windows Hello for Business keys,
#        device-bound passkeys, platform credentials and legacy per-user MFA
#        switches - Entra logs those under other services than the one the
#        script queried.
#   FIX  ASN lookup (opt-in) labelled only the first few IPs when the DNS
#        resolver started timing out, and said nothing. It now sends the whole
#        list to Team Cymru in ONE bulk whois connection, falls back to DNS
#        with a retry if TCP 43 is blocked, and reports how many IPs it could
#        not label.
#   NEW  Log reach check. Entra ID Free keeps sign-in and audit logs for 7
#        days; P1/P2 keeps 30, counted from the day the licence was added. A
#        30-day run on such a tenant gets 7 days of Entra data and nothing
#        said so. The run now tests whether the tenant's logs hold anything
#        older than a week and states the result in the log, the master
#        summary and each mailbox's Entra status.
#   NOTE Nothing in the script limits the Entra steps to 7 days: step 18 uses
#        the Days Back value and 17b always asks for 30.
#
# REV 2.4 changes
#   NEW  Step 18 - Entra sign-in log, interactive AND non-interactive, per
#        mailbox (18_Entra_SignIns.csv). Non-interactive sign-ins are the
#        token refreshes where a stolen session shows up; the unified audit
#        log used by step 1 does not show them. Needs the same Graph sign-in
#        as the MFA step (click "Refresh MFA" first). How far back it reaches
#        depends on the tenant's Entra licence - see the REV 2.5 note above.
#   NEW  Country and ASN next to every IP in the master summary, taken from
#        Microsoft's own sign-in geolocation.
#   NEW  _SIGNIN_IP_SUMMARY.csv - one row per mailbox + IP: country, city,
#        ASN, ok/failed counts per log, first and last seen.
#   NEW  Optional (off by default): look up ASN / network name / registered
#        country for IPs Microsoft did not label, via Team Cymru's public
#        IP-to-ASN service over DNS. This sends those IPs to a third party.
#   NEW  Run asks before starting when steps 17/18 are ticked but there is
#        no Graph sign-in, instead of quietly producing "not checked".
#
# REV 2.3 changes
#   FIX  IP addresses were blank in the sign-in export and UniqueIPs was
#        always 0. The script read AuditData.ClientIPAddress for every
#        record, but only Exchange mailbox records use that name - Entra
#        sign-in records carry the address in ClientIP / ActorIpAddress, as
#        do SharePoint and admin records. Every step now reads the right
#        field (steps 1, 9, 10, 11, 12, 13 and 16 were affected).
#   NEW  01_SignIn_Events.csv has an ErrorCode column (AADSTS code, e.g.
#        50126 wrong password, 50057 account disabled).
#   NEW  Master summary lists each mailbox's sign-in IPs with ok/failed counts.
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

Write-Log "Script started - LTI MS365 Investigation Utility REV 2.5 (PowerShell $($PSVersionTable.PSVersion))"

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
                        <CheckBox x:Name="chkStep18" Content="18. Entra Sign-In Log (incl. non-interactive)" IsChecked="True" ToolTip="Needs a Graph sign-in (click Refresh MFA first) and Entra ID P1/P2"/>
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
        <StackPanel Grid.Row="8" Margin="0,0,0,10">
            <CheckBox x:Name="chkOpenFolder" Content="Open output folder when complete" IsChecked="True"/>
            <CheckBox x:Name="chkGeoLookup" Content="Look up ASN / network for unlabelled IPs (sends those IPs to Team Cymru over DNS)" IsChecked="False" Margin="0,4,0,0"
                      ToolTip="Off: country and ASN come only from the Entra sign-in log (step 18). On: unlabelled IPs are also looked up with Team Cymru's public IP-to-ASN service."/>
        </StackPanel>

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
$chkOpenFolder=$window.FindName("chkOpenFolder"); $chkGeoLookup=$window.FindName("chkGeoLookup"); $btnRun=$window.FindName("btnRun"); $progressBar=$window.FindName("progressBar")
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
for ($i = 1; $i -le 18; $i++) { $chkSteps[$i] = $window.FindName("chkStep{0:D2}" -f $i) }

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

# Sign-in IP intelligence (step 18 and the IP roll-up).
$script:LTIIPInfo          = @{}      # IP  -> country / state / city / ASN / network name / source
$script:LTIASNames         = @{}      # ASN -> network name (only filled by the opt-in lookup)
$script:allIPRollup        = [System.Collections.Generic.List[PSCustomObject]]::new()   # one row per mailbox + IP, per run
$script:LTIGeoLookup       = $false   # opt-in Team Cymru lookup, set from the checkbox at run time
$script:LTIGeoLookupCount  = 0
$script:LTIEntraBlocked    = $null    # why the Entra sign-in log cannot be read in this tenant, once known
$script:LTILastPagedTruncated = $false
$script:LTIVersion         = "REV 2.5"
$script:LTILogReach        = $null    # result of the Entra log reach check for the current run

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
    # $true when the page cap stopped the loop with more data still available.
    $script:LTILastPagedTruncated = [bool]$next
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

function Get-LTIStamp {
    # "2026-11-21 16:36:10 UTC (11:36:10 local, UTC-05:00)"
    # These stamps used to be Get-Date with the 'u' format, which prints LOCAL
    # time with a Z suffix - five hours out for a US Eastern workstation.
    param([DateTime]$When = (Get-Date))

    $utc = $When.ToUniversalTime()
    $off = [TimeZoneInfo]::Local.GetUtcOffset($When)
    $sign = '+'
    if ($off -lt [TimeSpan]::Zero) { $sign = '-' }
    $abs = $off.Duration()
    return ("{0} UTC ({1} local, UTC{2}{3:00}:{4:00})" -f $utc.ToString("yyyy-MM-dd HH:mm:ss"), $When.ToString("HH:mm:ss"), $sign, $abs.Hours, $abs.Minutes)
}

function Get-LTIAuditTime {
    # UTC timestamp for a unified-audit-log row, in the same format as every
    # other timeline column. Prefers AuditData.CreationTime (documented as UTC).
    param($Row, $AuditData)

    $t = $null
    if ($AuditData) { $t = $AuditData.CreationTime }
    if ($null -eq $t -or [string]::IsNullOrWhiteSpace([string]$t)) { $t = $Row.CreationDate }
    return (Format-LTIDateTime -Value $t)
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
    # Entra directory audit events for sign-in method changes: who registered,
    # changed, reset or deleted an MFA method / key / passkey, and when.
    # Entra spreads these over several services, so each is queried separately
    # and a failure of one never loses the others:
    #   Authentication Methods      - security info registered / deleted / changed
    #   Device Registration Service - Windows Hello for Business keys, device-bound
    #                                 passkeys, platform credentials, passwordless
    #                                 phone sign-in, device registration
    #   Core Directory              - legacy per-user MFA switched on / off
    # Limited by the tenant's audit retention (7 days on Entra ID Free, 30 days
    # with P1/P2). ALWAYS returns an array, even when empty.
    param([int]$DaysBack = 30)

    $events = [System.Collections.Generic.List[object]]::new()
    $startUtc = (Get-Date).ToUniversalTime().AddDays(-1 * $DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")

    $queries = @(
        @{ Name = 'Authentication Methods'; Required = $true
           Filter = "loggedByService eq 'Authentication Methods' and activityDateTime ge $startUtc"
           Match  = '(security info|authentication method|authenticator|phone|FIDO|passkey|Temporary Access Pass|passwordless|MFA|multifactor|strong authentication)' },
        @{ Name = 'Device Registration Service'; Required = $false
           Filter = "loggedByService eq 'Device Registration Service' and activityDateTime ge $startUtc"
           Match  = '(Windows Hello|passkey|credential|register device)' },
        @{ Name = 'Core Directory (per-user MFA off)'; Required = $false
           Filter = "activityDisplayName eq 'Disable Strong Authentication' and activityDateTime ge $startUtc"
           Match  = '.' },
        @{ Name = 'Core Directory (per-user MFA on)'; Required = $false
           Filter = "activityDisplayName eq 'Enable Strong Authentication' and activityDateTime ge $startUtc"
           Match  = '.' }
    )

    Add-Log "  Fetching MFA / sign-in method audit events for the last $DaysBack day(s)..."
    foreach ($q in $queries) {
        try {
            $uri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=' + [Uri]::EscapeDataString($q.Filter)
            $kept = 0
            foreach ($item in (Get-LTIGraphPaged -Uri $uri)) {
                if ([string]$item.activityDisplayName -match $q.Match) { $events.Add($item); $kept++ }
            }
            Write-Log "MFA audit query '$($q.Name)': $kept event(s)"
        } catch {
            Write-Log "MFA audit query '$($q.Name)' failed: $_" "WARN"
            if ($q.Required) {
                Add-Log "  [WARN] MFA configuration audit events unavailable: $($_.Exception.Message)"
                if ([int]$_.Exception.Data['LTIStatus'] -eq 403) {
                    Add-Log "         Needs AuditLog.Read.All plus Reports Reader, Security Reader, Global Reader or Global Admin."
                }
                Add-Log "         MFA config date columns will be blank. MFA status itself is not affected."
                # Same sign-in, same answer for the other services - do not repeat the refusal.
                if (@(401, 403) -contains [int]$_.Exception.Data['LTIStatus']) { break }
            } else {
                Add-Log "  [INFO] Could not read '$($q.Name)' audit events: $($_.Exception.Message)"
            }
        }
    }

    Add-Log "  [OK] Loaded $($events.Count) MFA / sign-in method audit event(s)"
    return , $events.ToArray()
}

function Test-LTIEntraLogReach {
    # Does this tenant's Entra log hold ANYTHING older than 8 days?
    #   'Yes'     - the log reaches back further than a week (P1/P2 retention)
    #   'No'      - nothing older than a week exists: 7-day retention (Entra ID
    #               Free, or P1/P2 added in the last few days)
    #   'Unknown' - the check itself could not run
    # One cheap request per log. It is what tells a 30-day run that the Entra
    # data in it only covers 7 days.
    param([Parameter(Mandatory = $true)][ValidateSet('SignIns', 'Audit')][string]$Log)

    $now  = (Get-Date).ToUniversalTime()
    $from = $now.AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $to   = $now.AddDays(-8).ToString("yyyy-MM-ddTHH:mm:ssZ")
    if ($Log -eq 'SignIns') {
        $uri = 'https://graph.microsoft.com/beta/auditLogs/signIns?$top=1&$filter=' + [Uri]::EscapeDataString("createdDateTime ge $from and createdDateTime le $to")
    } else {
        $uri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=1&$filter=' + [Uri]::EscapeDataString("activityDateTime ge $from and activityDateTime le $to")
    }
    try {
        $r = Invoke-LTIGraphGet -Uri $uri
        if (@(@($r.value) | Where-Object { $null -ne $_ }).Count -gt 0) { return 'Yes' }
        return 'No'
    } catch {
        Write-Log "Entra log reach check ($Log) failed: $($_.Exception.Message)" "WARN"
        return 'Unknown'
    }
}

function Get-LTILogReachText {
    # One sentence per log for the report header. Empty when the check did not run.
    param($Reach, [int]$DaysBack)

    if (-not $Reach) { return @() }
    $lines = @()
    foreach ($pair in @(@('SignIns', 'sign-in log (step 18)'), @('Audit', 'audit log (17b MFA changes)'))) {
        $state = [string]$Reach[$pair[0]]
        if ($state -eq 'No') {
            $lines += "Entra $($pair[1]): holds NOTHING older than 7 days. Entra ID Free keeps 7 days; P1/P2 keeps 30 from the day the licence was added. Anything Entra-sourced in this report covers the last 7 days only$(if ($DaysBack -gt 7) { ", not the $DaysBack requested" })."
        } elseif ($state -eq 'Yes') {
            $lines += "Entra $($pair[1]): reaches back more than 7 days (up to 30)."
        } elseif ($state) {
            $lines += "Entra $($pair[1]): reach could not be checked."
        }
    }
    return $lines
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

        # Windows Hello / passkey / device registration events are self-service and
        # may name only the device as the target - the user is then the initiator.
        # (Never done for Authentication Methods events, where the initiator can be
        # an admin acting on someone else.)
        if ($matched.Count -eq 0 -and [string]$ev.loggedByService -eq 'Device Registration Service' -and $ev.initiatedBy -and $ev.initiatedBy.user) {
            foreach ($key in @([string]$ev.initiatedBy.user.userPrincipalName, [string]$ev.initiatedBy.user.id)) {
                if ($key -and $lookup.ContainsKey($key.ToLowerInvariant())) { $matched[$lookup[$key.ToLowerInvariant()]] = $true }
            }
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
                Service       = [string]$ev.loggedByService
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
$btnCheckAll.Add_Click({ for ($i=1;$i-le 18;$i++) { $chkSteps[$i].IsChecked=$true } })
$btnUncheckAll.Add_Click({ for ($i=1;$i-le 18;$i++) { $chkSteps[$i].IsChecked=$false } })
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

function Get-LTIAuditIP {
    # The client IP sits in a different AuditData property depending on the workload:
    #   Exchange mailbox records     -> ClientIPAddress
    #   Entra ID sign-in records     -> ClientIP / ActorIpAddress
    #   SharePoint and admin records -> ClientIP
    # REV 2.2 and earlier read ClientIPAddress for everything, so sign-in, OAuth,
    # SharePoint and admin records all came back with a blank IP.
    # Returns the first one present, with any port and IPv6 brackets removed.
    param($AuditData)

    if ($null -eq $AuditData) { return "" }
    foreach ($name in @('ClientIPAddress', 'ClientIP', 'ActorIpAddress', 'ActorIP')) {
        $v = [string]$AuditData.$name
        if ([string]::IsNullOrWhiteSpace($v)) { continue }
        $v = $v.Trim()
        if ($v -match '^\[([^\]]+)\](:\d+)?$') { return $Matches[1] }           # [2001:db8::1]:443
        if ($v -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$') { return $Matches[1] }    # 203.0.113.5:51234
        return $v
    }
    return ""
}

# -----------------------------------------------------------------------------
#  SIGN-IN IP INTELLIGENCE (REV 2.4)
#  - Entra sign-in log (interactive + non-interactive) via Microsoft Graph
#  - Country / city / ASN per IP
#  - One roll-up row per mailbox + IP
# -----------------------------------------------------------------------------
function Test-LTIPublicIP {
    # $true for an address worth looking up: not private, loopback, link-local,
    # carrier-grade NAT, multicast or otherwise reserved.
    param([string]$IP)

    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse([string]$IP, [ref]$addr)) { return $false }
    $b = $addr.GetAddressBytes()

    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224) { return $false }
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
        if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
        return $true
    }
    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ([System.Net.IPAddress]::IsLoopback($addr) -or $addr.IsIPv6LinkLocal -or $addr.IsIPv6SiteLocal -or $addr.IsIPv6Multicast) { return $false }
        if (($b[0] -band 0xFE) -eq 0xFC) { return $false }     # fc00::/7 unique local
        if (($b | Measure-Object -Sum).Sum -eq 0) { return $false }
        return $true
    }
    return $false
}

function Get-LTICymruQueryName {
    # DNS name for Team Cymru's IP-to-ASN service: reversed octets (IPv4) or
    # reversed nibbles (IPv6) under origin.asn.cymru.com / origin6.asn.cymru.com.
    param([string]$IP)

    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse([string]$IP, [ref]$addr)) { return $null }
    $b = $addr.GetAddressBytes()

    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return "$($b[3]).$($b[2]).$($b[1]).$($b[0]).origin.asn.cymru.com"
    }
    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        $nibbles = [System.Collections.Generic.List[string]]::new()
        for ($i = $b.Length - 1; $i -ge 0; $i--) {
            $nibbles.Add(('{0:x}' -f ($b[$i] -band 0x0F)))
            $nibbles.Add(('{0:x}' -f (($b[$i] -shr 4) -band 0x0F)))
        }
        return (($nibbles -join '.') + '.origin6.asn.cymru.com')
    }
    return $null
}

function Resolve-LTIDnsTxt {
    # First TXT string for a name, or $null. Never throws. One retry: a single
    # dropped UDP answer should not leave an IP unlabelled.
    param([string]$Name)

    foreach ($attempt in 1, 2) {
        try {
            $r = Resolve-DnsName -Name $Name -Type TXT -DnsOnly -ErrorAction Stop | Where-Object { $_.Strings } | Select-Object -First 1
            if ($r) { return (@($r.Strings) -join '') }
            return $null
        } catch {
            if ($attempt -eq 1) { Start-Sleep -Milliseconds 300 }
        }
    }
    return $null
}

function Set-LTIIPInfo {
    # Records what is known about an IP. Microsoft's own sign-in geolocation
    # always wins over a registry lookup; blanks never overwrite values.
    param([string]$IP, [string]$Country, [string]$State, [string]$City, [string]$ASN, [string]$ASName, [string]$Source)

    if ([string]::IsNullOrWhiteSpace($IP)) { return }
    $info = $script:LTIIPInfo[$IP]
    if (-not $info) {
        $info = [PSCustomObject]@{ Country = ""; State = ""; City = ""; ASN = ""; ASName = ""; Source = "" }
        $script:LTIIPInfo[$IP] = $info
    }
    $fromEntra = ($Source -eq 'Entra')
    if ($Country -and ($fromEntra -or -not $info.Country)) {
        $info.Country = $Country
        $info.Source = $Source
        if ($fromEntra) { $info.State = $State; $info.City = $City }
    }
    if ($ASN -and $ASN -ne '0' -and ($fromEntra -or -not $info.ASN)) { $info.ASN = $ASN }
    if ($ASName -and -not $info.ASName -and $ASN -and $info.ASN -eq $ASN) { $info.ASName = $ASName; $script:LTIASNames[$ASN] = $ASName }
    if (-not $info.Source) { $info.Source = $Source }
}

function Invoke-LTICymruBulkWhois {
    # The whole list in ONE TCP connection to whois.cymru.com:43, which is how
    # Team Cymru asks for more than a handful of addresses to be sent.
    # Returns the raw reply, or $null when the port cannot be reached.
    param([string[]]$IPs)

    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $connect = $client.ConnectAsync('whois.cymru.com', 43)
        if (-not $connect.Wait(8000)) { throw "connection timed out" }
        $client.ReceiveTimeout = 30000
        $client.SendTimeout = 10000

        $stream = $client.GetStream()
        $payload = "begin`nverbose`n" + ($IPs -join "`n") + "`nend`n"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($payload)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()

        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII)
        return $reader.ReadToEnd()
    } catch {
        Write-Log "Team Cymru bulk whois failed: $($_.Exception.Message)" "WARN"
        return $null
    } finally {
        if ($client) { try { $client.Close() } catch {} }
    }
}

function ConvertFrom-LTICymruBulk {
    # Bulk verbose reply -> hashtable: IP -> ASN / Country / ASName.
    #   AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
    #   23028   | 216.90.108.31    | 216.90.108.0/24     | US | arin     | 1998-09-25 | TEAM-CYMRU, US
    # Addresses with no route come back as NA and are left out.
    param([string]$Text)

    $map = @{}
    foreach ($line in @(([string]$Text) -split "`r?`n")) {
        $f = @($line -split '\|' | ForEach-Object { $_.Trim() })
        if ($f.Count -lt 7) { continue }
        $asn = @($f[0] -split '\s+' | Where-Object { $_ })[0]
        if ($asn -notmatch '^\d+$') { continue }

        $addr = $null
        if (-not [System.Net.IPAddress]::TryParse($f[1], [ref]$addr)) { continue }
        $key = $addr.ToString()
        if ($map.ContainsKey($key)) { continue }

        $cc = $f[3]
        if ($cc -eq 'NA') { $cc = '' }
        $name = ($f[6] -replace ',\s*[A-Z]{2}$', '').Trim()
        if ($name -eq 'NA') { $name = '' }
        $map[$key] = [PSCustomObject]@{ ASN = $asn; Country = $cc; ASName = $name }
    }
    return $map
}

function Update-LTIIPInfoFromCymru {
    # OPT-IN (checkbox on the main window). Fills in ASN, network name and
    # country for IPs Microsoft did not label, using Team Cymru's public
    # IP-to-ASN service. This sends those IP addresses to a third party.
    # The country returned is where the address block is REGISTERED, which is
    # often not where the device is - Entra's geolocation is always preferred.
    #
    # Called once per run with every IP, so there is one bulk connection rather
    # than a query per address. If TCP 43 is blocked it falls back to DNS.
    param([string[]]$IPs)

    if (-not $script:LTIGeoLookup) { return }

    $all  = @($IPs | Where-Object { $_ } | Select-Object -Unique)
    $need = @($all | Where-Object {
        $i = $script:LTIIPInfo[$_]
        ((-not $i) -or (-not $i.ASN) -or (-not $i.Country)) -and (Test-LTIPublicIP -IP $_)
    })

    if ($need.Count -gt 0) {
        Add-Log "  ASN lookup: $($need.Count) unlabelled public IP(s) -> Team Cymru bulk whois..."
        Flush-UI
        $bulkWorked = $false
        for ($offset = 0; $offset -lt $need.Count; $offset += 2000) {
            $chunk = @($need | Select-Object -Skip $offset -First 2000)
            $raw = Invoke-LTICymruBulkWhois -IPs $chunk
            if (-not $raw) { continue }
            $bulkWorked = $true
            $answers = ConvertFrom-LTICymruBulk -Text $raw
            foreach ($ip in $chunk) {
                $addr = $null
                if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$addr)) { continue }
                $a = $answers[$addr.ToString()]
                if ($a) { Set-LTIIPInfo -IP $ip -Country $a.Country -ASN $a.ASN -ASName $a.ASName -Source 'Team Cymru (registered country)' }
            }
            Flush-UI
        }

        if (-not $bulkWorked) {
            Add-Log "  [WARN] Bulk whois (TCP 43 to whois.cymru.com) could not be reached - using DNS lookups instead (slower)."
            $done = 0
            foreach ($ip in @($need | Select-Object -First 1000)) {
                $done++
                $name = Get-LTICymruQueryName -IP $ip
                $txt = $null
                if ($name) { $txt = Resolve-LTIDnsTxt -Name $name }
                if ($txt) {
                    # "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
                    $f = @($txt -split '\|' | ForEach-Object { $_.Trim() })
                    if ($f.Count -ge 3) {
                        $asn = @($f[0] -split '\s+' | Where-Object { $_ })[0]
                        Set-LTIIPInfo -IP $ip -Country $f[2] -ASN $asn -Source 'Team Cymru (registered country)'
                    }
                }
                if ($done % 10 -eq 0) { $lblProgress.Text = "ASN lookup: $done / $($need.Count)"; Flush-UI }
            }
            if ($need.Count -gt 1000) { Add-Log "  [WARN] DNS fallback is limited to 1000 IPs per run - $($need.Count - 1000) not looked up." }
        }

        $unanswered = @($need | Where-Object { $i = $script:LTIIPInfo[$_]; (-not $i) -or (-not $i.ASN) })
        Add-Log "  ASN lookup: labelled $($need.Count - $unanswered.Count) of $($need.Count) IP(s)$(if ($unanswered.Count -gt 0) { " - $($unanswered.Count) had no answer and stay unlabelled" })"
    }

    # Network names for ASNs that still have none (ASNs from Entra, or from the
    # DNS fallback). Only the AS number is sent, once per distinct ASN.
    foreach ($ip in $all) {
        $info = $script:LTIIPInfo[$ip]
        if ($info -and $info.ASN -and -not $info.ASName) {
            if (-not $script:LTIASNames.ContainsKey($info.ASN)) {
                $nameTxt = Resolve-LTIDnsTxt -Name "AS$($info.ASN).asn.cymru.com"
                $asName = ""
                if ($nameTxt) {
                    # "23028 | US | arin | 2002-01-04 | TEAM-CYMRU, US"
                    $nf = @($nameTxt -split '\|' | ForEach-Object { $_.Trim() })
                    if ($nf.Count -ge 5) { $asName = ($nf[4] -replace ',\s*[A-Z]{2}$', '').Trim() }
                }
                $script:LTIASNames[$info.ASN] = $asName
            }
            $info.ASName = $script:LTIASNames[$info.ASN]
        }
    }
}

function Update-LTIRollupGeo {
    # Runs once, after every mailbox has been processed: one lookup for every
    # unlabelled IP in the run, then the labels in the roll-up rows and in each
    # mailbox's findings are refreshed.
    param($Findings)

    if ($script:allIPRollup.Count -eq 0) { return }
    Update-LTIIPInfoFromCymru -IPs @($script:allIPRollup | ForEach-Object { $_.IP })

    foreach ($row in $script:allIPRollup) {
        $info = $script:LTIIPInfo[$row.IP]
        if (-not $info) { continue }
        $row.Country = $info.Country; $row.State = $info.State; $row.City = $info.City
        $row.ASN = $info.ASN; $row.ASName = $info.ASName; $row.GeoSource = $info.Source
    }

    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $rows = @($script:allIPRollup | Where-Object { $_.UPN -eq $f.UPN })
        if ($rows.Count -eq 0) { continue }
        $f.SignInIPs         = Get-LTIIPSummaryText -Rows $rows -OkProperty 'AuditOK' -FailedProperty 'AuditFailed'
        $f.NonInteractiveIPs = Get-LTIIPSummaryText -Rows $rows -OkProperty 'NonInteractiveOK' -FailedProperty 'NonInteractiveFailed'
        $countries = Get-LTICountrySummary -Rows $rows
        $f.SignInCountries   = $countries.Text
        $f.CountryCount      = $countries.Count
    }
}

function Get-LTIIPLabel {
    # "[US AS7922 COMCAST-7922]" - whatever of country / ASN / network name is known.
    param([string]$IP)

    $info = $script:LTIIPInfo[$IP]
    if (-not $info) { return "" }
    $parts = @()
    if ($info.Country) { $parts += $info.Country }
    if ($info.ASN)     { $parts += "AS$($info.ASN)" }
    if ($info.ASName)  { $parts += $info.ASName }
    if ($parts.Count -eq 0) { return "" }
    return "[" + ($parts -join " ") + "]"
}

function Get-LTIEntraSignIns {
    # Entra sign-in log for one user: interactive AND non-interactive (token
    # refreshes, background app sign-ins - where a stolen session token shows up).
    # Non-interactive sign-ins only exist on Graph's beta endpoint. Microsoft
    # only serves this log to tenants with Entra ID P1/P2, and keeps 30 days.
    #
    # Returns: Rows (flat, CSV-ready), Truncated ($true if the page cap was hit),
    #          Note (set when the non-interactive half failed).
    # Throws when the log cannot be read at all.
    param(
        [Parameter(Mandatory = $true)][string]$UPN,
        [Parameter(Mandatory = $true)][DateTime]$Start,
        [Parameter(Mandatory = $true)][DateTime]$End,
        [int]$MaxPages = 25
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $truncated = $false
    $note = ""

    $from = $Start.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $to   = $End.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Filter on the object ID when the MFA step has already loaded the directory.
    $who = "userPrincipalName eq '" + $UPN.ToLowerInvariant().Replace("'", "''") + "'"
    if ($script:MFAContext -and $script:MFAContext.DirectoryByUpn) {
        $dir = $script:MFAContext.DirectoryByUpn[$UPN.ToLowerInvariant()]
        if ($dir -and $dir.id) { $who = "userId eq '$($dir.id)'" }
    }

    foreach ($type in @('interactiveUser', 'nonInteractiveUser')) {
        $label = 'Interactive'
        if ($type -eq 'nonInteractiveUser') { $label = 'NonInteractive' }

        $filter = "$who and createdDateTime ge $from and createdDateTime le $to and signInEventTypes/any(t: t eq '$type')"
        $uri = 'https://graph.microsoft.com/beta/auditLogs/signIns?$filter=' + [Uri]::EscapeDataString($filter)

        $items = @()
        try {
            $items = Get-LTIGraphPaged -Uri $uri -MaxPages $MaxPages
            if ($script:LTILastPagedTruncated) { $truncated = $true }
        } catch {
            if ($type -eq 'interactiveUser') { throw }
            $note = "non-interactive sign-ins unavailable: $($_.Exception.Message)"
            Write-Log "Entra non-interactive sign-ins failed for ${UPN}: $($_.Exception.Message)" "WARN"
            continue
        }

        foreach ($s in $items) {
            $code = 0
            if ($s.status -and $null -ne $s.status.errorCode) { $code = [int]$s.status.errorCode }
            $result = 'Success'
            if ($code -ne 0) { $result = 'Failure' }

            $ip = ([string]$s.ipAddress).Trim()
            $country = ""; $state = ""; $city = ""
            if ($s.location) { $country = [string]$s.location.countryOrRegion; $state = [string]$s.location.state; $city = [string]$s.location.city }
            $asn = ""
            if ($null -ne $s.autonomousSystemNumber -and [string]$s.autonomousSystemNumber -ne '0') { $asn = [string]$s.autonomousSystemNumber }
            Set-LTIIPInfo -IP $ip -Country $country -State $state -City $city -ASN $asn -Source 'Entra'

            $dd = $s.deviceDetail
            $rows.Add([PSCustomObject]@{
                Timestamp         = Format-LTIDateTime -Value $s.createdDateTime
                Type              = $label
                Result            = $result
                ErrorCode         = $code
                FailureReason     = [string]$s.status.failureReason
                IP                = $ip
                Country           = $country
                State             = $state
                City              = $city
                ASN               = $asn
                App               = [string]$s.appDisplayName
                Resource          = [string]$s.resourceDisplayName
                ClientApp         = [string]$s.clientAppUsed
                DeviceOS          = [string]$dd.operatingSystem
                Browser           = [string]$dd.browser
                DeviceName        = [string]$dd.displayName
                DeviceTrust       = [string]$dd.trustType
                DeviceCompliant   = [string]$dd.isCompliant
                DeviceManaged     = [string]$dd.isManaged
                ConditionalAccess = [string]$s.conditionalAccessStatus
                AuthRequirement   = [string]$s.authenticationRequirement
                TokenType         = [string]$s.incomingTokenType
                RiskLevel         = [string]$s.riskLevelDuringSignIn
                UserAgent         = [string]$s.userAgent
                CorrelationId     = [string]$s.correlationId
            })
        }
        Flush-UI
    }

    return [PSCustomObject]@{ Rows = $rows; Truncated = $truncated; Note = $note }
}

function Get-LTIIPRollup {
    # One row per IP for a mailbox, combining the unified audit log sign-ins
    # (step 1) with the Entra sign-in log (step 18). The two logs overlap for
    # interactive sign-ins, so their counts are kept in separate columns and
    # must not be added together.
    param([string]$UPN, $AuditSignIns, $EntraSignIns)

    $map = [ordered]@{}
    $touch = {
        param($ip, $counter, $when)
        if ([string]::IsNullOrWhiteSpace($ip)) { return }
        if (-not $map.Contains($ip)) {
            $map[$ip] = [PSCustomObject]@{ AuditOK = 0; AuditFailed = 0; InteractiveOK = 0; InteractiveFailed = 0; NonInteractiveOK = 0; NonInteractiveFailed = 0; First = $null; Last = $null }
        }
        $e = $map[$ip]
        if ($counter) { $e.$counter++ }
        $t = ConvertTo-LTIUtcDateTime -Value $when
        if ($null -ne $t) {
            if ($null -eq $e.First -or $t -lt $e.First) { $e.First = $t }
            if ($null -eq $e.Last  -or $t -gt $e.Last)  { $e.Last  = $t }
        }
    }

    foreach ($r in @($AuditSignIns)) {
        if ($null -eq $r) { continue }
        $counter = $null
        if ($r.Operation -eq 'UserLoggedIn') { $counter = 'AuditOK' } elseif ($r.Operation -eq 'UserLoginFailed') { $counter = 'AuditFailed' }
        & $touch ([string]$r.ClientIP) $counter $r.Timestamp
    }
    foreach ($r in @($EntraSignIns)) {
        if ($null -eq $r) { continue }
        $counter = $r.Type + 'OK'
        if ($r.Result -ne 'Success') { $counter = $r.Type + 'Failed' }
        & $touch ([string]$r.IP) $counter $r.Timestamp
    }

    $out = foreach ($ip in @($map.Keys)) {
        $e = $map[$ip]
        $info = $script:LTIIPInfo[$ip]
        [PSCustomObject]@{
            UPN                  = $UPN
            IP                   = $ip
            Country              = $(if ($info) { $info.Country } else { "" })
            State                = $(if ($info) { $info.State } else { "" })
            City                 = $(if ($info) { $info.City } else { "" })
            ASN                  = $(if ($info) { $info.ASN } else { "" })
            ASName               = $(if ($info) { $info.ASName } else { "" })
            GeoSource            = $(if ($info) { $info.Source } else { "" })
            AuditOK              = $e.AuditOK
            AuditFailed          = $e.AuditFailed
            InteractiveOK        = $e.InteractiveOK
            InteractiveFailed    = $e.InteractiveFailed
            NonInteractiveOK     = $e.NonInteractiveOK
            NonInteractiveFailed = $e.NonInteractiveFailed
            FirstSeen            = Format-LTIDateTime -Value $e.First
            LastSeen             = Format-LTIDateTime -Value $e.Last
        }
    }
    return , @($out)
}

function Get-LTIIPSummaryText {
    # "203.0.113.5 [US AS7922 COMCAST-7922] (41 ok / 2 failed); ..." - busiest first.
    param($Rows, [string]$OkProperty, [string]$FailedProperty, [int]$Max = 10)

    $use = @(@($Rows) | Where-Object { $_ -and (($_.$OkProperty + $_.$FailedProperty) -gt 0) } |
        Sort-Object -Property @{ Expression = { $_.$OkProperty + $_.$FailedProperty }; Descending = $true }, @{ Expression = { $_.IP } })
    if ($use.Count -eq 0) { return "" }

    $parts = @($use | Select-Object -First $Max | ForEach-Object {
        $label = Get-LTIIPLabel -IP $_.IP
        if ($label) { $label = " $label" }
        "$($_.IP)$label ($($_.$OkProperty) ok / $($_.$FailedProperty) failed)"
    })
    $text = $parts -join "; "
    if ($use.Count -gt $Max) { $text += "; +$($use.Count - $Max) more" }
    return $text
}

function Get-LTICountrySummary {
    # "US (4 IPs), NG (1 IP)" - counts distinct IPs, so it reads the same whichever
    # log the sign-ins came from. Returns Text and Count (countries seen).
    param($Rows)

    $known = @(@($Rows) | Where-Object { $_ -and $_.Country })
    if ($known.Count -eq 0) { return [PSCustomObject]@{ Text = ""; Count = 0 } }

    $groups = @($known | Group-Object -Property Country | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Name' })
    $parts = @($groups | ForEach-Object { "$($_.Name) ($($_.Count) IP$(if ($_.Count -ne 1) { 's' }))" })
    $unknown = @(@($Rows) | Where-Object { $_ -and -not $_.Country }).Count
    if ($unknown -gt 0) { $parts += "unlabelled ($unknown IP$(if ($unknown -ne 1) { 's' }))" }
    return [PSCustomObject]@{ Text = ($parts -join ", "); Count = $groups.Count }
}

function Export-ResultSet { param([string]$Name,[string]$FileName,[string]$OutFolder,$Data)
    $fp=Join-Path $OutFolder $FileName
    if ($null -eq $Data -or ($Data -is [System.Collections.IEnumerable] -and @($Data).Count -eq 0)) {
        $ep=$fp -replace '\.csv$','_EMPTY.txt'; ("NO DATA FOUND - " + (Get-LTIStamp))|Out-File -FilePath $ep -Encoding UTF8; Add-Log "  [WARN] No data: $Name"; return 0 }
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
    $report.Add("Generated: $(Get-LTIStamp)")
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
    $findings=[PSCustomObject]@{UPN=$UPN;DisplayName="";SignInsOK=0;SignInsFailed=0;UniqueIPs=0;SignInIPs="";SignInCountries="";CountryCount=0;EntraSignInLog="Not run";EntraInteractive="";EntraNonInteractive="";NonInteractiveIPs="";ForwardingActive=$false;ForwardingTarget="";SuspiciousRules=0;TotalRules=0;OAuthConsents=0;AdminActions=0;FileEvents=0;OutboundMail=0;AuditEnabled=$null;MFAStatus="NotChecked";MFAMethods="";NewMFAMethods=0;AccountEnabled="";Errors=[System.Collections.Generic.List[string]]::new()}
    # AuditEnabled stays $null and MFAStatus stays "NotChecked" until the relevant check
    # actually runs, so a skipped or failed check is never reported as "off".

    $auditSignIns=@(); $entraSignIns=@()   # kept for the IP roll-up at the end
    Add-Log "Verifying mailbox: $UPN"; Flush-UI
    try { $mbx=Get-Mailbox -Identity $UPN -ErrorAction Stop; $findings.DisplayName=$mbx.DisplayName; Add-Log "  [OK] Mailbox: $($mbx.DisplayName) [$($mbx.PrimarySmtpAddress)]" }
    catch { Add-Log "  [ERROR] Not found: $_"; $findings.Errors.Add("Not found: $_"); return $findings }

    if ($EnabledSteps[1]) { Add-Log "======================================================================"; Add-Log "  1. Sign-In and Authentication Events"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("UserLoggedIn","UserLoginFailed","ForeignRealmIndexLogonInitialAuthUsingADFSFederatedToken","PasswordLogonInitialAuthUsingPassword")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;ResultStatus=$a.ResultStatus;LogonError=$a.LogonError;ErrorCode=$(if($null -ne $a.ErrorCode -and "$($a.ErrorCode)" -ne ''){$a.ErrorCode}else{$a.ErrorNumber});ClientIP=(Get-LTIAuditIP $a);UserAgent=$a.ExtendedProperties|Where-Object{$_.Name -eq "UserAgent"}|Select-Object -ExpandProperty Value -ErrorAction SilentlyContinue;RequestType=$a.ExtendedProperties|Where-Object{$_.Name -eq "RequestType"}|Select-Object -ExpandProperty Value -ErrorAction SilentlyContinue;Application=$a.ApplicationId;Workload=$a.Workload}}
            Export-ResultSet -Name "Sign-In Events" -FileName "01_SignIn_Events.csv" -OutFolder $OutputFolder -Data $parsed
            $findings.SignInsOK=@($parsed|Where-Object{$_.Operation -eq "UserLoggedIn"}).Count; $findings.SignInsFailed=@($parsed|Where-Object{$_.Operation -eq "UserLoginFailed"}).Count; $findings.UniqueIPs=@($parsed|Where-Object{$_.ClientIP}|Select-Object -ExpandProperty ClientIP -Unique).Count
            $auditSignIns=@($parsed|Where-Object{$_})
            Add-Log "  Sign-ins: $($findings.SignInsOK) ok, $($findings.SignInsFailed) failed, $($findings.UniqueIPs) IPs"
            if(($findings.SignInsOK + $findings.SignInsFailed) -gt 0 -and $findings.UniqueIPs -eq 0){Add-Log "  [WARN] $($findings.SignInsOK + $findings.SignInsFailed) sign-in record(s) came back with no IP address in ClientIP or ActorIpAddress. Check the Entra sign-in log for this user."}
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Sign-ins: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 1" }

    if ($EnabledSteps[2]) { Add-Log "======================================================================"; Add-Log "  2. Mailbox Activity"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("MailboxLogin","MailItemsAccessed","Send","SendAs","SendOnBehalf","Create","HardDelete","SoftDelete","MoveToDeletedItems","Update","Copy","Move")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops -RecordTypes @("ExchangeItem","ExchangeItemAggregated")
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;ClientIP=(Get-LTIAuditIP $a);ClientInfo=$a.ClientInfoString;ItemSubject=$a.Item.Subject;Folder=$a.Item.ParentFolder.Path;ResultStatus=$a.ResultStatus}}
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
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;Target=($a.Target|ForEach-Object{$_.Id}) -join '; ';ModifiedProps=($a.ModifiedProperties|ForEach-Object{"$($_.Name)=$($_.NewValue)"}) -join '; ';ClientIP=(Get-LTIAuditIP $a);ResultStatus=$a.ResultStatus;ActorUPN=$a.UserId}}
            Export-ResultSet -Name "OAuth" -FileName "09_OAuth_App_Consent.csv" -OutFolder $OutputFolder -Data $parsed; $findings.OAuthConsents=@($parsed).Count
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("OAuth: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 9" }

    if ($EnabledSteps[10]) { Add-Log "======================================================================"; Add-Log "  10. Rule Changes"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("New-InboxRule","Set-InboxRule","Enable-InboxRule","Remove-InboxRule","UpdateInboxRules","New-TransportRule","Set-TransportRule")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;Parameters=($a.Parameters|ForEach-Object{"$($_.Name)=$($_.Value)"}) -join '; ';ClientIP=(Get-LTIAuditIP $a);SessionId=$a.SessionId}}
            Export-ResultSet -Name "Rule Changes" -FileName "10_Rule_Changes.csv" -OutFolder $OutputFolder -Data $parsed
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("RuleChg: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 10" }

    if ($EnabledSteps[11]) { Add-Log "======================================================================"; Add-Log "  11. File Activity"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("FileDownloaded","FileUploaded","FileDeleted","FileModified","FileRenamed","FileMoved","FileCopied","SharingSet","AnonymousLinkCreated","CompanyLinkCreated","SharingInvitationCreated","AddedToSecureLink")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops -RecordTypes @("SharePointFileOperation")
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;FileName=$a.SourceFileName;FileUrl=$a.ObjectId;SiteUrl=$a.SiteUrl;ClientIP=(Get-LTIAuditIP $a);UserAgent=$a.UserAgent}}
            Export-ResultSet -Name "File Activity" -FileName "11_File_Activity.csv" -OutFolder $OutputFolder -Data $parsed; $findings.FileEvents=@($parsed).Count
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Files: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 11" }

    if ($EnabledSteps[12]) { Add-Log "======================================================================"; Add-Log "  12. Admin Actions"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("Add member to role.","Add user.","Reset user password.","Set force change user password.","Update user.","Delete user.","Set-Mailbox","Add-MailboxPermission","Remove-MailboxPermission","New-ManagementRoleAssignment")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;Target=($a.Target|ForEach-Object{$_.Id}) -join '; ';Parameters=($a.Parameters|ForEach-Object{"$($_.Name)=$($_.Value)"}) -join '; ';ClientIP=(Get-LTIAuditIP $a);ResultStatus=$a.ResultStatus}}
            Export-ResultSet -Name "Admin Actions" -FileName "12_Admin_Actions.csv" -OutFolder $OutputFolder -Data $parsed; $findings.AdminActions=@($parsed).Count
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Admin: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 12" }

    if ($EnabledSteps[13]) { Add-Log "======================================================================"; Add-Log "  13. eDiscovery"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("SearchStarted","SearchExportDownloaded","New-ComplianceSearch","New-ComplianceSearchAction","CaseAdded")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;Parameters=($a.Parameters|ForEach-Object{"$($_.Name)=$($_.Value)"}) -join '; ';ClientIP=(Get-LTIAuditIP $a)}}
            Export-ResultSet -Name "eDiscovery" -FileName "13_eDiscovery_Activity.csv" -OutFolder $OutputFolder -Data $parsed
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("eDisc: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 13" }

    if ($EnabledSteps[14]) { Add-Log "======================================================================"; Add-Log "  14. Message Trace"; Add-Log "======================================================================"; Flush-UI
        try { Add-Log "  Outbound..."; Flush-UI; $ob=Get-MessageTraceV2All -SenderAddress $UPN -Start $StartDate -End $EndDate
            $obs=$ob|Select-Object @{N='Received';E={Format-LTIDateTime $_.Received}},SenderAddress,RecipientAddress,Subject,Status,@{N='FromIP';E={$_.FromIP}},Size,MessageId; Export-ResultSet -Name "Outbound" -FileName "14a_MessageTrace_Outbound.csv" -OutFolder $OutputFolder -Data $obs; $findings.OutboundMail=@($ob).Count
            Add-Log "  Inbound..."; Flush-UI; $ib=Get-MessageTraceV2All -RecipientAddress $UPN -Start $StartDate -End $EndDate
            $ibs=$ib|Select-Object @{N='Received';E={Format-LTIDateTime $_.Received}},SenderAddress,RecipientAddress,Subject,Status,@{N='FromIP';E={$_.FromIP}},Size,MessageId; Export-ResultSet -Name "Inbound" -FileName "14b_MessageTrace_Inbound.csv" -OutFolder $OutputFolder -Data $ibs
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
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);RecordType=$_.RecordType;Operation=$a.Operation;Workload=$a.Workload;ClientIP=(Get-LTIAuditIP $a);ResultStatus=$a.ResultStatus;ObjectId=$a.ObjectId}}
            Export-ResultSet -Name "All Audit" -FileName "16_All_Audit_Activity.csv" -OutFolder $OutputFolder -Data $parsed
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("CatchAll: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 16" }

    if ($EnabledSteps[18]) { Add-Log "======================================================================"; Add-Log "  18. Entra Sign-In Log (interactive + non-interactive)"; Add-Log "======================================================================"
        if ($script:LTIEntraBlocked) {
            # Already refused once in this run for a tenant-wide reason - do not repeat the call per mailbox.
            $findings.EntraSignInLog = "Unavailable - $($script:LTIEntraBlocked)"
            Add-Log "  [SKIP] $($script:LTIEntraBlocked)"
        } elseif (-not (Test-LTIGraphToken)) {
            $findings.EntraSignInLog = "Not checked - no Graph sign-in"
            Add-Log "  [SKIP] No Graph sign-in. Click 'Refresh MFA' and sign in before running to include this step."
        } else {
            try {
                $entra = Get-LTIEntraSignIns -UPN $UPN -Start $StartDate -End $EndDate
                $entraSignIns = @($entra.Rows)
                Export-ResultSet -Name "Entra Sign-Ins" -FileName "18_Entra_SignIns.csv" -OutFolder $OutputFolder -Data $entraSignIns
                $iOK = @($entraSignIns | Where-Object { $_.Type -eq 'Interactive' -and $_.Result -eq 'Success' }).Count
                $iNo = @($entraSignIns | Where-Object { $_.Type -eq 'Interactive' -and $_.Result -ne 'Success' }).Count
                $nOK = @($entraSignIns | Where-Object { $_.Type -eq 'NonInteractive' -and $_.Result -eq 'Success' }).Count
                $nNo = @($entraSignIns | Where-Object { $_.Type -eq 'NonInteractive' -and $_.Result -ne 'Success' }).Count
                $findings.EntraInteractive = "$iOK ok / $iNo failed"
                $findings.EntraSignInLog = "OK"
                $reachNote = ""
                if ($script:LTILogReach -and $script:LTILogReach.SignIns -eq 'No') { $reachNote = " - tenant log only holds the last 7 days"; $findings.EntraSignInLog += $reachNote }
                if ($entra.Note) {
                    $findings.EntraSignInLog = "Partial - $($entra.Note)$reachNote"
                    Add-Log "  [WARN] $($entra.Note)"
                } else {
                    $findings.EntraNonInteractive = "$nOK ok / $nNo failed"
                }
                if ($entra.Truncated) {
                    $findings.EntraSignInLog += " (truncated - newest $($entraSignIns.Count) kept)"
                    Add-Log "  [WARN] Very busy account: only the newest $($entraSignIns.Count) sign-ins were retrieved."
                }
                Add-Log "  Interactive: $($findings.EntraInteractive) | Non-interactive: $(if($findings.EntraNonInteractive){$findings.EntraNonInteractive}else{'not available'})"
            } catch {
                $status = [int]$_.Exception.Data['LTIStatus']
                $msg = [string]$_.Exception.Message
                if ($msg -match 'NonPremium|premium license') {
                    $script:LTIEntraBlocked = "this tenant has no Entra ID P1/P2 licence, so Microsoft does not serve its sign-in log over Graph"
                } elseif ($status -ge 400 -and $status -lt 500) {
                    # A refusal here is about the sign-in or the tenant, not this mailbox.
                    $script:LTIEntraBlocked = "Graph refused the sign-in log request ($msg)"
                    if ($status -eq 403) { $script:LTIEntraBlocked += " - needs Global Reader, Reports Reader, Security Reader or Global Admin" }
                    $findings.Errors.Add("Entra sign-ins: $msg")
                } else {
                    $findings.Errors.Add("Entra sign-ins: $msg")
                }
                if ($script:LTIEntraBlocked) { $findings.EntraSignInLog = "Unavailable - $($script:LTIEntraBlocked)"; Add-Log "  [INFO] Entra sign-in log unavailable: $($script:LTIEntraBlocked)" }
                else { $findings.EntraSignInLog = "Error - $msg"; Add-Log "  [ERROR] $msg" }
            }
        }
        Flush-UI
    } else { Add-Log "  [SKIP] Step 18" }

    # Sign-in IP roll-up: every IP this mailbox signed in from, across both logs,
    # labelled with country / ASN where known.
    $ipRows = Get-LTIIPRollup -UPN $UPN -AuditSignIns $auditSignIns -EntraSignIns $entraSignIns
    if ($ipRows.Count -gt 0) {
        foreach ($row in $ipRows) { $script:allIPRollup.Add($row) }
        $findings.UniqueIPs         = $ipRows.Count
        $findings.SignInIPs         = Get-LTIIPSummaryText -Rows $ipRows -OkProperty 'AuditOK' -FailedProperty 'AuditFailed'
        $findings.NonInteractiveIPs = Get-LTIIPSummaryText -Rows $ipRows -OkProperty 'NonInteractiveOK' -FailedProperty 'NonInteractiveFailed'
        $countries = Get-LTICountrySummary -Rows $ipRows
        $findings.SignInCountries   = $countries.Text
        $findings.CountryCount      = $countries.Count
        Add-Log "  Sign-in IPs: $($ipRows.Count)$(if($countries.Text){" | Countries: $($countries.Text)"})"
        if ($findings.SignInIPs)         { Add-Log "    Audit log      : $($findings.SignInIPs)" }
        if ($findings.NonInteractiveIPs) { Add-Log "    Non-interactive: $($findings.NonInteractiveIPs)" }
    }

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
    for($i=1;$i-le 18;$i++){$enabledSteps[$i]=($chkSteps[$i].IsChecked -eq $true);if($enabledSteps[$i]){$enabledCount++}}
    if ($enabledCount -eq 0) { [System.Windows.MessageBox]::Show("Select at least one step.","Required","OK","Warning"); return }

    $selectedUPNs=[System.Collections.Generic.List[string]]::new()
    foreach ($si in $lstMailboxes.SelectedItems) { if($si -match '<(.+?)>'){$selectedUPNs.Add($Matches[1])} }
    if ($selectedUPNs.Count -eq 0) { [System.Windows.MessageBox]::Show("Could not parse mailboxes.","Error","OK","Error"); return }

    # Steps 17 and 18 read Microsoft Graph, and the Graph sign-in cannot be started
    # from inside a run. Say so now rather than produce a report full of "not checked".
    $cachedForPrompt = @($script:allMFAData | ForEach-Object { $_.UPN })
    $needsGraph = $enabledSteps[18] -or ($enabledSteps[17] -and @($selectedUPNs | Where-Object { $cachedForPrompt -notcontains $_ }).Count -gt 0)
    if ($needsGraph -and -not (Test-LTIGraphToken)) {
        $answer = [System.Windows.MessageBox]::Show("Steps 17 (MFA) and 18 (Entra sign-in log) need a Microsoft Graph sign-in, and there isn't one yet.`n`nTo include them: click No, click 'Refresh MFA', complete the sign-in, then run again.`n`nRun now without them?","Graph sign-in needed","YesNo","Warning")
        if ("$answer" -eq "No") { return }
    }

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

    # Per-run state for the sign-in IP roll-up (step 18 and the IP summary).
    $script:allIPRollup.Clear(); $script:LTIEntraBlocked = $null; $script:LTIGeoLookupCount = 0
    $script:LTIGeoLookup = ($chkGeoLookup.IsChecked -eq $true)
    if ($script:LTIGeoLookup) { Add-Log "ASN lookup: ON - IPs Microsoft did not label are sent to Team Cymru" }

    # How far back do this tenant's Entra logs actually go? (7 days on Entra ID Free.)
    $script:LTILogReach = $null
    if (($enabledSteps[17] -or $enabledSteps[18]) -and (Test-LTIGraphToken)) {
        $script:LTILogReach = @{ SignIns = (Test-LTIEntraLogReach -Log SignIns); Audit = (Test-LTIEntraLogReach -Log Audit) }
        foreach ($line in (Get-LTILogReachText -Reach $script:LTILogReach -DaysBack $daysBack)) {
            if ($line -match 'NOTHING older') { Add-Log "[WARN] $line" } else { Add-Log $line }
        }
    }

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
            ("MFA WAS NOT CHECKED - " + (Get-LTIStamp) + "`r`nNo Microsoft Graph sign-in was completed before this run, so there is no MFA data for the selected mailboxes.`r`nClick 'Refresh MFA' in the utility, complete the sign-in, and run the investigation again.") |
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
            if($result.CountryCount -gt 1){$flags+="SIGN-INS FROM $($result.CountryCount) COUNTRIES"}
            if($result.Errors.Count -gt 0){$flags+="$($result.Errors.Count) ERRORS"}
            Add-Log ""; if($flags.Count -gt 0){Add-Log "  >> ALERTS: $($flags -join ' | ')"}else{Add-Log "  >> No major alerts."}
        } catch { Add-Log "  >> FAILED: $_" }
        Flush-UI
    }

    # --- Sign-in IP roll-up (one row per mailbox + IP) ---
    if ($script:allIPRollup.Count -gt 0) {
        Add-Log ""
        Update-LTIRollupGeo -Findings $allFindings
        if ($script:LTIGeoLookup) {
            foreach ($f in $allFindings) { if ($f.CountryCount -gt 1) { Add-Log "  $($f.UPN): sign-ins from $($f.CountryCount) countries - $($f.SignInCountries)" } }
        }
        @($script:allIPRollup) | Export-Csv -Path (Join-Path $rootFolder "_SIGNIN_IP_SUMMARY.csv") -NoTypeInformation -Encoding UTF8
        Add-Log ""; Add-Log "Sign-in IP summary: $($script:allIPRollup.Count) mailbox/IP row(s) -> _SIGNIN_IP_SUMMARY.csv"
    }

    # --- Master CSV ---
    $csvPath=Join-Path $rootFolder "_MASTER_SUMMARY.csv"
    # MFAEnabled is True / False, or blank when MFA was not checked or the lookup failed (see MFAStatus).
    $csvData=foreach($f in $allFindings){$mfa=Get-LTIMFAVerdict -Findings $f;[PSCustomObject]@{UPN=$f.UPN;DisplayName=$f.DisplayName;MFAEnabled=$mfa.EnabledText;MFAStatus=$f.MFAStatus;MFAMethods=$f.MFAMethods;NewMFAMethods=$f.NewMFAMethods;SignInAllowed=$f.AccountEnabled;SignInsOK=$f.SignInsOK;SignInsFailed=$f.SignInsFailed;UniqueIPs=$f.UniqueIPs;SignInIPs=$f.SignInIPs;SignInCountries=$f.SignInCountries;EntraSignInLog=$f.EntraSignInLog;EntraInteractive=$f.EntraInteractive;EntraNonInteractive=$f.EntraNonInteractive;NonInteractiveIPs=$f.NonInteractiveIPs;ForwardingActive=$f.ForwardingActive;ForwardingTarget=$f.ForwardingTarget;SuspiciousRules=$f.SuspiciousRules;TotalRules=$f.TotalRules;OAuthConsents=$f.OAuthConsents;AdminActions=$f.AdminActions;FileEvents=$f.FileEvents;OutboundMail=$f.OutboundMail;AuditEnabled=$f.AuditEnabled;Errors=($f.Errors -join '; ')}}
    @($csvData)|Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8; Add-Log "Master CSV: $csvPath"

    # --- Master TXT ---
    $txtPath=Join-Path $rootFolder "_MASTER_SUMMARY.txt"; $sl=[System.Collections.Generic.List[string]]::new()
    $sl.Add("LTI MS365 Investigation Utility - Master Summary"); $sl.Add("================================================")
    $sl.Add("Generated : $(Get-LTIStamp)"); $sl.Add("Date Range: $(Format-LTIDateTime $startDate) to $(Format-LTIDateTime $endDate) ($daysBack days back; all times in this report are UTC)")
    $sl.Add("Steps Run : $enabledCount  (tool $($script:LTIVersion))"); $sl.Add("Mailboxes : $total investigated"); $sl.Add("")
    $notesAt=$sl.Count
    $alertCount=0
    foreach($f in $allFindings){$mfa=Get-LTIMFAVerdict -Findings $f
        $ha=$f.ForwardingActive -or $f.SuspiciousRules -gt 0 -or $f.SignInsFailed -gt 10 -or $f.OAuthConsents -gt 0 -or $mfa.NoMFA -or $f.NewMFAMethods -gt 0; if($ha){$alertCount++}
        $m=if($ha){"[!!!]"}else{"[OK] "}; $sl.Add("$m $($f.UPN) ($($f.DisplayName))"); $sl.Add("      MFA: $($mfa.Text)")
        if($f.NewMFAMethods -gt 0){$sl.Add("      *** $($f.NewMFAMethods) MFA METHOD(S) ADDED IN THE INVESTIGATION WINDOW - see 17a_MFA_Method_Details.csv")}
        $sl.Add("      Sign-ins: $($f.SignInsOK) ok / $($f.SignInsFailed) failed / $($f.UniqueIPs) IPs")
        if($f.SignInIPs){$sl.Add("      IPs: $($f.SignInIPs)")}
        if($f.EntraSignInLog -ne "Not run"){
            if($f.EntraInteractive){$sl.Add("      Entra log: interactive $($f.EntraInteractive)$(if($f.EntraNonInteractive){" | non-interactive $($f.EntraNonInteractive)"})")}
            if($f.EntraSignInLog -ne "OK" -and $f.EntraSignInLog -ne "OK - tenant log only holds the last 7 days"){$sl.Add("      Entra log status: $($f.EntraSignInLog)")}
            if($f.NonInteractiveIPs){$sl.Add("      Non-interactive IPs: $($f.NonInteractiveIPs)")}
        }
        if($f.SignInCountries){$sl.Add("      $(if($f.CountryCount -gt 1){'*** '})Countries: $($f.SignInCountries)")}
        if($f.ForwardingActive){$sl.Add("      *** FORWARDING -> $($f.ForwardingTarget)")}; if($f.SuspiciousRules -gt 0){$sl.Add("      *** $($f.SuspiciousRules) SUSPICIOUS RULES")}
        if($f.OAuthConsents -gt 0){$sl.Add("      *** $($f.OAuthConsents) OAuth consents")}
        if($f.AuditEnabled -eq $false){$sl.Add("      *** Auditing DISABLED")}elseif($null -eq $f.AuditEnabled){$sl.Add("      Auditing: not checked")}
        if($f.Errors.Count -gt 0){$sl.Add("      Errors: $($f.Errors -join '; ')")}; $sl.Add("")}
    $notes=[System.Collections.Generic.List[string]]::new()
    $notes.Add("ALERTS  : $alertCount mailbox(es) with suspicious findings")
    $notes.Add("MFA NOTE: 'Enabled' means an MFA-capable method is registered. It does not prove MFA is enforced (Conditional Access / Security Defaults are not checked).")
    $notes.Add("IP NOTE : Country / ASN come from Microsoft's sign-in geolocation (step 18)$(if($script:LTIGeoLookup){'; IPs it did not label carry the country their address block is REGISTERED in, which is not a location'}). Audit-log and Entra-log counts overlap for interactive sign-ins - do not add them. Details: _SIGNIN_IP_SUMMARY.csv")
    foreach($line in (Get-LTILogReachText -Reach $script:LTILogReach -DaysBack $daysBack)){$notes.Add("LOG NOTE: $line")}
    $notes.Add("")
    $sl.InsertRange($notesAt,$notes)
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
        $cLines.Add("Generated : $(Get-LTIStamp)")
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
