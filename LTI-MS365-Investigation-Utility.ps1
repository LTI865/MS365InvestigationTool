# =============================================================================
# LTI MS365 Investigation Utility
# REV 3.3 - Mail Apps, Microsoft's Own Network, This Tool's Own Sign-in
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
#                     User.Read.All; plus Policy.Read.All and
#                     Directory.Read.All when "Extended Graph checks" is
#                     ticked). A Global Admin is prompted on first use.
#
# License Compatibility: Exchange Online Plan 1 and above.
# Does NOT require Entra ID P1/P2. With P1/P2 the MFA panel also shows the
# user's real default MFA method and 30 days of MFA audit history (7 on Free).
#
# REV 3.3 changes
#   FIX  Well-known mail apps (Apple Mail / "Apple Internet Accounts", Samsung
#        Email, Android Mail, Thunderbird, Spark) holding mailbox access no
#        longer score as "third-party app with mail access". They are listed
#        in a MailApps column at +0 with a reminder to confirm the user really
#        uses that app. A consent made INSIDE the window still scores.
#   NEW  Addresses in Microsoft's own network are labelled "Microsoft network"
#        wherever an IP is shown, in a MicrosoftNetwork column and in the
#        per-country counts. Labelled, not ignored: a Microsoft service acting
#        for the user and a server rented in Azure sit on the same network.
#   FIX  Investigating the account that is running this tool no longer flags
#        the tool's own device-code sign-in - only sign-ins to this tool's app
#        from the address used for this session's sign-in are set aside.
#
# REV 3.2 changes
#   NEW  Countries now show how many sign-ins SUCCEEDED and failed in each
#        one ("US: 412 ok / 3 failed (4 IPs); NG: 0 ok / 57 failed (12 IPs)"),
#        plus a SuccessCountries column. A country only scores when a sign-in
#        succeeded there; failed attempts from abroad are listed, not scored.
#   FIX  Sign-in prompts and expired sessions were counted as failed sign-ins
#        ("keep me signed in?", "MFA required", "session expired" and similar
#        Entra codes). They are now counted as Interrupted, the way the Entra
#        portal shows them, in both sign-in logs.
#   NEW  Indicator: the password was accepted but the sign-in was stopped at
#        MFA or by Conditional Access, from a network the user never completed
#        a sign-in from. That is what a stolen password looks like when MFA
#        holds - the one "interrupted" pattern that must not be ignored.
#   FIX  Exchange's own hidden automatic-reply rules (Microsoft.Exchange.OOF.*)
#        were flagged as hidden inbox rules. They are recognised like the junk
#        e-mail rule - but only while they do nothing else: a rule that
#        borrows a system name and forwards, deletes or hides mail is flagged.
#
# REV 3.1 changes
#   FIX  "Successful sign-in from a scripted client" fired on ordinary Office
#        use. Microsoft's own Office back end (for example "Augmentation
#        Loop") signs in with an HTTP-library user agent (node-fetch). Such a
#        sign-in is no longer flagged when ALL of these hold: the app is owned
#        by Microsoft, it carries the identity of a joined / registered /
#        managed device, and that same device also has ordinary (browser or
#        Office) sign-ins in the same session and from the same network.
#        Anything short of that is still flagged, and the indicator now names
#        the app, device and network so it can be judged at a glance.
#   FIX  A phone moving between Wi-Fi and mobile data inside one country no
#        longer rates Medium for "same session, several networks" or
#        "impossible travel". Both are kept as Low so they stay visible.
#   NEW  18_Entra_SignIns.csv has AppId, AppOwnerTenant and DeviceId columns.
#
# REV 3.0 changes
#   FIX  Baseline comparison reports listed only the number of changes: the
#        detail lines (what was added, removed or modified) were dropped by a
#        type-conversion error. They are written now. Comparison also covers
#        app consents and protocol settings.
#   NEW  _AI_BRIEF.md - ONE file to hand to an analyst (human or AI): what was
#        run, what could not be checked, tenant-wide findings and every
#        mailbox's evidence, ranked. Replaces dropping several CSVs in a chat.
#   NEW  _REPORT.html - the same findings as a self-contained, sortable,
#        printable report for the client.
#   NEW  Severity score (0-100) with the reasons behind it for each mailbox;
#        the summaries are ranked by it instead of a yes / no marker.
#   NEW  00_Timeline.csv per mailbox - sign-ins, mail, rule changes, MFA
#        changes, app consents and file activity merged in UTC order.
#   NEW  Is MFA actually ENFORCED? Security Defaults, Conditional Access and
#        legacy per-user MFA are read and evaluated for each user
#        (17c_MFA_Enforcement_Policies.csv).
#   NEW  Step 19 - app consents: what each user and the whole tenant has
#        consented to, apps with mail / file access, apps often abused in
#        mailbox compromises, and every app change in the window.
#   NEW  Sign-in indicators from the step 18 data: one session used from two
#        countries or networks, impossible travel, legacy protocols, scripted
#        clients, device-code sign-ins, success after password guessing.
#   NEW  Inbox rules: hidden rules are identified, each flagged rule says why,
#        and mark-as-read alone no longer counts as suspicious.
#   NEW  _FORWARDING_REVIEW.csv - mailbox forwarding for EVERY loaded mailbox,
#        forwarding inbox rules and redirecting transport rules, with external
#        targets and look-alike domains (one or two characters off) marked.
#   NEW  Outbound mail profile per hour with burst detection
#        (14c_Outbound_By_Hour.csv) and protocol exposure (IMAP / POP / SMTP
#        AUTH) per mailbox (15a_Protocol_Settings.csv).
#   NEW  "Extended Graph checks" box: asks for two more read-only Graph
#        permissions (Policy.Read.All, Directory.Read.All) used by the MFA
#        enforcement and app checks. Untick it to sign in exactly as before.
#   FIX  Audit-log paging no longer counts a record twice when Exchange
#        returns it on two pages.
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

Write-Log "Script started - LTI MS365 Investigation Utility REV 3.3 (PowerShell $($PSVersionTable.PSVersion))"

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
                        <DataGridTextColumn Header="MFA Enforced"      Binding="{Binding MFAEnforcement}"       Width="100"/>
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
                        <CheckBox x:Name="chkStep03" Content="3.  Inbox Rules (incl. hidden)" IsChecked="True"/>
                        <CheckBox x:Name="chkStep04" Content="4.  Mailbox Forwarding (+ look-alikes)" IsChecked="True"/>
                        <CheckBox x:Name="chkStep05" Content="5.  Transport Rules" IsChecked="True"/>
                        <CheckBox x:Name="chkStep06" Content="6.  Permissions / Delegates" IsChecked="True"/>
                        <CheckBox x:Name="chkStep07" Content="7.  Auto-Reply / OOF" IsChecked="True"/>
                        <CheckBox x:Name="chkStep08" Content="8.  Mobile Devices" IsChecked="True"/>
                        <CheckBox x:Name="chkStep17" Content="17. MFA Status + Enforcement" IsChecked="True"/>
                        <CheckBox x:Name="chkStep19" Content="19. App Consents (Graph)" IsChecked="True" ToolTip="Needs a Graph sign-in (click Refresh MFA first). Current consents need the extended Graph checks."/>
                    </StackPanel>
                    <StackPanel Grid.Column="1">
                        <CheckBox x:Name="chkStep09" Content="9.  OAuth / App Consent" IsChecked="True"/>
                        <CheckBox x:Name="chkStep10" Content="10. Rule Creation / Changes" IsChecked="True"/>
                        <CheckBox x:Name="chkStep11" Content="11. SharePoint / OneDrive Files" IsChecked="True"/>
                        <CheckBox x:Name="chkStep12" Content="12. Admin / Elevated Actions" IsChecked="True"/>
                        <CheckBox x:Name="chkStep13" Content="13. eDiscovery / Compliance" IsChecked="True"/>
                        <CheckBox x:Name="chkStep14" Content="14. Message Trace + Outbound Bursts" IsChecked="True"/>
                        <CheckBox x:Name="chkStep15" Content="15. Mailbox Audit + Protocols" IsChecked="True"/>
                        <CheckBox x:Name="chkStep16" Content="16. Catch-All Audit Dump" IsChecked="True"/>
                        <CheckBox x:Name="chkStep18" Content="18. Entra Sign-In Log + Indicators" IsChecked="True" ToolTip="Needs a Graph sign-in (click Refresh MFA first) and Entra ID P1/P2"/>
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
            <CheckBox x:Name="chkExtendedGraph" Content="Extended Graph checks: MFA enforcement + app consents (2 more read-only permissions at sign-in)" IsChecked="True" Margin="0,4,0,0"
                      ToolTip="Adds Policy.Read.All and Directory.Read.All to the Graph sign-in. A Global Admin is asked to consent the first time in each tenant. Untick to sign in with the basic permissions only."/>
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
        <TextBox Grid.Row="11" x:Name="txtLog" Height="160" IsReadOnly="True" TextWrapping="Wrap"
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
$chkOpenFolder=$window.FindName("chkOpenFolder"); $chkGeoLookup=$window.FindName("chkGeoLookup"); $chkExtendedGraph=$window.FindName("chkExtendedGraph"); $btnRun=$window.FindName("btnRun"); $progressBar=$window.FindName("progressBar")
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
for ($i = 1; $i -le 19; $i++) { $chkSteps[$i] = $window.FindName("chkStep{0:D2}" -f $i) }

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
$script:LTIVersion         = "REV 3.3"

# Entra sign-in error codes that are NOT a rejected sign-in: the sign-in paused
# for a prompt (keep me signed in, MFA, registration, consent, account picker)
# or an old session / token had simply expired. The Entra portal shows most of
# these as "Interrupted". They are counted separately from failures.
$script:LTIInterruptCodes = @(
    50140, 50058, 50199, 16000, 16001, 65001, 9002341,        # prompts with no security meaning
    50074, 50076, 50079, 50072, 50125, 50055, 50144, 50158,   # MFA / registration / expired-password prompts
    50097, 50129, 81010, 81012, 81014,                        # device or seamless-SSO hand-offs
    70043, 70044, 700082, 70008, 50089, 50078, 50133, 50173   # expired or revoked session / token
)
# Codes only reached AFTER the password (first factor) was accepted. Harmless
# from the user's own network; from anywhere else they mean somebody else knows
# the password and was stopped by the second step.
$script:LTIPasswordAcceptedCodes = @(50074, 50076, 50079, 50072, 50125, 50055, 50144, 50158, 500121, 53003)

# Well-known mail apps, by app ID (from Microsoft's app-consent-policy
# documentation). Mailbox access is what these apps are for, so holding it is
# not scored - but the user should actually use the app. eM Client is on that
# list too and is deliberately NOT here: see $script:LTIKnownAbusedApps.
$script:LTIKnownMailApps = @{
    'f8d98a96-0999-43f5-8af3-69971c7bb423' = 'Apple Mail (iPhone / iPad / Mac)'
    '8acd33ea-7197-4a96-bc33-d7cc7101262f' = 'Samsung Email (Android)'
    '2cee05de-2b8f-45a2-8289-2a06ca32c4c8' = 'Android Mail / Gmail app'
    '9e5f94bc-e8a4-4e73-b8be-63364c29d753' = 'Thunderbird'
    'b50c1dbd-1855-4e54-b07c-d3c3029e93d3' = 'Spark Email'
}
# Microsoft's own networks (autonomous system numbers). Used to LABEL an
# address, never to ignore it: Microsoft's services and servers anyone can rent
# in Azure share these networks.
$script:LTIMicrosoftASNs = @('3598', '6584', '8068', '8069', '8070', '8071', '8072', '8073', '8074', '8075', '12076')
$script:GraphSignInAt = $null   # when this session's device-code sign-in completed (UTC)

# Tenants that own Microsoft's first-party apps.
$script:LTIMicrosoftTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
# Microsoft apps known to sign in with an HTTP-library user agent. Matched by
# app ID (a display name can be copied by anyone); used when Graph does not
# say which tenant owns the app.
$script:LTIMicrosoftScriptedApps = @{ '4354e225-50c9-4423-9ece-2d5afd904870' = 'Augmentation Loop' }
$script:LTIIndicatorNotes = @()         # what the last indicator pass chose not to flag, and why

# REV 3.0 run state.
$script:allForwarding        = [System.Collections.Generic.List[PSCustomObject]]::new()   # tenant forwarding review
$script:LTIAcceptedDomains   = @()      # the tenant's own mail domains (lower case)
$script:LTIOperatorDomains   = @()      # domains of the accounts used to sign in
$script:LTIOrgSmtpAuthDisabled = $null  # organisation-wide SMTP AUTH switch
$script:LTIAppContext        = $null    # step 19 tenant data for the current run
$script:LTIUserIdCache       = @{}
$script:LTIMembershipCache   = @{}
# Third-party apps repeatedly seen in mailbox-compromise cases (public threat
# research, e.g. Huntress "Rogue Apps"). A match means "check the user really
# installed this", not proof of abuse.
$script:LTIKnownAbusedApps = @(
    @{ Label = 'eM Client';                       Pattern = '(?i)\beM ?Client\b';  AppId = 'e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd' },
    @{ Label = 'PERFECTDATA SOFTWARE';            Pattern = '(?i)perfect ?data';    AppId = 'ff8d92dc-3d82-41d6-bcbd-b9174d163620' },
    @{ Label = 'Newsletter Software Supermailer'; Pattern = '(?i)super ?mailer';    AppId = '' },
    @{ Label = 'CloudSponge';                     Pattern = '(?i)cloudsponge';      AppId = '' },
    @{ Label = 'rclone';                          Pattern = '(?i)^rclone';          AppId = '' },
    @{ Label = 'SigParser';                       Pattern = '(?i)sigparser';        AppId = '' }
)
$script:LTILogReach        = $null    # result of the Entra log reach check for the current run

# Microsoft Graph sign-in state
$script:GraphClientId     = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph Command Line Tools (public client)
$script:GraphScopesCore   = @(
    "https://graph.microsoft.com/UserAuthenticationMethod.Read.All",
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/User.Read.All"
)
# Read-only extras for the MFA-enforcement and app-consent checks. Requested only
# when "Extended Graph checks" is ticked; every check that needs one tests for it.
$script:GraphScopesExtended = @(
    "https://graph.microsoft.com/Policy.Read.All",
    "https://graph.microsoft.com/Directory.Read.All"
)
$script:GraphScopes        = @($script:GraphScopesCore)   # what the current sign-in asked for
$script:GraphGrantedScopes = @()                          # what the current token actually carries
$script:GraphSignedInAs    = ""
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
    $script:GraphGrantedScopes = @()
    $script:GraphSignedInAs   = ""
    $script:GraphSignInAt     = $null
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

    $script:GraphGrantedScopes = @()
    $script:GraphSignedInAs = "signed in (account name not readable)"
    $claims = ConvertFrom-LTIJwt -Token $script:GraphToken
    if (-not $claims) { Write-Log "Graph token acquired (claims not readable)"; return }

    $script:GraphGrantedScopes = @(([string]$claims.scp) -split ' ' | Where-Object { $_ })
    $who = [string]$claims.upn
    if (-not $who) { $who = [string]$claims.unique_name }
    if (-not $who) { $who = [string]$claims.oid }
    $script:GraphSignedInAs = $who
    if ($who -match '@([^@\s]+)$') { $script:LTIOperatorDomains = @(@($script:LTIOperatorDomains) + $Matches[1].ToLowerInvariant() | Select-Object -Unique) }
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
    $enforcement = Get-LTIMFAEnforcementContext

    return @{
        DirectoryByUpn    = $dir
        AuditByUpn        = $audit.Summary
        AuditRows         = $audit.Rows
        RegistrationByUpn = $reg
        Enforcement       = $enforcement
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
        MFAEnforcement     = "Unknown"
        MFAEnforcedBy      = ""
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

    # Is anything making this user USE MFA? (Security Defaults / Conditional Access / per-user MFA)
    if (-not $SkipReason) {
        $enfUserId = ""
        if ($dir -and $dir.id) { $enfUserId = [string]$dir.id }
        try {
            $enf = Get-LTIMFAEnforcement -UserId $enfUserId -Context $Context.Enforcement
            $rec.MFAEnforcement = $enf.State
            $rec.MFAEnforcedBy  = $enf.By
        } catch { Write-Log "MFA enforcement evaluation failed for ${upn}: $($_.Exception.Message)" "WARN" }
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
                if (@($script:GraphScopes).Count -gt @($script:GraphScopesCore).Count) { Add-Log "          If it asked for admin approval: untick 'Extended Graph checks' and click Refresh MFA to sign in with the basic permissions." }
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
                    if (@($script:GraphScopes).Count -gt @($script:GraphScopesCore).Count) { Add-Log "          To sign in without the extra permissions: untick 'Extended Graph checks' and click Refresh MFA." }
                }
                $lblProgress.Text = "Sign-in failed"
                Reset-MFAButtons
                return
            }

            # Got the token - stop the timer and run the queries
            $script:MFATimer.Stop()
            Add-Log "  [OK] Signed in successfully"
            Set-LTIGraphToken -TokenResp $tokenResp -Authority $script:MFAAuthority
            $script:GraphSignInAt = (Get-Date).ToUniversalTime()
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
    $script:LTIMembershipCache = @{}
    $script:LTIUserIdCache = @{}
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

    # Extended permissions wanted but missing from the current sign-in? Try to add
    # them silently; if the tenant has not consented them yet, sign in again.
    $wanted = @(Get-LTIWantedScopes)
    if ((Test-LTIGraphToken) -and ($wanted.Count -gt $script:GraphScopesCore.Count) -and -not (Test-LTIExtendedScopes)) {
        if (Request-LTIScopeUpgrade) {
            Add-Log "  Extended Graph permissions added to the existing sign-in"
        } else {
            Add-Log "  Signing in again to add the extended Graph permissions (Conditional Access, app consents)..."
            Clear-LTIGraphToken
        }
    }

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
        $script:GraphScopes = $wanted
        if ($wanted.Count -gt $script:GraphScopesCore.Count) {
            Add-Log "  Asking for the extended permissions too (Policy.Read.All, Directory.Read.All)."
            Add-Log "  If the browser says an admin must approve: untick 'Extended Graph checks' and click Refresh MFA again."
        }
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
$btnCheckAll.Add_Click({ for ($i=1;$i-le 19;$i++) { $chkSteps[$i].IsChecked=$true } })
$btnUncheckAll.Add_Click({ for ($i=1;$i-le 19;$i++) { $chkSteps[$i].IsChecked=$false } })
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
            if ($ci -and [string]$ci.UserPrincipalName -match '@([^@\s]+)$') { $script:LTIOperatorDomains = @(@($script:LTIOperatorDomains) + $Matches[1].ToLowerInvariant() | Select-Object -Unique) }
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
                   Select-Object DisplayName,UserPrincipalName,PrimarySmtpAddress,RecipientTypeDetails,ExternalDirectoryObjectId,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward |
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
    $all=[System.Collections.Generic.List[object]]::new(); $pg=1; $seen=@{}; $dups=0
    do { Add-Log "    Audit log query page $pg ..."; Flush-UI; $r=Search-UnifiedAuditLog @Params
        if ($null -eq $r -or @($r).Count -eq 0) { Add-Log "    No results."; break }
        # Large-set paging can hand back the same record on two pages; count each once.
        $bc=@($r).Count; foreach($x in @($r)){$rid=[string]$x.Identity; if($rid){ if($seen.ContainsKey($rid)){$dups++;continue}; $seen[$rid]=$true }; $all.Add($x)}
        Add-Log "    Page ${pg}: $bc record(s) (total: $($all.Count)$(if($dups -gt 0){", $dups duplicate(s) dropped"}))"
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
        $row.MicrosoftNetwork = $(if (Test-LTIMicrosoftNetwork -ASN ([string]$info.ASN) -ASName ([string]$info.ASName)) { "Yes" } else { "" })
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
        $f.CountriesOK       = $countries.OkCount
        $f.SuccessCountries  = $countries.OkText
    }
}

function Test-LTIMicrosoftNetwork {
    # Is this address in Microsoft's own network? (By AS number, or by the
    # network name when a lookup supplied one.)
    param([string]$ASN, [string]$ASName)

    if ($ASN -and (@($script:LTIMicrosoftASNs) -contains $ASN.Trim())) { return $true }
    if ($ASName -match '^(?i)MICROSOFT') { return $true }
    return $false
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
    if (Test-LTIMicrosoftNetwork -ASN ([string]$info.ASN) -ASName ([string]$info.ASName)) { $parts += "- Microsoft network" }
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
            $result = Get-LTISignInOutcome -Code $code

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
                SessionId         = [string]$s.sessionId
                AuthProtocol      = [string]$s.authenticationProtocol
                TransferMethod    = [string]$s.originalTransferMethod
                RiskDetail        = [string]$s.riskDetail
                Latitude          = $(if ($s.location -and $s.location.geoCoordinates -and $null -ne $s.location.geoCoordinates.latitude) { [string]$s.location.geoCoordinates.latitude } else { "" })
                Longitude         = $(if ($s.location -and $s.location.geoCoordinates -and $null -ne $s.location.geoCoordinates.longitude) { [string]$s.location.geoCoordinates.longitude } else { "" })
                AppId             = [string]$s.appId
                AppOwnerTenant    = [string]$s.appOwnerTenantId
                DeviceId          = [string]$dd.deviceId
            })
        }
        Flush-UI
    }

    return [PSCustomObject]@{ Rows = $rows; Truncated = $truncated; Note = $note }
}

function Get-LTISignInOutcome {
    # Entra error code -> Success | Interrupted | Failure.
    param($Code)

    $n = 0
    if ($null -eq $Code -or [string]$Code -eq '') { return 'Failure' }
    if (-not [int]::TryParse([string]$Code, [ref]$n)) { return 'Failure' }
    if ($n -eq 0) { return 'Success' }
    if (@($script:LTIInterruptCodes) -contains $n) { return 'Interrupted' }
    return 'Failure'
}

function Get-LTIAuditOutcome {
    # The same three-way outcome for a unified-audit-log sign-in row.
    param($Row)

    if ($null -eq $Row) { return '' }
    if ($Row.Operation -eq 'UserLoggedIn') { return 'Success' }
    if ($Row.Operation -ne 'UserLoginFailed') { return '' }
    $outcome = Get-LTISignInOutcome -Code $Row.ErrorCode
    if ($outcome -eq 'Success') { return 'Failure' }   # a failed-login record with code 0 is still a failure
    if ($outcome -eq 'Failure' -and [string]$Row.LogonError -match 'Interrupt$') { return 'Interrupted' }
    return $outcome
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
            $map[$ip] = [PSCustomObject]@{ AuditOK = 0; AuditFailed = 0; AuditInterrupted = 0; InteractiveOK = 0; InteractiveFailed = 0; InteractiveInterrupted = 0; NonInteractiveOK = 0; NonInteractiveFailed = 0; NonInteractiveInterrupted = 0; First = $null; Last = $null }
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
        switch (Get-LTIAuditOutcome -Row $r) { 'Success' { $counter = 'AuditOK' } 'Failure' { $counter = 'AuditFailed' } 'Interrupted' { $counter = 'AuditInterrupted' } }
        & $touch ([string]$r.ClientIP) $counter $r.Timestamp
    }
    foreach ($r in @($EntraSignIns)) {
        if ($null -eq $r) { continue }
        $counter = $r.Type + 'OK'
        if ($r.Result -eq 'Interrupted') { $counter = $r.Type + 'Interrupted' }
        elseif ($r.Result -ne 'Success') { $counter = $r.Type + 'Failed' }
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
            MicrosoftNetwork     = $(if ($info -and (Test-LTIMicrosoftNetwork -ASN ([string]$info.ASN) -ASName ([string]$info.ASName))) { "Yes" } else { "" })
            AuditOK              = $e.AuditOK
            AuditFailed          = $e.AuditFailed
            InteractiveOK        = $e.InteractiveOK
            InteractiveFailed    = $e.InteractiveFailed
            NonInteractiveOK     = $e.NonInteractiveOK
            NonInteractiveFailed = $e.NonInteractiveFailed
            AuditInterrupted          = $e.AuditInterrupted
            InteractiveInterrupted    = $e.InteractiveInterrupted
            NonInteractiveInterrupted = $e.NonInteractiveInterrupted
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
    # "US: 412 ok / 3 failed (4 IPs); NG: 0 ok / 57 failed (12 IPs)" - how many
    # sign-ins SUCCEEDED and failed in each country.
    # The audit log and the Entra log both record interactive sign-ins, so per
    # address the larger of the two counts is used, plus the background
    # (non-interactive) sign-ins that only the Entra log has. Prompts and
    # expired sessions (Interrupted) are in neither number.
    # Returns Text, Count (countries seen), OkCount (countries where a sign-in
    # succeeded) and OkText ("US 412; GB 3").
    param($Rows)

    $all = @(@($Rows) | Where-Object { $_ })
    if ($all.Count -eq 0) { return [PSCustomObject]@{ Text = ""; Count = 0; OkCount = 0; OkText = "" } }

    $byCountry = @{}
    foreach ($row in $all) {
        $key = [string]$row.Country
        if (-not $byCountry.ContainsKey($key)) { $byCountry[$key] = [PSCustomObject]@{ Name = $key; IPs = 0; OK = 0; Failed = 0; MS = 0 } }
        $c = $byCountry[$key]
        $c.IPs++
        if ($row.MicrosoftNetwork -eq 'Yes') { $c.MS++ }
        $c.OK     += [Math]::Max([int]$row.AuditOK, [int]$row.InteractiveOK) + [int]$row.NonInteractiveOK
        $c.Failed += [Math]::Max([int]$row.AuditFailed, [int]$row.InteractiveFailed) + [int]$row.NonInteractiveFailed
    }
    $order = @{ Expression = 'OK'; Descending = $true }, @{ Expression = 'Failed'; Descending = $true }, @{ Expression = 'Name' }
    $known = @($byCountry.Values | Where-Object { $_.Name } | Sort-Object -Property $order)
    # No address has a country (step 18 off and no lookup): nothing useful to say.
    if ($known.Count -eq 0) { return [PSCustomObject]@{ Text = ""; Count = 0; OkCount = 0; OkText = "" } }
    $ipText = {
        param($c)
        $t = "$($c.IPs) IP$(if ($c.IPs -ne 1) { 's' })"
        if ($c.MS -gt 0 -and $c.MS -eq $c.IPs) { $t += ", all Microsoft network" } elseif ($c.MS -gt 0) { $t += ", $($c.MS) Microsoft network" }
        return $t
    }
    $parts = @($known | ForEach-Object { "$($_.Name): $($_.OK) ok / $($_.Failed) failed ($(& $ipText $_))" })
    if ($byCountry.ContainsKey('')) {
        $u = $byCountry['']
        $parts += "unlabelled: $($u.OK) ok / $($u.Failed) failed ($(& $ipText $u))"
    }
    $okList = @($known | Where-Object { $_.OK -gt 0 })
    return [PSCustomObject]@{
        Text    = ($parts -join "; ")
        Count   = $known.Count
        OkCount = $okList.Count
        OkText  = (@($okList | ForEach-Object { "$($_.Name) $($_.OK)" }) -join "; ")
    }
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
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Mailbox Forwarding" `
        -BaselineFile (Join-Path $BaselineUserFolder "04_Mailbox_Forwarding.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "04_Mailbox_Forwarding.csv") `
        -KeyColumns @("UserPrincipalName") `
        -CompareColumns @("ForwardingAddress","ForwardingSmtpAddress","DeliverToMailboxAndForward")
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Transport Rules" `
        -BaselineFile (Join-Path $BaselineUserFolder "05_Transport_Rules.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "05_Transport_Rules.csv") `
        -KeyColumns @("Name") `
        -CompareColumns @("State","Priority","Description","Mode")
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Full Access Permissions" `
        -BaselineFile (Join-Path $BaselineUserFolder "06a_FullAccess_Permissions.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "06a_FullAccess_Permissions.csv") `
        -KeyColumns @("User") `
        -CompareColumns @("AccessRights","Deny")
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Send-As Permissions" `
        -BaselineFile (Join-Path $BaselineUserFolder "06b_SendAs_Permissions.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "06b_SendAs_Permissions.csv") `
        -KeyColumns @("Trustee") `
        -CompareColumns @("AccessControlType","AccessRights")
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Send on Behalf" `
        -BaselineFile (Join-Path $BaselineUserFolder "06c_SendOnBehalf.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "06c_SendOnBehalf.csv") `
        -KeyColumns @("GrantSendOnBehalfTo") `
        -CompareColumns @("GrantSendOnBehalfTo")
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Calendar Delegates" `
        -BaselineFile (Join-Path $BaselineUserFolder "06d_Calendar_Delegates.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "06d_Calendar_Delegates.csv") `
        -KeyColumns @("User") `
        -CompareColumns @("AccessRights","SharingPermissionFlags")
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Auto-Reply / OOF" `
        -BaselineFile (Join-Path $BaselineUserFolder "07_AutoReply_OOF.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "07_AutoReply_OOF.csv") `
        -KeyColumns @("AutoReplyState") `
        -CompareColumns @("AutoReplyState","InternalMessage","ExternalMessage","ExternalAudience","StartTime","EndTime")
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Mobile Devices" `
        -BaselineFile (Join-Path $BaselineUserFolder "08_Mobile_Devices.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "08_Mobile_Devices.csv") `
        -KeyColumns @("DeviceId") `
        -CompareColumns @("FriendlyName","DeviceModel","DeviceOS","DeviceAccessState")
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Mailbox Audit Config" `
        -BaselineFile (Join-Path $BaselineUserFolder "15_Mailbox_Audit_Config.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "15_Mailbox_Audit_Config.csv") `
        -KeyColumns @("UserPrincipalName") `
        -CompareColumns @("AuditEnabled","AuditLogAgeLimit","AuditAdmin","AuditDelegate","AuditOwner")
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

    # MFA baseline comparison. 17_MFA_Status.csv is a tenant-level file, so it is
    # filtered to this user - otherwise every user's report lists everyone's changes.
    $c = Compare-BaselineCSV -Label "MFA Status" `
        -BaselineFile (Join-Path (Split-Path $BaselineUserFolder -Parent) "17_MFA_Status.csv") `
        -CurrentFile (Join-Path (Split-Path $CurrentUserFolder -Parent) "17_MFA_Status.csv") `
        -KeyColumns @("UPN") `
        -CompareColumns @("MFAStatus","MFAMethods","MFAFirstConfigSeen","MFALastConfig","MFALastConfigEvent","DefaultMethod") `
        -FilterColumn "UPN" -FilterValue $UPN
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

    # REV 3.0 files. A baseline taken with an older version has neither, and is skipped.
    $c = Compare-BaselineCSV -Label "App Consents (this user)" `
        -BaselineFile (Join-Path $BaselineUserFolder "19_App_Consents.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "19_App_Consents.csv") `
        -KeyColumns @("App","AppId") `
        -CompareColumns @("Scopes") `
        -FilterColumn "Kind" -FilterValue "Current consent (this user)"
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

    $c = Compare-BaselineCSV -Label "Protocol Settings" `
        -BaselineFile (Join-Path $BaselineUserFolder "15a_Protocol_Settings.csv") `
        -CurrentFile (Join-Path $CurrentUserFolder "15a_Protocol_Settings.csv") `
        -KeyColumns @("Mailbox") `
        -CompareColumns @("ImapEnabled","PopEnabled","SmtpClientAuthenticationDisabled","ActiveSyncEnabled")
    if ($c.Count -gt 0) { foreach ($line in @($c)) { $report.Add([string]$line) }; $report.Add(""); $totalChanges += $c.Count }

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
    $findings=[PSCustomObject]@{
        UPN=$UPN; DisplayName=""; MailboxType=""; OutputFolder=$OutputFolder
        Score=0; Level="None"; Reasons=@(); ReasonText=""
        SignInsOK=0; SignInsFailed=0; SignInsInterrupted=0; UniqueIPs=0; SignInIPs=""; SignInCountries=""; CountryCount=0; CountriesOK=0; SuccessCountries=""
        EntraSignInLog="Not run"; EntraInteractive=""; EntraNonInteractive=""; NonInteractiveIPs=""
        Indicators=@(); SignInIndicators=""
        ForwardingActive=$false; ForwardingTarget=""; ForwardingExternal=""; ForwardingLookAlike=""; ForwardingAll=""; MailboxForwardExternal=""; ForwardingUnclassified=""
        SuspiciousRules=0; HiddenRules=0; TotalRules=0; RuleFlags=""; RuleDetails=@()
        OAuthConsents=0; AppStatus="Not run"; AppGrants=0; AppEvents=0; RiskyApps=""; AbusedApps=""; MailApps=""; AppRows=@()
        AdminActions=0; FileEvents=0
        OutboundMail=0; OutboundProfile=""; OutboundBurst=$false; OutboundBurstReason=""
        Protocols=""; AuditEnabled=$null
        MFAStatus="NotChecked"; MFAMethods=""; NewMFAMethods=0; AccountEnabled=""; MFAEnforcement=""; MFAEnforcedBy=""
        TimelineRows=@(); Errors=[System.Collections.Generic.List[string]]::new()
    }
    # AuditEnabled stays $null and MFAStatus stays "NotChecked" until the relevant check
    # actually runs, so a skipped or failed check is never reported as "off".

    $auditSignIns=@(); $entraSignIns=@()   # kept for the IP roll-up at the end
    $collected=@{}                         # each step's rows, for the merged timeline
    Add-Log "Verifying mailbox: $UPN"; Flush-UI
    try { $mbx=Get-Mailbox -Identity $UPN -ErrorAction Stop; $findings.DisplayName=$mbx.DisplayName; Add-Log "  [OK] Mailbox: $($mbx.DisplayName) [$($mbx.PrimarySmtpAddress)]" }
    catch { Add-Log "  [ERROR] Not found: $_"; $findings.Errors.Add("Not found: $_"); return $findings }

    if ($EnabledSteps[1]) { Add-Log "======================================================================"; Add-Log "  1. Sign-In and Authentication Events"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("UserLoggedIn","UserLoginFailed","ForeignRealmIndexLogonInitialAuthUsingADFSFederatedToken","PasswordLogonInitialAuthUsingPassword")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;ResultStatus=$a.ResultStatus;LogonError=$a.LogonError;ErrorCode=$(if($null -ne $a.ErrorCode -and "$($a.ErrorCode)" -ne ''){$a.ErrorCode}else{$a.ErrorNumber});ClientIP=(Get-LTIAuditIP $a);UserAgent=$a.ExtendedProperties|Where-Object{$_.Name -eq "UserAgent"}|Select-Object -ExpandProperty Value -ErrorAction SilentlyContinue;RequestType=$a.ExtendedProperties|Where-Object{$_.Name -eq "RequestType"}|Select-Object -ExpandProperty Value -ErrorAction SilentlyContinue;Application=$a.ApplicationId;Workload=$a.Workload}}
            # Outcome: Success / Failure / Interrupted (a prompt or an expired session - not a rejected sign-in).
            foreach($p in @($parsed)){ if($null -ne $p){ $p|Add-Member -NotePropertyName Outcome -NotePropertyValue (Get-LTIAuditOutcome -Row $p) -Force } }
            Export-ResultSet -Name "Sign-In Events" -FileName "01_SignIn_Events.csv" -OutFolder $OutputFolder -Data $parsed
            $findings.SignInsOK=@($parsed|Where-Object{$_.Operation -eq "UserLoggedIn"}).Count; $findings.SignInsFailed=@($parsed|Where-Object{$_.Outcome -eq "Failure"}).Count; $findings.SignInsInterrupted=@($parsed|Where-Object{$_.Outcome -eq "Interrupted"}).Count; $findings.UniqueIPs=@($parsed|Where-Object{$_.ClientIP}|Select-Object -ExpandProperty ClientIP -Unique).Count
            $auditSignIns=@($parsed|Where-Object{$_})
            Add-Log "  Sign-ins: $($findings.SignInsOK) ok, $($findings.SignInsFailed) failed, $($findings.UniqueIPs) IPs$(if($findings.SignInsInterrupted -gt 0){" (+$($findings.SignInsInterrupted) interrupted: prompts / expired sessions, not failures)"})"
            if(($findings.SignInsOK + $findings.SignInsFailed + $findings.SignInsInterrupted) -gt 0 -and $findings.UniqueIPs -eq 0){Add-Log "  [WARN] $($findings.SignInsOK + $findings.SignInsFailed + $findings.SignInsInterrupted) sign-in record(s) came back with no IP address in ClientIP or ActorIpAddress. Check the Entra sign-in log for this user."}
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Sign-ins: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 1" }

    if ($EnabledSteps[2]) { Add-Log "======================================================================"; Add-Log "  2. Mailbox Activity"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("MailboxLogin","MailItemsAccessed","Send","SendAs","SendOnBehalf","Create","HardDelete","SoftDelete","MoveToDeletedItems","Update","Copy","Move")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops -RecordTypes @("ExchangeItem","ExchangeItemAggregated")
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;ClientIP=(Get-LTIAuditIP $a);ClientInfo=$a.ClientInfoString;ItemSubject=$a.Item.Subject;Folder=$a.Item.ParentFolder.Path;ResultStatus=$a.ResultStatus}}
            Export-ResultSet -Name "Mailbox Activity" -FileName "02_Mailbox_Activity.csv" -OutFolder $OutputFolder -Data $parsed; $collected.Mailbox=@($parsed|Where-Object{$_})
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Mailbox: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 2" }

    if ($EnabledSteps[3]) { Add-Log "======================================================================"; Add-Log "  3. Inbox Rules"; Add-Log "======================================================================"; Flush-UI
        try {
            $allRules = @(Get-InboxRule -Mailbox $UPN -IncludeHidden -ErrorAction Stop | Where-Object { $_ })
            # Rules that only appear with -IncludeHidden are hidden from Outlook - the
            # way an attacker keeps a forwarding rule out of the user's sight.
            $visible = @{}
            try { foreach ($vr in @(Get-InboxRule -Mailbox $UPN -ErrorAction Stop | Where-Object { $_ })) { $visible[([string]$vr.RuleIdentity + '|' + [string]$vr.Name)] = $true } } catch { $visible = $null }
            $j = { param($v) (@($v | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join '; ') }
            $ruleRows = [System.Collections.Generic.List[object]]::new()
            foreach ($rule in $allRules) {
                $isHidden = $false
                if ($null -ne $visible) { $isHidden = -not $visible.ContainsKey(([string]$rule.RuleIdentity + '|' + [string]$rule.Name)) }
                # Exchange keeps hidden rules of its own on a mailbox: the junk e-mail rule and,
                # when automatic replies are set, the Microsoft.Exchange.OOF.* rules. They are
                # accepted as built-in only while they do nothing an attacker would want - a rule
                # that borrows one of these names and forwards, deletes or hides mail is flagged.
                $systemName = ([string]$rule.Name -match '^(Junk E-?mail Rule|Microsoft\.Exchange\.OOF\..+)$')
                $review = Get-LTIRuleReview -Rule $rule -Hidden $false
                $builtIn = $isHidden -and $systemName -and (-not $review.Suspicious)
                if ($isHidden -and -not $builtIn) {
                    $review = Get-LTIRuleReview -Rule $rule -Hidden $true
                    if ($systemName) { $review = [PSCustomObject]@{ Flags = @(@($review.Flags) + "carries the name of an Exchange system rule but acts on mail"); Targets = $review.Targets; Suspicious = $true } }
                }
                foreach ($tgt in $review.Targets) {
                    Add-LTIForwardingRow -UPN $UPN -Source "Inbox rule '$($rule.Name)' - $($tgt.Kind)" -Raw $tgt.Raw -Address $tgt.Address -Note $(if ($rule.Enabled -eq $false) { "rule is disabled" } elseif ($isHidden) { "hidden rule" } else { "" })
                }
                $ruleRows.Add([PSCustomObject]@{
                    Name = $rule.Name; Description = $rule.Description; Enabled = $rule.Enabled; Hidden = $isHidden
                    Suspicious = $review.Suspicious; Flags = $(if ($builtIn) { "(built-in Exchange rule: junk e-mail / automatic replies)" } else { $review.Flags -join '; ' }); Priority = $rule.Priority
                    ForwardTo = (& $j $rule.ForwardTo); ForwardAsAttachmentTo = (& $j $rule.ForwardAsAttachmentTo); RedirectTo = (& $j $rule.RedirectTo)
                    DeleteMessage = $rule.DeleteMessage; MoveToFolder = $rule.MoveToFolder; CopyToFolder = $rule.CopyToFolder; MarkAsRead = $rule.MarkAsRead; StopProcessingRules = $rule.StopProcessingRules
                    SubjectContains = (& $j $rule.SubjectContainsWords); BodyContains = (& $j $rule.BodyContainsWords); SubjectOrBodyContains = (& $j $rule.SubjectOrBodyContainsWords)
                    FromAddress = (& $j $rule.From); FromAddressContains = (& $j $rule.FromAddressContainsWords); SentTo = (& $j $rule.SentTo)
                    Identity = $rule.Identity; RuleIdentity = $rule.RuleIdentity
                })
            }
            Export-ResultSet -Name "Inbox Rules" -FileName "03_Inbox_Rules.csv" -OutFolder $OutputFolder -Data @($ruleRows)
            $sus = @($ruleRows | Where-Object { $_.Suspicious })
            $findings.TotalRules = $ruleRows.Count; $findings.SuspiciousRules = $sus.Count; $findings.RuleDetails = @($ruleRows)
            $findings.HiddenRules = @($ruleRows | Where-Object { $_.Hidden -and $_.Flags -notmatch 'built-in' }).Count
            $findings.RuleFlags = (@($sus | ForEach-Object { "'$($_.Name)': $($_.Flags)" }) -join ' | ')
            if ($sus.Count -gt 0) { Add-Log "  [WARN] *** $($sus.Count) RULE(S) FLAGGED ***"; foreach ($sr in $sus) { Add-Log "    Rule '$($sr.Name)': $($sr.Flags)" } }
            else { Add-Log "  $($ruleRows.Count) rule(s), none flagged." }
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Rules: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 3" }

    if ($EnabledSteps[4]) { Add-Log "======================================================================"; Add-Log "  4. Mailbox Forwarding (SMTP)"; Add-Log "======================================================================"; Flush-UI
        try { $fw=Get-Mailbox -Identity $UPN|Select-Object DisplayName,UserPrincipalName,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward
            Export-ResultSet -Name "Forwarding" -FileName "04_Mailbox_Forwarding.csv" -OutFolder $OutputFolder -Data $fw
            # The live mailbox replaces whatever the mailbox list (loaded earlier) said.
            foreach($old in @($script:allForwarding|Where-Object{$_.UPN -eq $UPN -and $_.Source -like 'Mailbox forwarding*'})){[void]$script:allForwarding.Remove($old)}
            $null=Add-LTIMailboxForwardingRows -Mailbox $fw -UPN $UPN
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
            Export-ResultSet -Name "OAuth" -FileName "09_OAuth_App_Consent.csv" -OutFolder $OutputFolder -Data $parsed; $collected.OAuth=@($parsed|Where-Object{$_}); $findings.OAuthConsents=@($parsed).Count
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("OAuth: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 9" }

    if ($EnabledSteps[10]) { Add-Log "======================================================================"; Add-Log "  10. Rule Changes"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("New-InboxRule","Set-InboxRule","Enable-InboxRule","Remove-InboxRule","UpdateInboxRules","New-TransportRule","Set-TransportRule")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;Parameters=($a.Parameters|ForEach-Object{"$($_.Name)=$($_.Value)"}) -join '; ';ClientIP=(Get-LTIAuditIP $a);SessionId=$a.SessionId}}
            Export-ResultSet -Name "Rule Changes" -FileName "10_Rule_Changes.csv" -OutFolder $OutputFolder -Data $parsed; $collected.RuleChanges=@($parsed|Where-Object{$_})
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("RuleChg: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 10" }

    if ($EnabledSteps[11]) { Add-Log "======================================================================"; Add-Log "  11. File Activity"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("FileDownloaded","FileUploaded","FileDeleted","FileModified","FileRenamed","FileMoved","FileCopied","SharingSet","AnonymousLinkCreated","CompanyLinkCreated","SharingInvitationCreated","AddedToSecureLink")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops -RecordTypes @("SharePointFileOperation")
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;FileName=$a.SourceFileName;FileUrl=$a.ObjectId;SiteUrl=$a.SiteUrl;ClientIP=(Get-LTIAuditIP $a);UserAgent=$a.UserAgent}}
            Export-ResultSet -Name "File Activity" -FileName "11_File_Activity.csv" -OutFolder $OutputFolder -Data $parsed; $collected.Files=@($parsed|Where-Object{$_}); $findings.FileEvents=@($parsed).Count
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Files: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 11" }

    if ($EnabledSteps[12]) { Add-Log "======================================================================"; Add-Log "  12. Admin Actions"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("Add member to role.","Add user.","Reset user password.","Set force change user password.","Update user.","Delete user.","Set-Mailbox","Add-MailboxPermission","Remove-MailboxPermission","New-ManagementRoleAssignment")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;Target=($a.Target|ForEach-Object{$_.Id}) -join '; ';Parameters=($a.Parameters|ForEach-Object{"$($_.Name)=$($_.Value)"}) -join '; ';ClientIP=(Get-LTIAuditIP $a);ResultStatus=$a.ResultStatus}}
            Export-ResultSet -Name "Admin Actions" -FileName "12_Admin_Actions.csv" -OutFolder $OutputFolder -Data $parsed; $collected.Admin=@($parsed|Where-Object{$_}); $findings.AdminActions=@($parsed).Count
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Admin: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 12" }

    if ($EnabledSteps[13]) { Add-Log "======================================================================"; Add-Log "  13. eDiscovery"; Add-Log "======================================================================"; Flush-UI
        try { $ops=@("SearchStarted","SearchExportDownloaded","New-ComplianceSearch","New-ComplianceSearchAction","CaseAdded")
            $raw=Search-UnifiedAuditLogAll -Start $StartDate -End $EndDate -UserIds $UPN -Operations $ops
            $parsed=$raw|ForEach-Object{$a=$_|Select-Object -ExpandProperty AuditData|ConvertFrom-Json;[PSCustomObject]@{Timestamp=(Get-LTIAuditTime $_ $a);Operation=$a.Operation;Parameters=($a.Parameters|ForEach-Object{"$($_.Name)=$($_.Value)"}) -join '; ';ClientIP=(Get-LTIAuditIP $a)}}
            Export-ResultSet -Name "eDiscovery" -FileName "13_eDiscovery_Activity.csv" -OutFolder $OutputFolder -Data $parsed; $collected.EDiscovery=@($parsed|Where-Object{$_})
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("eDisc: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 13" }

    if ($EnabledSteps[14]) { Add-Log "======================================================================"; Add-Log "  14. Message Trace"; Add-Log "======================================================================"; Flush-UI
        try { Add-Log "  Outbound..."; Flush-UI; $ob=Get-MessageTraceV2All -SenderAddress $UPN -Start $StartDate -End $EndDate
            $obs=$ob|Select-Object @{N='Received';E={Format-LTIDateTime $_.Received}},SenderAddress,RecipientAddress,Subject,Status,@{N='FromIP';E={$_.FromIP}},Size,MessageId; Export-ResultSet -Name "Outbound" -FileName "14a_MessageTrace_Outbound.csv" -OutFolder $OutputFolder -Data $obs; $findings.OutboundMail=@($ob).Count
            $outbound=Get-LTIOutboundProfile -Rows $ob; $findings.OutboundProfile=$outbound.Text; $findings.OutboundBurst=$outbound.Burst; $findings.OutboundBurstReason=$outbound.BurstReason; $collected.Outbound=@($ob|Where-Object{$_})
            if(@($outbound.Hours).Count -gt 0){Export-ResultSet -Name "Outbound by hour" -FileName "14c_Outbound_By_Hour.csv" -OutFolder $OutputFolder -Data @($outbound.Hours)}
            if($outbound.Burst){Add-Log "  [WARN] *** OUTBOUND BURST: $($outbound.BurstReason) ***"}elseif($outbound.Text){Add-Log "  $($outbound.Text)"}
            Add-Log "  Inbound..."; Flush-UI; $ib=Get-MessageTraceV2All -RecipientAddress $UPN -Start $StartDate -End $EndDate
            $ibs=$ib|Select-Object @{N='Received';E={Format-LTIDateTime $_.Received}},SenderAddress,RecipientAddress,Subject,Status,@{N='FromIP';E={$_.FromIP}},Size,MessageId; Export-ResultSet -Name "Inbound" -FileName "14b_MessageTrace_Inbound.csv" -OutFolder $OutputFolder -Data $ibs
        } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Trace: $_") }; Flush-UI
    } else { Add-Log "  [SKIP] Step 14" }

    if ($EnabledSteps[15]) { Add-Log "======================================================================"; Add-Log "  15. Audit Config"; Add-Log "======================================================================"; Flush-UI
        try { $ac=Get-Mailbox -Identity $UPN|Select-Object DisplayName,UserPrincipalName,AuditEnabled,AuditLogAgeLimit,@{N='AuditAdmin';E={($_.AuditAdmin -join ', ')}},@{N='AuditDelegate';E={($_.AuditDelegate -join ', ')}},@{N='AuditOwner';E={($_.AuditOwner -join ', ')}}
            Export-ResultSet -Name "Audit Config" -FileName "15_Mailbox_Audit_Config.csv" -OutFolder $OutputFolder -Data $ac; $findings.AuditEnabled=$ac.AuditEnabled
            if($ac.AuditEnabled -ne $true){Add-Log "  [WARN] AUDITING DISABLED"}else{Add-Log "  Auditing enabled."}
            # Protocols that take a password with no MFA step.
            try { $cas=Get-CASMailbox -Identity $UPN -ErrorAction Stop|Select-Object @{N='Mailbox';E={$UPN}},ImapEnabled,PopEnabled,SmtpClientAuthenticationDisabled,ActiveSyncEnabled,OWAEnabled,MAPIEnabled,EwsEnabled
                Export-ResultSet -Name "Protocol settings" -FileName "15a_Protocol_Settings.csv" -OutFolder $OutputFolder -Data $cas
                $on=@(); if($cas.ImapEnabled -eq $true){$on+="IMAP"}; if($cas.PopEnabled -eq $true){$on+="POP"}
                $smtpOff=$cas.SmtpClientAuthenticationDisabled; if($null -eq $smtpOff){$smtpOff=$script:LTIOrgSmtpAuthDisabled}
                if($smtpOff -eq $false){$on+="SMTP AUTH"}
                $findings.Protocols=$(if($on.Count -gt 0){"$($on -join ', ') enabled"}else{"IMAP, POP and SMTP AUTH are off"}); Add-Log "  Protocols: $($findings.Protocols)"
            } catch { Add-Log "  [WARN] Protocol settings: $_" }
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
                $iNo = @($entraSignIns | Where-Object { $_.Type -eq 'Interactive' -and $_.Result -eq 'Failure' }).Count
                $iInt = @($entraSignIns | Where-Object { $_.Type -eq 'Interactive' -and $_.Result -eq 'Interrupted' }).Count
                $nInt = @($entraSignIns | Where-Object { $_.Type -eq 'NonInteractive' -and $_.Result -eq 'Interrupted' }).Count
                $nOK = @($entraSignIns | Where-Object { $_.Type -eq 'NonInteractive' -and $_.Result -eq 'Success' }).Count
                $nNo = @($entraSignIns | Where-Object { $_.Type -eq 'NonInteractive' -and $_.Result -eq 'Failure' }).Count
                $findings.EntraInteractive = "$iOK ok / $iNo failed$(if ($iInt -gt 0) { " / $iInt interrupted" })"
                $findings.EntraSignInLog = "OK"
                $reachNote = ""
                if ($script:LTILogReach -and $script:LTILogReach.SignIns -eq 'No') { $reachNote = " - tenant log only holds the last 7 days"; $findings.EntraSignInLog += $reachNote }
                if ($entra.Note) {
                    $findings.EntraSignInLog = "Partial - $($entra.Note)$reachNote"
                    Add-Log "  [WARN] $($entra.Note)"
                } else {
                    $findings.EntraNonInteractive = "$nOK ok / $nNo failed$(if ($nInt -gt 0) { " / $nInt interrupted" })"
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

    # Sign-in indicators: patterns across both sign-in logs that point at a stolen
    # session or a scripted attacker.
    if ($EnabledSteps[1] -or $EnabledSteps[18]) {
        try {
            $indicators = Get-LTISignInIndicators -EntraRows $entraSignIns -AuditRows $auditSignIns -UPN $UPN
            foreach ($note in @($script:LTIIndicatorNotes)) { Add-Log "  [INFO] $note" }
            if ($indicators.Count -gt 0) {
                $findings.Indicators = $indicators
                $findings.SignInIndicators = (@($indicators | ForEach-Object { "[$($_.Severity)] $($_.Indicator) ($($_.Count))" }) -join ' | ')
                Export-ResultSet -Name "Sign-in indicators" -FileName "18a_SignIn_Indicators.csv" -OutFolder $OutputFolder -Data $indicators
                foreach ($ind in $indicators) { Add-Log "  $(if ($ind.Severity -ne 'Low') { '[WARN] ' })[$($ind.Severity)] $($ind.Indicator) ($($ind.Count))" }
            }
        } catch { Add-Log "  [ERROR] Sign-in indicators: $_"; $findings.Errors.Add("Indicators: $_") }
    }

    if ($EnabledSteps[19]) { Add-Log "======================================================================"; Add-Log "  19. App Consents"; Add-Log "======================================================================"
        if (-not $script:LTIAppContext) {
            $findings.AppStatus = "Not checked - no Graph sign-in"
            Add-Log "  [SKIP] No Graph sign-in. Click 'Refresh MFA' and sign in before running to include this step."
        } else {
            try {
                $appf = Get-LTIAppFindingsForUser -UPN $UPN -UserId (Get-LTIUserId -UPN $UPN) -Context $script:LTIAppContext
                $findings.AppStatus = $appf.Status; $findings.AppGrants = $appf.Grants; $findings.AppEvents = $appf.Events
                $findings.RiskyApps = $appf.Risky; $findings.AbusedApps = $appf.Abused; $findings.MailApps = $appf.MailApps; $findings.AppRows = @($appf.Rows)
                Export-ResultSet -Name "App consents" -FileName "19_App_Consents.csv" -OutFolder $OutputFolder -Data @($appf.Rows)
                Add-Log "  $($appf.Grants) app(s) consented by this user, $($appf.Events) app change(s) in the window"
                if ($appf.Risky)  { Add-Log "  [WARN] Third-party app(s) with mail / file access: $($appf.Risky)" }
                if ($appf.Abused) { Add-Log "  [WARN] *** APP OFTEN SEEN IN MAILBOX COMPROMISES: $($appf.Abused) ***" }
            } catch { Add-Log "  [ERROR] $_"; $findings.Errors.Add("Apps: $_") }
        }
        Flush-UI
    } else { Add-Log "  [SKIP] Step 19" }

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
        $findings.CountriesOK       = $countries.OkCount
        $findings.SuccessCountries  = $countries.OkText
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
        $findings.MFAEnforcement = [string]$cachedMFA.MFAEnforcement
        $findings.MFAEnforcedBy  = [string]$cachedMFA.MFAEnforcedBy

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
    $loaded = $script:allMailboxes | Where-Object { $_.UserPrincipalName -eq $UPN } | Select-Object -First 1
    if ($loaded) { $findings.MailboxType = [string]$loaded.RecipientTypeDetails }

    # Everything this run learned about the mailbox, in time order. Written to
    # 00_Timeline.csv once the whole run has finished (so IP labels are final).
    try {
        $collected.SignIns    = $auditSignIns
        $collected.Entra      = $entraSignIns
        $collected.MfaMethods = @($script:allMFAMethodDetails | Where-Object { $_.UPN -eq $UPN })
        $collected.MfaAudit   = @($script:allMFAAuditRows | Where-Object { $_.UPN -eq $UPN })
        $collected.AppRows    = @($findings.AppRows)
        $collected.Indicators = @($findings.Indicators)
        $findings.TimelineRows = Get-LTITimeline -Data $collected -WindowStart $StartDate
    } catch { Add-Log "  [ERROR] Timeline: $_"; $findings.Errors.Add("Timeline: $_") }

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
#  REV 3.0 - GRAPH PERMISSION TIERS
#  Core permissions (MFA methods, audit log, users) are what the tool has always
#  asked for. The extended pair adds Conditional Access / Security Defaults /
#  per-user MFA (Policy.Read.All) and app consents, service principals and group
#  membership (Directory.Read.All). They are requested only when the "Extended
#  Graph checks" box is ticked, and every check that needs one of them tests for
#  it first, so a sign-in without them still does everything it did before.
# -----------------------------------------------------------------------------
function Get-LTIWantedScopes {
    $wanted = @($script:GraphScopesCore)
    if ($chkExtendedGraph -and $chkExtendedGraph.IsChecked -eq $true) { $wanted += @($script:GraphScopesExtended) }
    return $wanted
}

function Test-LTIGraphScope {
    # $true when the current Graph token carries the named permission.
    param([Parameter(Mandatory = $true)][string]$Name)

    if (-not $script:GraphToken) { return $false }
    if (@($script:GraphGrantedScopes).Count -gt 0) { return (@($script:GraphGrantedScopes) -contains $Name) }
    # Token claims were not readable: go by what was asked for.
    return (@($script:GraphScopes | ForEach-Object { ($_ -split '/')[-1] }) -contains $Name)
}

function Test-LTIExtendedScopes {
    return ((Test-LTIGraphScope -Name 'Policy.Read.All') -and (Test-LTIGraphScope -Name 'Directory.Read.All'))
}

function Request-LTIScopeUpgrade {
    # Tries to add the extended permissions to the existing sign-in WITHOUT a new
    # prompt. Works when they have already been consented in this tenant. On
    # failure the current token is left exactly as it was.
    if (-not $script:GraphRefreshToken -or -not $script:GraphAuthority) { return $false }

    $all = @($script:GraphScopesCore) + @($script:GraphScopesExtended)
    $previous = $script:GraphScopes
    try {
        $resp = Invoke-RestMethod -Method Post -Uri "$($script:GraphAuthority)/oauth2/v2.0/token" -Body @{
            grant_type    = "refresh_token"
            client_id     = $script:GraphClientId
            refresh_token = $script:GraphRefreshToken
            scope         = (($all -join " ") + " offline_access")
        } -ErrorAction Stop
        $script:GraphScopes = $all
        Set-LTIGraphToken -TokenResp $resp -Authority $script:GraphAuthority -Quiet
        if (Test-LTIExtendedScopes) { Write-Log "Extended Graph permissions added silently"; return $true }
        $script:GraphScopes = $previous
        return $false
    } catch {
        $info = Get-LTIHttpErrorInfo -ErrorRecord $_
        Write-Log "Silent scope upgrade not possible: $($info.Text)"
        $script:GraphScopes = $previous
        return $false
    }
}

function Get-LTIUserId {
    # Entra object ID for a UPN: from the directory map loaded by the MFA step,
    # otherwise one Graph lookup (cached). Returns "" when unknown.
    param([Parameter(Mandatory = $true)][string]$UPN)

    $key = $UPN.ToLowerInvariant()
    if ($script:MFAContext -and $script:MFAContext.DirectoryByUpn) {
        $dir = $script:MFAContext.DirectoryByUpn[$key]
        if ($dir -and $dir.id) { return [string]$dir.id }
    }
    if ($script:LTIUserIdCache.ContainsKey($key)) { return $script:LTIUserIdCache[$key] }
    $id = ""
    try {
        $u = Invoke-LTIGraphGet -Uri ('https://graph.microsoft.com/v1.0/users/' + [Uri]::EscapeDataString($UPN) + '?$select=id')
        if ($u -and $u.id) { $id = [string]$u.id }
    } catch { Write-Log "User ID lookup failed for ${UPN}: $($_.Exception.Message)" "WARN" }
    $script:LTIUserIdCache[$key] = $id
    return $id
}

# -----------------------------------------------------------------------------
#  REV 3.0 - IS MFA ACTUALLY ENFORCED?
#  A registered method only matters if something makes the user use it. Three
#  things can: Security Defaults, a Conditional Access policy, or legacy
#  per-user MFA. This reads all three and works out, per user, which applies.
# -----------------------------------------------------------------------------
function ConvertTo-LTICAPolicyInfo {
    # Conditional Access policy -> the facts needed to decide whether it makes a
    # given user do MFA at sign-in, plus a readable row for the CSV.
    param($Policy)

    $c = $Policy.conditions
    $g = $Policy.grantControls

    $builtIn = @()
    $operator = ""
    $strength = ""
    if ($g) {
        $builtIn = @($g.builtInControls | Where-Object { $_ })
        $operator = [string]$g.operator
        if ($g.authenticationStrength) {
            $strength = [string]$g.authenticationStrength.displayName
            if (-not $strength) { $strength = "authentication strength" }
        }
    }
    $isBlock     = ($builtIn -contains 'block')
    $requiresMfa = (-not $isBlock) -and (($builtIn -contains 'mfa') -or [bool]$strength)
    $others      = @($builtIn | Where-Object { $_ -ne 'mfa' -and $_ -ne 'block' })
    # "mfa OR compliantDevice": a compliant device satisfies the policy without MFA.
    $mfaOptional = $requiresMfa -and ($operator -eq 'OR') -and ($others.Count -gt 0)

    $grantParts = @($builtIn)
    if ($strength) { $grantParts += "strength: $strength" }
    $joiner = " AND "
    if ($operator -eq 'OR') { $joiner = " OR " }
    $grantText = ($grantParts -join $joiner)
    if (-not $grantText) { $grantText = "(session controls only)" }

    $u = $null; $a = $null
    if ($c) { $u = $c.users; $a = $c.applications }
    $list = { param($v) @($v | Where-Object { $_ } | ForEach-Object { [string]$_ }) }

    $incUsers  = @(& $list $u.includeUsers);  $excUsers  = @(& $list $u.excludeUsers)
    $incGroups = @(& $list $u.includeGroups); $excGroups = @(& $list $u.excludeGroups)
    $incRoles  = @(& $list $u.includeRoles);  $excRoles  = @(& $list $u.excludeRoles)

    $incApps = @(& $list $a.includeApplications)
    $excApps = @(& $list $a.excludeApplications)
    $actions = @(& $list $a.includeUserActions)
    # Exchange Online and SharePoint Online, as Conditional Access names them.
    $exoId = '00000002-0000-0ff1-ce00-000000000000'; $spoId = '00000003-0000-0ff1-ce00-000000000000'
    $appScope = 'Selected'
    if ($actions.Count -gt 0)              { $appScope = 'UserAction' }
    elseif ($incApps -contains 'All')      { $appScope = 'All' }
    elseif ($incApps -contains 'Office365' -or $incApps -contains $exoId) { $appScope = 'Office365' }
    elseif ($incApps.Count -eq 0)          { $appScope = 'None' }

    $appText = switch ($appScope) {
        'All'        { "All cloud apps" }
        'Office365'  { if ($incApps -contains 'Office365') { "Office 365" } else { "Exchange Online (one of $($incApps.Count) selected app(s))" } }
        'UserAction' { "User action: $($actions -join ', ')" }
        'None'       { "(none)" }
        default      { "$($incApps.Count) selected app(s)" }
    }
    if ($excApps.Count -gt 0) { $appText += ", excluding $($excApps.Count)" }

    # Conditions that narrow when the policy fires.
    $limits = [System.Collections.Generic.List[string]]::new()
    $locationExclusion = $false
    # Excluding some other app does not open the mailbox; excluding Office 365 does.
    if (@($excApps | Where-Object { @('Office365', $exoId, $spoId) -contains $_ }).Count -gt 0) { $limits.Add("excludes Office 365 / Exchange Online / SharePoint") }
    $clientTypes = @(); $modernOnly = $false
    if ($c) {
        $clientTypes = @(& $list $c.clientAppTypes)
        if ($clientTypes.Count -gt 0 -and -not ($clientTypes -contains 'all')) {
            # Browser + modern apps is every client that CAN do MFA. Legacy protocols
            # cannot, so they need a separate block policy - reported per user.
            if (($clientTypes -contains 'browser') -and ($clientTypes -contains 'mobileAppsAndDesktopClients')) { $modernOnly = $true }
            else { $limits.Add("client types: $($clientTypes -join ', ')") }
        }
        if ($c.locations) {
            $incLoc = @(& $list $c.locations.includeLocations)
            $excLoc = @(& $list $c.locations.excludeLocations)
            if ($incLoc.Count -gt 0 -and -not ($incLoc -contains 'All')) { $limits.Add("only from selected locations") }
            elseif ($excLoc.Count -gt 0) { $limits.Add("not from trusted / excluded locations"); $locationExclusion = $true }
        }
        if ($c.platforms) {
            $incPlat = @(& $list $c.platforms.includePlatforms)
            if ($incPlat.Count -gt 0 -and -not ($incPlat -contains 'all')) { $limits.Add("platforms: $($incPlat -join ', ')") }
        }
        if (@(& $list $c.signInRiskLevels).Count -gt 0) { $limits.Add("only on risky sign-ins ($((& $list $c.signInRiskLevels) -join ', '))") }
        if (@(& $list $c.userRiskLevels).Count -gt 0)   { $limits.Add("only for risky users ($((& $list $c.userRiskLevels) -join ', '))") }
        if ($c.devices -and $c.devices.deviceFilter)   { $limits.Add("device filter") }
    }
    $onlyLocationExclusion = $locationExclusion -and ($limits.Count -eq 1)

    $userParts = @()
    if ($incUsers -contains 'All') { $userParts += "All users" }
    else {
        $direct = @($incUsers | Where-Object { $_ -ne 'None' -and $_ -ne 'GuestsOrExternalUsers' })
        if ($direct.Count -gt 0)    { $userParts += "$($direct.Count) user(s)" }
        if ($incGroups.Count -gt 0) { $userParts += "$($incGroups.Count) group(s)" }
        if ($incRoles.Count -gt 0)  { $userParts += "$($incRoles.Count) role(s)" }
        if ($incUsers -contains 'GuestsOrExternalUsers' -or ($u -and $u.includeGuestsOrExternalUsers)) { $userParts += "guests" }
    }
    if ($userParts.Count -eq 0) { $userParts += "(nobody)" }
    $excCount = $excUsers.Count + $excGroups.Count + $excRoles.Count
    $usersText = ($userParts -join " + ")
    if ($excCount -gt 0) { $usersText += ", excluding $($excUsers.Count) user(s) / $($excGroups.Count) group(s) / $($excRoles.Count) role(s)" }

    return [PSCustomObject]@{
        Id = [string]$Policy.id; Name = [string]$Policy.displayName; State = [string]$Policy.state
        RequiresMFA = $requiresMfa; MfaOptional = $mfaOptional; IsBlock = $isBlock; GrantText = $grantText
        OtherControls = $others
        AppScope = $appScope; AppText = $appText
        IncludeUsers = $incUsers; ExcludeUsers = $excUsers
        IncludeGroups = $incGroups; ExcludeGroups = $excGroups
        IncludeRoles = $incRoles; ExcludeRoles = $excRoles
        UsersText = $usersText
        Limits = @($limits); OnlyLocationExclusion = $onlyLocationExclusion
        ClientTypes = $clientTypes; ModernOnly = $modernOnly
        BlocksLegacy = ($isBlock -and (($clientTypes -contains 'other') -or ($clientTypes -contains 'exchangeActiveSync')) -and (@('All', 'Office365') -contains $appScope))
    }
}

function Test-LTICAPolicyAppliesToUser {
    param($Info, [string]$UserId, $Membership)

    $groups = @(); $roles = @()
    if ($Membership) { $groups = @($Membership.Groups); $roles = @($Membership.Roles) }
    $hit = { param($set, $mine) foreach ($m in $mine) { if ($set -contains $m) { return $true } }; return $false }

    $included = $false
    if ($Info.IncludeUsers -contains 'All')                { $included = $true }
    elseif ($UserId -and ($Info.IncludeUsers -contains $UserId)) { $included = $true }
    elseif (& $hit $Info.IncludeGroups $groups)            { $included = $true }
    elseif (& $hit $Info.IncludeRoles $roles)              { $included = $true }
    if (-not $included) { return $false }

    if ($UserId -and ($Info.ExcludeUsers -contains $UserId)) { return $false }
    if (& $hit $Info.ExcludeGroups $groups) { return $false }
    if (& $hit $Info.ExcludeRoles $roles)   { return $false }
    return $true
}

function Get-LTIMFAEnforcementContext {
    # Tenant-level: Security Defaults + every Conditional Access policy.
    $ctx = @{
        Checked = $false; Reason = ""; SecurityDefaults = $null; CAError = ""
        Policies = @(); MfaPolicies = @(); LegacyBlockPolicies = @(); ReportOnly = 0; NeedsMembership = $false
        Rows = [System.Collections.Generic.List[object]]::new()
    }

    if (-not (Test-LTIGraphScope -Name 'Policy.Read.All')) {
        $ctx.Reason = "Not checked - needs the extended Graph permissions (tick 'Extended Graph checks', then Refresh MFA)"
        Add-Log "  [INFO] MFA enforcement not checked: the sign-in does not include Policy.Read.All."
        Add-Log "         Tick 'Extended Graph checks' and click Refresh MFA to add it."
        return $ctx
    }

    try {
        $sd = Invoke-LTIGraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
        $ctx.SecurityDefaults = ($sd.isEnabled -eq $true)
    } catch {
        Write-Log "Security Defaults lookup failed: $($_.Exception.Message)" "WARN"
        $ctx.Reason = "Security Defaults could not be read: $($_.Exception.Message)"
    }

    try {
        $raw = Get-LTIGraphPaged -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
        $ctx.Policies = @($raw | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-LTICAPolicyInfo -Policy $_ })
    } catch {
        # Tenants without Entra ID P1 have no Conditional Access; Graph may refuse the list.
        $ctx.CAError = [string]$_.Exception.Message
        Write-Log "Conditional Access policy list failed: $($ctx.CAError)" "WARN"
    }

    $ctx.Checked = ($null -ne $ctx.SecurityDefaults) -or ($ctx.Policies.Count -gt 0) -or (-not $ctx.CAError)
    if (-not $ctx.Checked -and -not $ctx.Reason) { $ctx.Reason = "Could not be read: $($ctx.CAError)" }

    $ctx.MfaPolicies = @($ctx.Policies | Where-Object { $_.State -eq 'enabled' -and $_.RequiresMFA -and @('All', 'Office365', 'Selected') -contains $_.AppScope })
    $ctx.ReportOnly  = @($ctx.Policies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' -and $_.RequiresMFA }).Count
    $ctx.LegacyBlockPolicies = @($ctx.Policies | Where-Object { $_.State -eq 'enabled' -and $_.BlocksLegacy })
    $ctx.NeedsMembership = (@(@($ctx.MfaPolicies) + @($ctx.LegacyBlockPolicies) | Where-Object { ($_.IncludeGroups.Count + $_.ExcludeGroups.Count + $_.IncludeRoles.Count + $_.ExcludeRoles.Count) -gt 0 }).Count -gt 0)

    $sdText = "Unknown"
    if ($ctx.SecurityDefaults -eq $true) { $sdText = "Enabled" } elseif ($ctx.SecurityDefaults -eq $false) { $sdText = "Disabled" }
    $ctx.Rows.Add([PSCustomObject]@{ Policy = "Security Defaults"; State = $sdText; RequiresMFA = ($ctx.SecurityDefaults -eq $true); Grant = "MFA for all users (Microsoft-managed)"; Users = "All users"; Apps = "All cloud apps"; Conditions = ""; CountsAsSignInMFA = ($ctx.SecurityDefaults -eq $true) })
    foreach ($p in $ctx.Policies) {
        $counts = ($ctx.MfaPolicies -contains $p)
        $ctx.Rows.Add([PSCustomObject]@{ Policy = $p.Name; State = $p.State; RequiresMFA = $p.RequiresMFA; Grant = $p.GrantText; Users = $p.UsersText; Apps = $p.AppText; Conditions = ($p.Limits -join '; '); CountsAsSignInMFA = $counts })
    }

    $caText = "$($ctx.Policies.Count) Conditional Access policy(ies), $($ctx.MfaPolicies.Count) enabled and requiring MFA"
    if ($ctx.CAError) { $caText = "Conditional Access not readable ($($ctx.CAError))" }
    Add-Log "  [OK] MFA enforcement: Security Defaults $sdText; $caText$(if ($ctx.ReportOnly -gt 0) { "; $($ctx.ReportOnly) MFA policy(ies) in report-only mode (not enforced)" })"
    return $ctx
}

function Get-LTIUserMembership {
    # Transitive group IDs and directory-role template IDs for a user (cached).
    param([Parameter(Mandatory = $true)][string]$UserId)

    if ($script:LTIMembershipCache.ContainsKey($UserId)) { return $script:LTIMembershipCache[$UserId] }
    $m = [PSCustomObject]@{ Groups = @(); Roles = @(); Known = $false }
    try {
        $items = Get-LTIGraphPaged -Uri "https://graph.microsoft.com/v1.0/users/$UserId/transitiveMemberOf?`$top=999"
        $m.Groups = @($items | Where-Object { [string]$_.'@odata.type' -match 'group$' } | ForEach-Object { [string]$_.id })
        $m.Roles  = @($items | Where-Object { [string]$_.'@odata.type' -match 'directoryRole$' } | ForEach-Object { [string]$_.roleTemplateId } | Where-Object { $_ })
        $m.Known = $true
    } catch { Write-Log "Group membership lookup failed for ${UserId}: $($_.Exception.Message)" "WARN" }
    $script:LTIMembershipCache[$UserId] = $m
    return $m
}

function Get-LTIPerUserMfaState {
    # Legacy per-user MFA: 'disabled', 'enabled' or 'enforced'. "" when unknown.
    param([Parameter(Mandatory = $true)][string]$UserId)
    try {
        $r = Invoke-LTIGraphGet -Uri "https://graph.microsoft.com/beta/users/$UserId/authentication/requirements"
        return [string]$r.perUserMfaState
    } catch {
        Write-Log "Per-user MFA state lookup failed for ${UserId}: $($_.Exception.Message)" "WARN"
        return ""
    }
}

function Get-LTIMFAEnforcement {
    # State: Enforced | Partial | NotEnforced | Unknown        By: the reason, in words
    param([string]$UserId, $Context)

    if (-not $Context -or -not $Context.Checked) {
        $why = "Not checked"
        if ($Context -and $Context.Reason) { $why = $Context.Reason }
        return [PSCustomObject]@{ State = "Unknown"; By = $why }
    }
    if ($Context.SecurityDefaults -eq $true) { return [PSCustomObject]@{ State = "Enforced"; By = "Security Defaults" } }
    if (-not $UserId) { return [PSCustomObject]@{ State = "Unknown"; By = "User not found in the directory" } }

    $membership = $null
    if ($Context.NeedsMembership) { $membership = Get-LTIUserMembership -UserId $UserId }

    $full = @(); $partial = @()
    foreach ($p in @($Context.MfaPolicies)) {
        if (-not (Test-LTICAPolicyAppliesToUser -Info $p -UserId $UserId -Membership $membership)) { continue }
        $limits = @($p.Limits)
        if ($p.AppScope -eq 'Selected') { $limits = @("selected apps only") + $limits }
        if ($p.MfaOptional) { $limits += "or $($p.OtherControls -join ' / ') instead of MFA" }

        if ($limits.Count -eq 0) {
            $note = ""
            if ($p.AppScope -eq 'Office365') { $note = " (Office 365 apps)" }
            $full += "'$($p.Name)'$note"
        } elseif ($p.OnlyLocationExclusion -and -not $p.MfaOptional -and $p.AppScope -ne 'Selected') {
            $full += "'$($p.Name)' (except from trusted / excluded locations)"
        } else {
            $partial += "'$($p.Name)' ($($limits -join '; '))"
        }
    }
    # Legacy protocols cannot do MFA at all; say whether a policy blocks them for this user.
    $legacyBy = @($Context.LegacyBlockPolicies | Where-Object { $_ -and (Test-LTICAPolicyAppliesToUser -Info $_ -UserId $UserId -Membership $membership) } | ForEach-Object { "'$($_.Name)'" })
    $legacyNote = "; legacy protocols: no Conditional Access policy blocks them for this user"
    if ($legacyBy.Count -gt 0) { $legacyNote = "; legacy protocols blocked by $($legacyBy -join ', ')" }

    if ($full.Count -gt 0) { return [PSCustomObject]@{ State = "Enforced"; By = "Conditional Access: $($full -join ', ')$legacyNote" } }

    $perUser = Get-LTIPerUserMfaState -UserId $UserId
    if ($perUser -eq 'enforced' -or $perUser -eq 'enabled') { return [PSCustomObject]@{ State = "Enforced"; By = "Per-user MFA ($perUser)$legacyNote" } }

    if ($partial.Count -gt 0) { return [PSCustomObject]@{ State = "Partial"; By = "Conditional Access, limited: $($partial -join ', ')$legacyNote" } }

    # Nothing found that enforces MFA. Only call that "not enforced" when every
    # place it could be enforced from was actually readable.
    if ($Context.CAError -or $null -eq $Context.SecurityDefaults) {
        $unread = @()
        if ($null -eq $Context.SecurityDefaults) { $unread += "Security Defaults" }
        if ($Context.CAError) { $unread += "Conditional Access" }
        return [PSCustomObject]@{ State = "Unknown"; By = "$($unread -join ' and ') could not be read, so enforcement cannot be confirmed either way" }
    }
    $why = "Security Defaults off; no Conditional Access policy requiring MFA applies to this user"
    if ($Context.NeedsMembership -and $membership -and -not $membership.Known) { return [PSCustomObject]@{ State = "Unknown"; By = "Group membership could not be read, so group-targeted Conditional Access policies could not be evaluated" } }
    if ($perUser -eq 'disabled') { $why += "; per-user MFA off" } else { $why += "; per-user MFA state unknown" }
    return [PSCustomObject]@{ State = "NotEnforced"; By = $why }
}

# -----------------------------------------------------------------------------
#  REV 3.0 - STEP 19: APP CONSENTS AND SERVICE PRINCIPALS
#  A consented mail app keeps reading the mailbox after the password is reset
#  and MFA is added. This lists what each user has consented to, what the whole
#  tenant has consented to, and every app-related change inside the window.
# -----------------------------------------------------------------------------
function Get-LTIScopeRisk {
    # Splits a scope string into the permissions that expose mail / files /
    # directory data. Returns the risky ones (array, possibly empty).
    param([string]$Scope)

    $risky = '^(Mail\.|MailboxSettings\.ReadWrite|EWS\.|EAS\.|IMAP\.|POP\.|SMTP\.|full_access_as_user|Files\.(Read|ReadWrite)\.All|Sites\.(Read|ReadWrite|FullControl)\.All|Contacts\.|User\.ReadWrite\.All|Directory\.ReadWrite\.All|Directory\.AccessAsUser\.All|RoleManagement\.ReadWrite|full_access_as_app|Exchange\.ManageAsApp|Application\.ReadWrite\.|AppRoleAssignment\.ReadWrite)'
    return @(([string]$Scope) -split '\s+' | Where-Object { $_ -and ($_ -match $risky) })
}

function Test-LTIKnownAbusedApp {
    # Third-party apps repeatedly seen in mailbox-compromise cases. A match is a
    # prompt to check whether the user really installed it, not proof of abuse.
    param([string]$Name, [string]$AppId)

    foreach ($entry in $script:LTIKnownAbusedApps) {
        if ($Name -and ($Name -match $entry.Pattern)) { return $entry.Label }
        if ($AppId -and $entry.AppId -and ($AppId -eq $entry.AppId)) { return $entry.Label }
    }
    return ""
}

function Get-LTIAppContext {
    # Tenant-level, once per run.
    #   AuditRows - app-related audit events in the window (needs only AuditLog.Read.All)
    #   Grants    - current delegated permission grants (needs Directory.Read.All)
    param([Parameter(Mandatory = $true)][DateTime]$Start)

    $ctx = @{
        AuditChecked = $false; AuditError = ""; GrantsChecked = $false; GrantsReason = ""; AppOnlyChecked = $false; AppOnlyError = ""; OwnerByAppId = @{}
        AuditRows = [System.Collections.Generic.List[object]]::new()
        Grants    = [System.Collections.Generic.List[object]]::new()
    }

    # ---- audit events ----
    try {
        $from = $Start.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $uri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=' + [Uri]::EscapeDataString("category eq 'ApplicationManagement' and activityDateTime ge $from")
        foreach ($ev in (Get-LTIGraphPaged -Uri $uri)) {
            $activity = [string]$ev.activityDisplayName
            if ($activity -notmatch '(consent|permission grant|app role assignment|service principal|Add application|credential|owner to)') { continue }

            $actor = ""; $actorId = ""; $ip = ""
            if ($ev.initiatedBy -and $ev.initiatedBy.user) {
                $actor = [string]$ev.initiatedBy.user.userPrincipalName; $actorId = [string]$ev.initiatedBy.user.id; $ip = [string]$ev.initiatedBy.user.ipAddress
            }
            if (-not $actor -and $ev.initiatedBy -and $ev.initiatedBy.app) { $actor = "App: " + [string]$ev.initiatedBy.app.displayName }

            $app = ""; $targetUser = ""; $targetUserId = ""; $detail = [System.Collections.Generic.List[string]]::new()
            foreach ($t in @($ev.targetResources)) {
                if ($null -eq $t) { continue }
                if ([string]$t.type -eq 'User') { $targetUser = [string]$t.userPrincipalName; $targetUserId = [string]$t.id }
                elseif (-not $app -and $t.displayName) { $app = [string]$t.displayName }
                foreach ($mp in @($t.modifiedProperties)) {
                    if ($null -eq $mp) { continue }
                    if ([string]$mp.displayName -match '(Permissions|Scope|IsAdminConsent|AppRole\.Value|ConsentType|KeyDescription)') {
                        $val = ([string]$mp.newValue).Trim('"')
                        if ($val.Length -gt 300) { $val = $val.Substring(0, 300) + "..." }
                        if ($val) { $detail.Add("$($mp.displayName)=$val") }
                    }
                }
            }

            $ctx.AuditRows.Add([PSCustomObject]@{
                Timestamp = Format-LTIDateTime -Value $ev.activityDateTime; Activity = $activity; App = $app
                InitiatedBy = $actor; InitiatedById = $actorId; InitiatedByIP = $ip
                TargetUser = $targetUser; TargetUserId = $targetUserId
                Detail = ($detail -join '; '); Result = [string]$ev.result
            })
        }
        $ctx.AuditChecked = $true
        Add-Log "  [OK] App audit events in the window: $($ctx.AuditRows.Count)"
    } catch {
        $ctx.AuditError = [string]$_.Exception.Message
        Add-Log "  [WARN] App audit events unavailable: $($ctx.AuditError)"
    }

    # ---- current grants ----
    if (-not (Test-LTIGraphScope -Name 'Directory.Read.All')) {
        $ctx.GrantsReason = "Not checked - needs the extended Graph permissions (tick 'Extended Graph checks', then Refresh MFA)"
        Add-Log "  [INFO] Current app consents not checked: the sign-in does not include Directory.Read.All."
        return $ctx
    }
    try {
        $spById = @{}
        foreach ($sp in (Get-LTIGraphPaged -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$top=999')) {
            if ($sp.id) { $spById[[string]$sp.id] = $sp }
        }
        $userById = @{}
        if ($script:MFAContext -and $script:MFAContext.DirectoryByUpn) {
            foreach ($k in @($script:MFAContext.DirectoryByUpn.Keys)) { $d = $script:MFAContext.DirectoryByUpn[$k]; if ($d.id) { $userById[[string]$d.id] = [string]$d.userPrincipalName } }
        }
        # Microsoft's own tenants - apps they own are first-party.
        $microsoftTenants = @($script:LTIMicrosoftTenants)
        foreach ($spx in @($spById.Values)) { if ($spx.appId) { $ctx.OwnerByAppId[[string]$spx.appId] = [string]$spx.appOwnerOrganizationId } }

        foreach ($gr in (Get-LTIGraphPaged -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants')) {
            $sp = $spById[[string]$gr.clientId]
            $name = ""; $appId = ""; $owner = ""; $publisher = ""; $verified = ""
            if ($sp) {
                $name = [string]$sp.displayName; $appId = [string]$sp.appId; $owner = [string]$sp.appOwnerOrganizationId
                $publisher = [string]$sp.publisherName
                if ($sp.verifiedPublisher -and $sp.verifiedPublisher.displayName) { $verified = [string]$sp.verifiedPublisher.displayName }
            }
            $resource = $spById[[string]$gr.resourceId]
            $risky = Get-LTIScopeRisk -Scope ([string]$gr.scope)
            $principal = ""
            if ($gr.principalId) { $principal = $userById[[string]$gr.principalId]; if (-not $principal) { $principal = [string]$gr.principalId } }

            $ctx.Grants.Add([PSCustomObject]@{
                App = $name; AppId = $appId; Publisher = $publisher; VerifiedPublisher = $verified
                Microsoft = ($microsoftTenants -contains $owner)
                ConsentType = [string]$gr.consentType; Principal = $principal; PrincipalId = [string]$gr.principalId
                Resource = $(if ($resource) { [string]$resource.displayName } else { "" })
                Scopes = ([string]$gr.scope).Trim(); RiskyScopes = ($risky -join ' ')
                KnownAbused = (Test-LTIKnownAbusedApp -Name $name -AppId $appId)
                KnownMailClient = $(if ($appId -and $script:LTIKnownMailApps.ContainsKey($appId)) { $script:LTIKnownMailApps[$appId] } else { "" })
            })
        }
        $ctx.GrantsChecked = $true
        $delegated = $ctx.Grants.Count

        # Application (app-only) permissions on Microsoft Graph and Exchange Online.
        # These reach EVERY mailbox with no user signed in, and survive any
        # password reset - the strongest persistence an attacker with admin can leave.
        try {
            $resourceAppIds = @('00000003-0000-0000-c000-000000000000', '00000002-0000-0ff1-ce00-000000000000')
            foreach ($res in @($spById.Values | Where-Object { $resourceAppIds -contains [string]$_.appId })) {
                $roleName = @{}
                foreach ($ar in @($res.appRoles)) { if ($ar -and $ar.id) { $roleName[[string]$ar.id] = [string]$ar.value } }
                $byClient = @{}
                foreach ($as in (Get-LTIGraphPaged -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($res.id)/appRoleAssignedTo")) {
                    if ($null -eq $as -or [string]$as.principalType -ne 'ServicePrincipal') { continue }
                    $cid = [string]$as.principalId
                    if (-not $byClient.ContainsKey($cid)) { $byClient[$cid] = [System.Collections.Generic.List[string]]::new() }
                    $role = $roleName[[string]$as.appRoleId]; if (-not $role) { $role = [string]$as.appRoleId }
                    $byClient[$cid].Add($role)
                }
                foreach ($cid in @($byClient.Keys)) {
                    $sp = $spById[$cid]
                    $name = ""; $appId = ""; $owner = ""; $publisher = ""; $verified = ""
                    if ($sp) {
                        $name = [string]$sp.displayName; $appId = [string]$sp.appId; $owner = [string]$sp.appOwnerOrganizationId; $publisher = [string]$sp.publisherName
                        if ($sp.verifiedPublisher -and $sp.verifiedPublisher.displayName) { $verified = [string]$sp.verifiedPublisher.displayName }
                    }
                    $scopes = (@($byClient[$cid] | Sort-Object -Unique) -join ' ')
                    $ctx.Grants.Add([PSCustomObject]@{
                        App = $name; AppId = $appId; Publisher = $publisher; VerifiedPublisher = $verified
                        Microsoft = ($microsoftTenants -contains $owner)
                        ConsentType = 'Application'; Principal = '(app-only: whole tenant, no user needed)'; PrincipalId = ''
                        Resource = [string]$res.displayName
                        Scopes = $scopes; RiskyScopes = ((Get-LTIScopeRisk -Scope $scopes) -join ' ')
                        KnownAbused = (Test-LTIKnownAbusedApp -Name $name -AppId $appId)
                        KnownMailClient = ""
                    })
                }
            }
            $ctx.AppOnlyChecked = $true
        } catch {
            $ctx.AppOnlyError = [string]$_.Exception.Message
            Add-Log "  [WARN] Application (app-only) permissions could not be read: $($ctx.AppOnlyError)"
        }

        $thirdPartyMail = @($ctx.Grants | Where-Object { -not $_.Microsoft -and $_.RiskyScopes }).Count
        $appOnlyMail = @($ctx.Grants | Where-Object { -not $_.Microsoft -and $_.RiskyScopes -and $_.ConsentType -eq 'Application' })
        Add-Log "  [OK] App permissions: $delegated delegated grant(s), $($ctx.Grants.Count - $delegated) app with app-only permissions ($thirdPartyMail non-Microsoft with mail / file / directory access)"
        if ($appOnlyMail.Count -gt 0) { Add-Log "  [WARN] *** NON-MICROSOFT APP(S) CAN READ MAIL OR FILES TENANT-WIDE WITHOUT A USER: $(@($appOnlyMail | ForEach-Object { "$($_.App) [$($_.RiskyScopes)]" }) -join '; ') ***" }
        $abused = @($ctx.Grants | Where-Object { $_.KnownAbused })
        if ($abused.Count -gt 0) { Add-Log "  [WARN] *** App(s) often seen in mailbox compromises have consent in this tenant: $(@($abused | ForEach-Object { $_.App } | Select-Object -Unique) -join ', ') ***" }
    } catch {
        $ctx.GrantsReason = "Could not be read: $($_.Exception.Message)"
        Add-Log "  [WARN] Current app consents unavailable: $($_.Exception.Message)"
    }
    return $ctx
}

function Get-LTIAppFindingsForUser {
    # Rows for 19_App_Consents.csv plus the numbers the summary needs.
    param([string]$UPN, [string]$UserId, $Context)

    $rows = [System.Collections.Generic.List[object]]::new()
    $risky = [System.Collections.Generic.List[string]]::new()
    $abused = [System.Collections.Generic.List[string]]::new()
    $mailApps = [System.Collections.Generic.List[string]]::new()
    $grantCount = 0; $eventCount = 0
    if (-not $Context) { return [PSCustomObject]@{ Rows = $rows; Grants = 0; Events = 0; Risky = ""; Abused = ""; MailApps = ""; Status = "Not run" } }

    foreach ($g in @($Context.Grants)) {
        if ($g.ConsentType -ne 'Principal' -or -not $UserId -or $g.PrincipalId -ne $UserId) { continue }
        $grantCount++
        $rows.Add([PSCustomObject]@{ Kind = "Current consent (this user)"; Timestamp = ""; App = $g.App; AppId = $g.AppId; Publisher = $(if ($g.VerifiedPublisher) { "$($g.VerifiedPublisher) (verified)" } else { $g.Publisher }); Microsoft = $g.Microsoft; Scopes = $g.Scopes; RiskyScopes = $g.RiskyScopes; KnownAbused = $g.KnownAbused; Activity = ""; InitiatedBy = ""; IP = ""; Detail = "" })
        # A well-known mail app holding mailbox access is doing its job; it is listed, not scored.
        if (-not $g.Microsoft -and $g.RiskyScopes) {
            if ($g.KnownMailClient -and -not $g.KnownAbused) { $mailApps.Add("$($g.App) ($($g.KnownMailClient))") }
            else { $risky.Add("$($g.App) [$($g.RiskyScopes)]") }
        }
        if ($g.KnownAbused) { $abused.Add($g.App) }
    }
    foreach ($e in @($Context.AuditRows)) {
        $mine = ($e.InitiatedBy -and ($e.InitiatedBy -eq $UPN)) -or ($UserId -and ($e.InitiatedById -eq $UserId -or $e.TargetUserId -eq $UserId)) -or ($e.TargetUser -and ($e.TargetUser -eq $UPN))
        if (-not $mine) { continue }
        $eventCount++
        $known = Test-LTIKnownAbusedApp -Name $e.App -AppId ""
        if ($known) { $abused.Add($e.App) }
        $rows.Add([PSCustomObject]@{ Kind = "Change in the window"; Timestamp = $e.Timestamp; App = $e.App; AppId = ""; Publisher = ""; Microsoft = ""; Scopes = ""; RiskyScopes = ""; KnownAbused = $known; Activity = $e.Activity; InitiatedBy = $e.InitiatedBy; IP = $e.InitiatedByIP; Detail = $e.Detail })
    }

    $status = "OK"
    if (-not $Context.GrantsChecked) { $status = "Audit events only - current consents: $($Context.GrantsReason)" }
    if (-not $Context.AuditChecked) { $status = "Current consents only - audit events: $($Context.AuditError)" }
    if (-not $Context.GrantsChecked -and -not $Context.AuditChecked) { $status = "Unavailable" }

    return [PSCustomObject]@{
        Rows = $rows; Grants = $grantCount; Events = $eventCount
        Risky = (@($risky | Select-Object -Unique) -join '; ')
        Abused = (@($abused | Select-Object -Unique) -join ', ')
        MailApps = (@($mailApps | Select-Object -Unique) -join '; ')
        Status = $status
    }
}

# -----------------------------------------------------------------------------
#  REV 3.0 - INBOX RULES, FORWARDING AND LOOK-ALIKE DOMAINS
# -----------------------------------------------------------------------------
function Get-LTIEmailFromText {
    # '"Bob" [SMTP:bob@x.com]', 'smtp:bob@x.com', 'bob@x.com' -> 'bob@x.com'.
    # '"Someone" [EX:/o=ExchangeLabs/...]' (an internal recipient) -> ''.
    param([string]$Text)

    if ($Text -match '(?i)smtp:([^\]\s;]+)') { return $Matches[1].ToLowerInvariant() }
    if ($Text -match '([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})') { return $Matches[1].ToLowerInvariant() }
    return ""
}

function Get-LTIDomainOf {
    param([string]$Address)
    if ($Address -match '@([^@\s>]+)$') { return $Matches[1].ToLowerInvariant().TrimEnd('.') }
    return ""
}

function Test-LTIExternalDomain {
    # "True" / "False" against the tenant's accepted domains; "Unknown" when
    # they could not be read.
    param([string]$Domain)
    if (-not $Domain) { return "Unknown" }
    if (@($script:LTIAcceptedDomains).Count -eq 0) { return "Unknown" }
    if (@($script:LTIAcceptedDomains) -contains $Domain) { return "False" }
    return "True"
}

function Get-LTIEditDistance {
    # Levenshtein distance. Domains are short, so the plain two-row form is fine.
    param([string]$A, [string]$B)

    if ($A -eq $B) { return 0 }
    if (-not $A) { return $B.Length }
    if (-not $B) { return $A.Length }
    $prev = New-Object 'int[]' ($B.Length + 1)
    $cur  = New-Object 'int[]' ($B.Length + 1)
    for ($j = 0; $j -le $B.Length; $j++) { $prev[$j] = $j }
    for ($i = 1; $i -le $A.Length; $i++) {
        $cur[0] = $i
        for ($j = 1; $j -le $B.Length; $j++) {
            $cost = 1
            if ($A[$i - 1] -eq $B[$j - 1]) { $cost = 0 }
            $cur[$j] = [Math]::Min([Math]::Min($prev[$j] + 1, $cur[$j - 1] + 1), $prev[$j - 1] + $cost)
        }
        $swap = $prev; $prev = $cur; $cur = $swap
    }
    return $prev[$B.Length]
}

function Test-LTILookAlike {
    # $true when two different domains are close enough to be mistaken for each
    # other: one or two edits apart, or identical after the usual character
    # swaps (rn -> m, vv -> w, 0 -> o, 1 -> l, dropped hyphen).
    param([string]$A, [string]$B)

    if (-not $A -or -not $B -or $A -eq $B) { return $false }
    # Same name on a different ending: contoso.com / contoso.net
    $ia = $A.LastIndexOf('.'); $ib = $B.LastIndexOf('.')
    if ($ia -gt 2 -and $ib -gt 2 -and $A.Substring(0, $ia) -eq $B.Substring(0, $ib)) { return $true }
    $norm = { param($d) ($d -replace 'rn', 'm' -replace 'vv', 'w' -replace '0', 'o' -replace '1', 'l' -replace '-', '') }
    if ((& $norm $A) -eq (& $norm $B)) { return $true }
    $shortest = [Math]::Min($A.Length, $B.Length)
    if ($shortest -lt 6) { return $false }
    $limit = 1
    if ($shortest -ge 12) { $limit = 2 }
    return ((Get-LTIEditDistance -A $A -B $B) -le $limit)
}

function Get-LTIRuleReview {
    # Looks at one inbox rule the way an investigator would. Returns:
    #   Flags      - why the rule deserves a look (empty = ordinary rule)
    #   Targets    - every address it forwards or redirects to
    #   Suspicious - $true when at least one flag is set
    param($Rule, [bool]$Hidden)

    $flags = [System.Collections.Generic.List[string]]::new()
    $targets = [System.Collections.Generic.List[object]]::new()

    foreach ($pair in @(@('ForwardTo', 'forwards to'), @('ForwardAsAttachmentTo', 'forwards (as attachment) to'), @('RedirectTo', 'redirects to'))) {
        foreach ($entry in @($Rule.($pair[0]) | Where-Object { $_ })) {
            $raw = [string]$entry
            $addr = Get-LTIEmailFromText -Text $raw
            $where = "internal recipient"
            if ($addr) {
                $ext = Test-LTIExternalDomain -Domain (Get-LTIDomainOf -Address $addr)
                $where = $addr
                if ($ext -eq "True") { $where = "$addr (EXTERNAL)" }
            }
            $flags.Add("$($pair[1]) $where")
            $targets.Add([PSCustomObject]@{ Kind = $pair[0]; Raw = $raw; Address = $addr })
        }
    }

    $words = @()
    foreach ($prop in @('SubjectContainsWords', 'BodyContainsWords', 'SubjectOrBodyContainsWords', 'FromAddressContainsWords', 'HeaderContainsWords')) {
        $words += @($Rule.$prop | Where-Object { $_ } | ForEach-Object { [string]$_ })
    }
    $sensitive = @($words | Where-Object { $_ -match '(?i)(invoice|payment|wire|bank|ach\b|remit|payroll|deposit|password|security|phish|hack|spam|virus|fraud|helpdesk|docusign|zelle|paypal|w-?2|w-?9|mfa|verif)' } | Select-Object -Unique)
    $name = [string]$Rule.Name
    $evasive = ($name -match '^[\W_]{1,4}$' -or ($name.Trim().Length -le 2 -and $name.Trim().Length -gt 0))

    $hides = $false; $softFolder = ""
    if ($Rule.DeleteMessage -eq $true) { $flags.Add("deletes matching mail"); $hides = $true }
    foreach ($prop in @('MoveToFolder', 'CopyToFolder')) {
        $folder = [string]$Rule.$prop
        if (-not $folder) { continue }
        if ($folder -match '(?i)(RSS|Conversation History|Notes|Sync Issues|Journal)') {
            # Folders nobody files mail into by hand - the usual hiding places.
            $verb = "moves"
            if ($prop -eq 'CopyToFolder') { $verb = "copies" }
            $flags.Add("$verb mail to '$folder'")
            if ($prop -eq 'MoveToFolder') { $hides = $true }
        } elseif ($prop -eq 'MoveToFolder' -and $folder -match '(?i)(Archive|Junk|Deleted Items|Clutter)') {
            $softFolder = $folder
        }
    }
    # Filing into Archive / Junk / Deleted Items is ordinary on its own; it is a
    # hiding rule when it also marks the mail read, targets sensitive words or
    # has a throwaway name.
    if ($softFolder -and ($Rule.MarkAsRead -eq $true -or $sensitive.Count -gt 0 -or $evasive)) { $flags.Add("moves mail to '$softFolder'"); $hides = $true }
    if ($Rule.MarkAsRead -eq $true -and ($hides -or $targets.Count -gt 0)) { $flags.Add("marks it as read") }
    if ($sensitive.Count -gt 0 -and ($hides -or $targets.Count -gt 0)) { $flags.Add("acts on mail mentioning: $($sensitive -join ', ')") }
    if ($evasive -and ($hides -or $targets.Count -gt 0 -or $Hidden)) { $flags.Add("throwaway rule name '$name'") }
    if ($Hidden) { $flags.Add("HIDDEN rule (not shown in Outlook)") }
    if ($flags.Count -gt 0 -and $Rule.Enabled -eq $false) { $flags.Add("currently disabled") }

    return [PSCustomObject]@{ Flags = @($flags); Targets = @($targets); Suspicious = ($flags.Count -gt 0) }
}

function Add-LTIForwardingRow {
    # One row of the tenant forwarding review.
    param([string]$UPN, [string]$Source, [string]$Raw, [string]$Address, [string]$Note)

    $domain = Get-LTIDomainOf -Address $Address
    $script:allForwarding.Add([PSCustomObject]@{
        UPN = $UPN; Source = $Source; Target = $Raw; TargetAddress = $Address; TargetDomain = $domain
        External = $(if ($Address) { Test-LTIExternalDomain -Domain $domain } elseif ($Note -match 'could not be resolved') { "Unknown" } else { "False" })
        LookAlikeOf = ""; SignInBlocked = ""; Selected = ""; Note = $Note
    })
}

function Add-LTIMailboxForwardingRows {
    # Mailbox-level forwarding (both kinds) for one mailbox -> forwarding review rows.
    # Returns how many rows it added.
    param($Mailbox, [string]$UPN)

    $mb = $Mailbox; $upn = $UPN; $count = 0
    if (-not $upn) { $upn = [string]$mb.UserPrincipalName }
    if ($mb.ForwardingSmtpAddress) {
        $raw = [string]$mb.ForwardingSmtpAddress
        Add-LTIForwardingRow -UPN $upn -Source "Mailbox forwarding (SMTP address)" -Raw $raw -Address (Get-LTIEmailFromText -Text $raw) -Note $(if ($mb.DeliverToMailboxAndForward -eq $true) { "keeps a copy in the mailbox" } else { "does NOT keep a copy in the mailbox" })
        $count++
    }
    if ($mb.ForwardingAddress) {
        $raw = [string]$mb.ForwardingAddress
        $addr = ""; $note = "internal recipient"
        try {
            $rcp = Get-Recipient -Identity $raw -ErrorAction Stop | Select-Object -First 1
            if ($rcp) {
                $addr = Get-LTIEmailFromText -Text ([string]$rcp.ExternalEmailAddress)
                if (-not $addr) { $addr = ([string]$rcp.PrimarySmtpAddress).ToLowerInvariant() }
                $note = "recipient type: $($rcp.RecipientTypeDetails)"
            }
        } catch { $note = "recipient could not be resolved" }
        Add-LTIForwardingRow -UPN $upn -Source "Mailbox forwarding (recipient)" -Raw $raw -Address $addr -Note $note
        $count++
    }
    return $count
}

function Get-LTITenantForwardingInventory {
    # Mailbox-level forwarding for EVERY loaded mailbox (not just the selected
    # ones) and every transport rule that redirects or copies mail. The wider
    # picture is what lets a one-letter-off target stand out.
    $count = 0
    foreach ($mb in @($script:allMailboxes)) {
        if ($null -eq $mb) { continue }
        $count += [int](Add-LTIMailboxForwardingRows -Mailbox $mb -UPN ([string]$mb.UserPrincipalName))
    }

    try {
        foreach ($tr in @(Get-TransportRule -ErrorAction Stop)) {
            foreach ($prop in @('RedirectMessageTo', 'BlindCopyTo', 'CopyTo', 'AddToRecipients')) {
                foreach ($entry in @($tr.$prop | Where-Object { $_ })) {
                    $raw = [string]$entry
                    Add-LTIForwardingRow -UPN "(tenant transport rule)" -Source "Transport rule '$($tr.Name)' - $prop" -Raw $raw -Address (Get-LTIEmailFromText -Text $raw) -Note "state: $($tr.State)"
                    $count++
                }
            }
        }
    } catch { Add-Log "  [WARN] Transport rules could not be read for the forwarding review: $_" }
    return $count
}

function Complete-LTIForwardingReview {
    # Runs after every mailbox: marks look-alike targets and copies the result
    # onto each selected mailbox's findings.
    param($Findings)

    if ($script:allForwarding.Count -eq 0) { return }

    $authoritative = @(@($script:LTIAcceptedDomains) + @($script:LTIOperatorDomains) | Where-Object { $_ } | Select-Object -Unique)
    # Big public mail providers: never the look-alike themselves (gmail.com and
    # ymail.com are one letter apart), but a target one letter off one of them is.
    $public = @('gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'icloud.com', 'me.com', 'mac.com', 'aol.com', 'comcast.net', 'att.net', 'verizon.net', 'sbcglobal.net', 'bellsouth.net', 'charter.net', 'cox.net', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com')
    $targetCount = @{}
    foreach ($row in $script:allForwarding) { if ($row.TargetDomain) { $targetCount[$row.TargetDomain] = 1 + [int]$targetCount[$row.TargetDomain] } }

    $blocked = @{}; $selected = @{}
    foreach ($m in @($script:allMFAData)) { if ($m.AccountEnabled -eq "False") { $blocked[([string]$m.UPN).ToLowerInvariant()] = $true } }
    foreach ($f in @($Findings)) { if ($f) { $selected[([string]$f.UPN).ToLowerInvariant()] = $true } }

    foreach ($row in $script:allForwarding) {
        $key = ([string]$row.UPN).ToLowerInvariant()
        $row.SignInBlocked = $(if ($blocked.ContainsKey($key)) { "True" } else { "" })
        $row.Selected = $(if ($selected.ContainsKey($key)) { "True" } else { "" })
        $d = $row.TargetDomain
        if (-not $d -or ($authoritative -contains $d) -or ($public -contains $d)) { continue }

        foreach ($ref in @($authoritative + $public)) { if (Test-LTILookAlike -A $d -B $ref) { $row.LookAlikeOf = $ref; break } }
        if (-not $row.LookAlikeOf) {
            # Against the other forwarding targets: the rarer of two near-identical domains is the suspect.
            foreach ($other in @($targetCount.Keys)) {
                if ($other -eq $d -or ($authoritative -contains $other)) { continue }
                if ((Test-LTILookAlike -A $d -B $other) -and ([int]$targetCount[$d] -le [int]$targetCount[$other])) { $row.LookAlikeOf = $other; break }
            }
        }
    }

    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $mine = @($script:allForwarding | Where-Object { $_.UPN -eq $f.UPN })
        if ($mine.Count -eq 0) { continue }
        $ext  = @($mine | Where-Object { $_.External -eq "True" })
        $look = @($mine | Where-Object { $_.LookAlikeOf })
        $f.ForwardingExternal  = (@($ext | ForEach-Object { $_.TargetAddress } | Select-Object -Unique) -join '; ')
        $f.ForwardingLookAlike = (@($look | ForEach-Object { "$($_.TargetAddress) looks like $($_.LookAlikeOf)" } | Select-Object -Unique) -join '; ')
        $mbxLevel = @($mine | Where-Object { $_.Source -like 'Mailbox forwarding*' })
        $f.MailboxForwardExternal = (@($mbxLevel | Where-Object { $_.External -eq "True" } | ForEach-Object { $_.TargetAddress } | Select-Object -Unique) -join '; ')
        $f.ForwardingUnclassified = (@($mbxLevel | Where-Object { $_.External -eq "Unknown" } | ForEach-Object { $(if ($_.TargetAddress) { $_.TargetAddress } else { $_.Target }) } | Select-Object -Unique) -join '; ')
        $f.ForwardingAll       = (@($mine | ForEach-Object { "$($_.Source): $(if ($_.TargetAddress) { $_.TargetAddress } else { $_.Target })" } | Select-Object -Unique) -join ' | ')
    }
}

# -----------------------------------------------------------------------------
#  REV 3.0 - OUTBOUND MAIL PROFILE
# -----------------------------------------------------------------------------
function Get-LTIOutboundProfile {
    # Message-trace rows (one per message + recipient) -> totals, an hour-by-hour
    # table and a burst verdict. A compromised mailbox used for phishing sends to
    # many recipients in a short time; a busy user is spread across the window.
    param($Rows)

    $rows = @($Rows | Where-Object { $_ })
    $result = [PSCustomObject]@{ Text = ""; Burst = $false; BurstReason = ""; Hours = @(); Messages = 0; Recipients = 0; External = 0 }
    if ($rows.Count -eq 0) { return $result }

    $hours = @{}; $allMsg = @{}; $allRcpt = @{}; $allExt = @{}; $perMessage = @{}
    foreach ($r in $rows) {
        $rcpt = ([string]$r.RecipientAddress).ToLowerInvariant()
        $msg = [string]$r.MessageId
        if (-not $msg) { $msg = "subject:" + [string]$r.Subject }
        $isExt = ((Test-LTIExternalDomain -Domain (Get-LTIDomainOf -Address $rcpt)) -eq "True")
        $allMsg[$msg] = $true; $allRcpt[$rcpt] = $true
        if ($isExt) { $allExt[$rcpt] = $true }
        if (-not $perMessage.ContainsKey($msg)) { $perMessage[$msg] = @{ Rcpt = @{}; Subject = [string]$r.Subject } }
        $perMessage[$msg].Rcpt[$rcpt] = $true

        $t = ConvertTo-LTIUtcDateTime -Value $r.Received
        if ($null -eq $t) { continue }
        $key = $t.ToString("yyyy-MM-dd HH':00 UTC'")
        if (-not $hours.ContainsKey($key)) { $hours[$key] = @{ Msg = @{}; Rcpt = @{}; Ext = @{}; Subj = @{} } }
        $h = $hours[$key]
        $h.Msg[$msg] = $true; $h.Rcpt[$rcpt] = $true
        if ($isExt) { $h.Ext[$rcpt] = $true }
        $s = [string]$r.Subject
        $h.Subj[$s] = 1 + [int]$h.Subj[$s]
    }

    $hourRows = @($hours.Keys | Sort-Object | ForEach-Object {
        $h = $hours[$_]
        $top = @($h.Subj.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1)
        [PSCustomObject]@{ HourUTC = $_; Messages = $h.Msg.Count; Recipients = $h.Rcpt.Count; ExternalRecipients = $h.Ext.Count; TopSubject = $(if ($top.Count) { [string]$top[0].Key } else { "" }) }
    })

    $result.Hours = $hourRows
    $result.Messages = $allMsg.Count; $result.Recipients = $allRcpt.Count; $result.External = $allExt.Count
    $text = "$($allMsg.Count) message(s) to $($allRcpt.Count) recipient(s), $($allExt.Count) external"

    if ($hourRows.Count -gt 0) {
        $peak = $hourRows | Sort-Object -Property Recipients, Messages -Descending | Select-Object -First 1
        # What is normal for this mailbox: the median of its OTHER active hours.
        $sorted = @($hourRows | Where-Object { $_.HourUTC -ne $peak.HourUTC } | ForEach-Object { $_.Recipients } | Sort-Object)
        $median = 0
        if ($sorted.Count -gt 0) { $median = $sorted[[int][Math]::Floor(($sorted.Count - 1) / 2)] }
        $text += "; busiest hour $($peak.HourUTC): $($peak.Messages) message(s) to $($peak.Recipients) recipient(s)"
        if ($peak.Recipients -ge 30 -and $peak.Recipients -ge (4 * [Math]::Max($median, 1))) {
            $result.Burst = $true
            $typical = "against a typical $median per hour in its other $($sorted.Count) active hour(s)"
            if ($sorted.Count -eq 0) { $typical = "the only hour with outbound mail in the window" }
            $result.BurstReason = "$($peak.Recipients) recipients in one hour ($($peak.HourUTC)), $typical"
        }
    }
    $widest = $null; $widestCount = 0
    foreach ($m in @($perMessage.Keys)) { $c = $perMessage[$m].Rcpt.Count; if ($c -gt $widestCount) { $widestCount = $c; $widest = $perMessage[$m] } }
    if ($widestCount -ge 25) {
        $result.Burst = $true
        $extra = "one message sent to $widestCount recipients (subject: '$($widest.Subject)')"
        $result.BurstReason = $(if ($result.BurstReason) { "$($result.BurstReason); $extra" } else { $extra })
    }
    $result.Text = $text
    return $result
}

# -----------------------------------------------------------------------------
#  REV 3.0 - SIGN-IN INDICATORS (session theft, scripted clients, legacy protocols)
# -----------------------------------------------------------------------------
function Get-LTIDistanceKm {
    param([double]$Lat1, [double]$Lon1, [double]$Lat2, [double]$Lon2)
    $toRad = [Math]::PI / 180
    $dLat = ($Lat2 - $Lat1) * $toRad; $dLon = ($Lon2 - $Lon1) * $toRad
    $a = [Math]::Pow([Math]::Sin($dLat / 2), 2) + [Math]::Cos($Lat1 * $toRad) * [Math]::Cos($Lat2 * $toRad) * [Math]::Pow([Math]::Sin($dLon / 2), 2)
    return (6371 * 2 * [Math]::Atan2([Math]::Sqrt($a), [Math]::Sqrt(1 - $a)))
}

function Test-LTIMicrosoftApp {
    # Is the app behind this sign-in one of Microsoft's own? Decided by who owns
    # the app or by its app ID - never by its display name.
    param($Row)

    if (-not $Row) { return $false }
    # App IDs are globally unique, so a known Microsoft app ID settles it.
    $appId = [string]$Row.AppId
    if ($appId -and $script:LTIMicrosoftScriptedApps.ContainsKey($appId)) { return $true }
    $owner = [string]$Row.AppOwnerTenant
    if ($owner) { return (@($script:LTIMicrosoftTenants) -contains $owner) }
    if (-not $appId) { return $false }
    if ($script:LTIAppContext -and $script:LTIAppContext.OwnerByAppId -and $script:LTIAppContext.OwnerByAppId.ContainsKey($appId)) {
        return (@($script:LTIMicrosoftTenants) -contains [string]$script:LTIAppContext.OwnerByAppId[$appId])
    }
    return $false
}

function Get-LTIDeviceKey {
    # One value that identifies the device behind a sign-in row ("" when the
    # sign-in carried no device identity).
    param($Row)

    if ($Row.DeviceId) { return "id:$($Row.DeviceId)" }
    if ($Row.DeviceName) { return "name:$($Row.DeviceName)" }
    return ""
}

function Get-LTISignInIndicators {
    # Reads the sign-in rows for one mailbox and reports the patterns that
    # usually mean a stolen session or a scripted attacker, each with a
    # severity (High / Medium / Low) and the evidence behind it.
    param($EntraRows, $AuditRows, [string]$UPN)

    $out = [System.Collections.Generic.List[object]]::new()
    $entra = @($EntraRows | Where-Object { $_ })
    # Appended to a finding when some of its sign-ins came from Microsoft's own network.
    $msNote = {
        param($rows)
        $ms = @($rows | Where-Object { $_ -and (Test-LTIMicrosoftNetwork -ASN ([string]$_.ASN) -ASName '') })
        if ($ms.Count -eq 0) { return "" }
        return " NOTE: $($ms.Count) of these sign-ins came from Microsoft's own network (AS$(@($ms | ForEach-Object { $_.ASN } | Select-Object -Unique) -join ', AS')). That is usually a Microsoft service acting for the user, but a server rented in Azure is on the same network - check the app and user agent before ruling it in or out."
    }
    $audit = @($AuditRows | Where-Object { $_ })
    $add = {
        param($severity, $name, $rows, $detail, $countOverride)
        $times = @($rows | ForEach-Object { ConvertTo-LTIUtcDateTime -Value $_.Timestamp } | Where-Object { $null -ne $_ } | Sort-Object)
        $first = ""; $last = ""
        if ($times.Count -gt 0) { $first = Format-LTIDateTime -Value $times[0]; $last = Format-LTIDateTime -Value $times[-1] }
        $ips = @($rows | ForEach-Object { if ($_.IP) { $_.IP } else { $_.ClientIP } } | Where-Object { $_ } | Select-Object -Unique)
        $n = @($rows).Count; if ($null -ne $countOverride) { $n = [int]$countOverride }
        $out.Add([PSCustomObject]@{ Severity = $severity; Indicator = $name; Count = $n; FirstSeen = $first; LastSeen = $last; IPs = (@($ips | Select-Object -First 8) -join '; '); Detail = $detail })
    }
    $scripted = '(?i)(python-requests|python-urllib|aiohttp|axios/|node-fetch|undici|Go-http-client|curl/|libwww-perl|fasthttp|BAV2ROPC|Wget/)'
    $legacy = @('IMAP', 'IMAP4', 'POP', 'POP3', 'SMTP', 'Authenticated SMTP', 'Other clients')

    $mobileOS = '(?i)^\s*(ios|ipados|android)'
    $script:LTIIndicatorNotes = @()

    $ok = @($entra | Where-Object { $_.Result -eq 'Success' })

    # 1. One session used from more than one country / network.
    foreach ($grp in @($ok | Where-Object { $_.SessionId } | Group-Object -Property SessionId)) {
        $countries = @($grp.Group | ForEach-Object { $_.Country } | Where-Object { $_ } | Select-Object -Unique)
        $asns = @($grp.Group | ForEach-Object { $_.ASN } | Where-Object { $_ } | Select-Object -Unique)
        if ($countries.Count -gt 1) {
            & $add 'High' 'Same session used from more than one country' $grp.Group "Session $($grp.Name): countries $($countries -join ', '); networks AS$($asns -join ', AS'). A session token is tied to one sign-in; seeing it from two countries is the signature of token theft.$(& $msNote $grp.Group)"
        } elseif ($asns.Count -gt 1) {
            # A phone or tablet does this all day (office Wi-Fi, mobile data, home), so
            # it is kept for the record but ranked Low.
            $withOS = @($grp.Group | Where-Object { $_.DeviceOS })
            if ($withOS.Count -gt 0 -and @($withOS | Where-Object { $_.DeviceOS -notmatch $mobileOS }).Count -eq 0) {
                & $add 'Low' 'Same session used from more than one network (phone or tablet)' $grp.Group "Session $($grp.Name) on $(@($withOS | ForEach-Object { $_.DeviceOS } | Select-Object -Unique) -join ', '): networks AS$($asns -join ', AS') in $($countries -join ', '). Normal for a mobile device moving between Wi-Fi and mobile data; worth a look only if a network is a hosting provider or one the user would never be on."
                continue
            }
            & $add 'Medium' 'Same session used from more than one network' $grp.Group "Session $($grp.Name): networks AS$($asns -join ', AS') in $($countries -join ', '). Often a phone moving between Wi-Fi and mobile data - check the networks are ones this user would use."
        }
    }

    # 2. Impossible travel between consecutive successful sign-ins.
    $timed = @($ok | ForEach-Object { [PSCustomObject]@{ Row = $_; T = (ConvertTo-LTIUtcDateTime -Value $_.Timestamp) } } | Where-Object { $null -ne $_.T -and $_.Row.IP } | Sort-Object -Property T)
    $travel = [System.Collections.Generic.List[object]]::new(); $travelText = [System.Collections.Generic.List[string]]::new(); $seenPairs = @{}; $travelPairs = 0; $travelAbroad = $false; $travelNonMobile = $false
    for ($i = 1; $i -lt $timed.Count; $i++) {
        $a = $timed[$i - 1]; $b = $timed[$i]
        if ($a.Row.IP -eq $b.Row.IP) { continue }
        $hoursApart = ($b.T - $a.T).TotalHours
        $pairKey = "$($a.Row.IP)>$($b.Row.IP)"
        if ($seenPairs.ContainsKey($pairKey)) { continue }
        $hit = $false; $why = ""
        if ($a.Row.Latitude -and $a.Row.Longitude -and $b.Row.Latitude -and $b.Row.Longitude) {
            $km = Get-LTIDistanceKm -Lat1 ([double]$a.Row.Latitude) -Lon1 ([double]$a.Row.Longitude) -Lat2 ([double]$b.Row.Latitude) -Lon2 ([double]$b.Row.Longitude)
            if ($km -ge 800 -and ($km / [Math]::Max($hoursApart, 0.01)) -gt 1000) { $hit = $true; $why = "$([int]$km) km in $([Math]::Round($hoursApart * 60)) min" }
        } elseif ($a.Row.Country -and $b.Row.Country -and $a.Row.Country -ne $b.Row.Country -and $hoursApart -le 1) {
            $hit = $true; $why = "country change in $([Math]::Round($hoursApart * 60)) min"
        }
        if ($hit) {
            $seenPairs[$pairKey] = $true; $seenPairs["$($b.Row.IP)>$($a.Row.IP)"] = $true; $travelPairs++
            if ($a.Row.Country -and $b.Row.Country -and $a.Row.Country -ne $b.Row.Country) { $travelAbroad = $true }
            if (-not ([string]$a.Row.DeviceOS -match $mobileOS -and [string]$b.Row.DeviceOS -match $mobileOS)) { $travelNonMobile = $true }
            $travel.Add($a.Row); $travel.Add($b.Row)
            if ($travelText.Count -lt 5) { $travelText.Add("$($a.Row.Timestamp) $($a.Row.IP) ($($a.Row.City) $($a.Row.Country)) -> $($b.Row.Timestamp) $($b.Row.IP) ($($b.Row.City) $($b.Row.Country)): $why") }
        }
    }
    # Inside one country this is very often a VPN or a mobile carrier, so it ranks lower.
    if ($travel.Count -gt 0) {
        if ($travelAbroad) { & $add 'High' 'Impossible travel between successful sign-ins' $travel (($travelText -join ' | ') + ". Rule out a VPN or a cloud-hosted app before treating this as a second person." + (& $msNote $travel)) $travelPairs }
        elseif ($travelNonMobile) { & $add 'Medium' 'Impossible travel between successful sign-ins (same country)' $travel (($travelText -join ' | ') + ". Inside one country this is often a VPN or a mobile carrier - check the networks.") $travelPairs }
        else { & $add 'Low' 'Impossible travel between successful sign-ins (same country, phone or tablet)' $travel (($travelText -join ' | ') + ". Every one of these is a phone or tablet inside one country: mobile-carrier addresses are routinely located hundreds of km from the device.") $travelPairs }
    }

    # 3. Legacy protocols (no MFA possible).
    $legOk = @($ok | Where-Object { $legacy -contains $_.ClientApp })
    $legFail = @($entra | Where-Object { $_.Result -ne 'Success' -and ($legacy -contains $_.ClientApp) })
    if ($legOk.Count -gt 0)   { & $add 'High' 'Successful sign-in over a legacy protocol' $legOk "Protocols: $(@($legOk | ForEach-Object { $_.ClientApp } | Select-Object -Unique) -join ', '). These cannot do MFA, so a password alone was enough." }
    if ($legFail.Count -gt 0) { & $add 'Low' 'Failed sign-in attempts over a legacy protocol' $legFail "Protocols: $(@($legFail | ForEach-Object { $_.ClientApp } | Select-Object -Unique) -join ', '). Typical of password spraying; none succeeded." }

    # 4. Password sent directly by a script (ROPC).
    $ropc = @($ok | Where-Object { $_.AuthProtocol -eq 'ropc' })
    if ($ropc.Count -gt 0) { & $add 'Medium' 'Successful password-only (ROPC) sign-in' $ropc "Apps: $(@($ropc | ForEach-Object { $_.App } | Select-Object -Unique) -join ', '). The password was submitted by a program, not typed into a Microsoft sign-in page." }

    # 5. Scripted / non-browser user agents - in either log.
    # Microsoft's own Office back end signs in this way too (for example
    # "Augmentation Loop" uses node-fetch). Such a row is NOT evidence of an
    # attack script when all of this holds:
    #   - the app is Microsoft's (by owner tenant or app ID, never by name);
    #   - the sign-in carries a joined / registered / managed device identity;
    #   - that same device also has ordinary, non-scripted successful sign-ins
    #     in the same session and from the same network.
    # A stolen token replayed from elsewhere fails at least one of these.
    $anchors = @{}
    foreach ($row in @($ok | Where-Object { $_.UserAgent -notmatch $scripted })) {
        $dk = Get-LTIDeviceKey -Row $row
        if (-not $dk) { continue }
        if (-not $anchors.ContainsKey($dk)) { $anchors[$dk] = @{ IPs = @{}; ASNs = @{}; Sessions = @{} } }
        if ($row.IP) { $anchors[$dk].IPs[[string]$row.IP] = $true }
        if ($row.ASN) { $anchors[$dk].ASNs[[string]$row.ASN] = $true }
        if ($row.SessionId) { $anchors[$dk].Sessions[[string]$row.SessionId] = $true }
    }
    $isOwnOffice = {
        param($row)
        if (-not (Test-LTIMicrosoftApp -Row $row)) { return $false }
        $dk = Get-LTIDeviceKey -Row $row
        if (-not $dk) { return $false }
        if (-not ($row.DeviceTrust -or [string]$row.DeviceManaged -eq 'True' -or [string]$row.DeviceCompliant -eq 'True')) { return $false }
        $anchor = $anchors[$dk]
        if (-not $anchor) { return $false }
        $sameNetwork = (($row.IP -and $anchor.IPs.ContainsKey([string]$row.IP)) -or ($row.ASN -and $anchor.ASNs.ContainsKey([string]$row.ASN)))
        if (-not $sameNetwork) { return $false }
        if ($row.SessionId -and -not $anchor.Sessions.ContainsKey([string]$row.SessionId)) { return $false }
        return $true
    }
    $uaOk = [System.Collections.Generic.List[object]]::new(); $uaFail = [System.Collections.Generic.List[object]]::new(); $uaOwn = [System.Collections.Generic.List[object]]::new(); $ownSeen = @{}
    foreach ($row in @($entra | Where-Object { $_.UserAgent -match $scripted })) {
        if (& $isOwnOffice $row) { $uaOwn.Add($row); $ownSeen["$($row.IP)|$($row.UserAgent)"] = $true }
        elseif ($row.Result -eq 'Success') { $uaOk.Add($row) }
        else { $uaFail.Add($row) }
    }
    # Audit-log rows carry no app or device, so one is cleared only when it has
    # the same address and user agent as a sign-in already cleared above.
    foreach ($row in @($audit | Where-Object { [string]$_.UserAgent -match $scripted })) {
        if ($ownSeen.ContainsKey("$($row.ClientIP)|$($row.UserAgent)")) { continue }
        if ($row.Operation -eq 'UserLoggedIn') { $uaOk.Add($row) } elseif ($row.Operation -eq 'UserLoginFailed') { $uaFail.Add($row) }
    }
    $uaDetail = {
        param($rows)
        $agents = @($rows | ForEach-Object { [string]$_.UserAgent } | Select-Object -Unique | Select-Object -First 3) -join ' | '
        $apps = @($rows | ForEach-Object { [string]$_.App } | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 4) -join ', '
        $devices = @($rows | ForEach-Object { [string]$_.DeviceName } | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 3) -join ', '
        $text = "User agents: $agents"
        if ($apps) { $text += ". Apps: $apps" }
        if ($devices) { $text += ". Devices: $devices" } elseif ($apps) { $text += ". No device identity on these sign-ins" }
        return $text
    }
    if ($uaOk.Count -gt 0)   { & $add 'High' 'Successful sign-in from a scripted client' @($uaOk) "$(& $uaDetail $uaOk). Attack toolkits sign in with HTTP libraries rather than browsers; a script or integration the organisation runs itself looks the same, so match the app and address to something known." }
    if ($uaFail.Count -gt 0) { & $add 'Low' 'Failed sign-in attempts from a scripted client' @($uaFail) (& $uaDetail $uaFail) }
    if ($uaOwn.Count -gt 0) {
        $script:LTIIndicatorNotes += "$($uaOwn.Count) sign-in(s) with an HTTP-library user agent were Microsoft's own Office services ($(@($uaOwn | ForEach-Object { [string]$_.App } | Where-Object { $_ } | Select-Object -Unique) -join ', ')) on the user's own device ($(@($uaOwn | ForEach-Object { [string]$_.DeviceName } | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 3) -join ', ')), in the same session and network as its ordinary sign-ins - not flagged"
    }

    # 6. Device-code sign-ins (a common phishing route).
    $dc = @($ok | Where-Object { $_.AuthProtocol -eq 'deviceCode' -or $_.TransferMethod -eq 'deviceCodeFlow' })
    # This tool signs in by device code itself. When the mailbox being investigated
    # is the account running the tool, its own sign-ins are set aside - but only
    # those to this tool's app from the address used for THIS session's sign-in.
    # A device-code sign-in to the same app from anywhere else is still flagged.
    $dcHint = ""
    if ($UPN -and $script:GraphSignedInAs -and ($UPN -eq [string]$script:GraphSignedInAs)) {
        $toolRows = @($dc | Where-Object { $_.AppId -and $_.AppId -eq $script:GraphClientId })
        if ($toolRows.Count -gt 0) {
            $sessionIPs = @{}
            if ($script:GraphSignInAt) {
                foreach ($row in $toolRows) {
                    $t = ConvertTo-LTIUtcDateTime -Value $row.Timestamp
                    if ($null -ne $t -and $row.IP -and [Math]::Abs(($t - $script:GraphSignInAt).TotalMinutes) -le 15) { $sessionIPs[[string]$row.IP] = $true }
                }
            }
            if ($sessionIPs.Count -gt 0) {
                $mine = @($toolRows | Where-Object { $_.IP -and $sessionIPs.ContainsKey([string]$_.IP) })
                $dc = @($dc | Where-Object { $mine -notcontains $_ })
                $script:LTIIndicatorNotes += "$($mine.Count) device-code sign-in(s) to '$($mine[0].App)' from $(@($sessionIPs.Keys) -join ', ') are this tool's own sign-ins by the account running it - not flagged"
            } else {
                $dcHint = " $($toolRows.Count) of these are to this tool's own app by the account running it, but none could be matched to this session's sign-in (the log can lag by a few minutes), so they are listed."
            }
        }
    }
    if ($dc.Count -gt 0) { & $add 'Medium' 'Successful device-code sign-in' $dc "Apps: $(@($dc | ForEach-Object { $_.App } | Select-Object -Unique) -join ', '). Device-code phishing tricks a user into approving a code for the attacker's session - confirm the user did this on purpose.$dcHint" }

    # 7. Microsoft's own risk verdict (Entra ID P2).
    $risk = @($entra | Where-Object { @('medium', 'high') -contains [string]$_.RiskLevel })
    if ($risk.Count -gt 0) {
        $sev = 'Medium'
        if (@($risk | Where-Object { $_.RiskLevel -eq 'high' -and $_.Result -eq 'Success' }).Count -gt 0) { $sev = 'High' }
        & $add $sev 'Sign-ins Microsoft scored as risky' $risk "Risk: $(@($risk | ForEach-Object { "$($_.RiskLevel)$(if ($_.RiskDetail -and $_.RiskDetail -ne 'none') { " ($($_.RiskDetail))" })" } | Select-Object -Unique) -join ', ')"
    }

    # 8. A success from an address that was also guessing passwords.
    foreach ($grp in @($entra | Where-Object { $_.IP } | Group-Object -Property IP)) {
        $f = @($grp.Group | Where-Object { $_.Result -ne 'Success' -and @(50126, 50053, 50055, 50056) -contains [int]$_.ErrorCode })
        $s = @($grp.Group | Where-Object { $_.Result -eq 'Success' })
        if ($f.Count -ge 10 -and $s.Count -gt 0) { & $add 'High' 'Successful sign-in after repeated password failures from the same IP' $grp.Group "$($f.Count) password failures then $($s.Count) success(es) from $($grp.Name)$(if ($grp.Group[0].Country) { " ($($grp.Group[0].Country))" })" }
    }

    # 9. A country that only ever appears in background (token) sign-ins.
    $interactiveCountries = @($ok | Where-Object { $_.Type -eq 'Interactive' } | ForEach-Object { $_.Country } | Where-Object { $_ } | Select-Object -Unique)
    if ($interactiveCountries.Count -gt 0) {
        $odd = @($ok | Where-Object { $_.Type -eq 'NonInteractive' -and $_.Country -and ($interactiveCountries -notcontains $_.Country) })
        if ($odd.Count -gt 0) { & $add 'Medium' 'Background sign-ins from a country with no interactive sign-in' $odd "Countries: $(@($odd | ForEach-Object { $_.Country } | Select-Object -Unique) -join ', ') (interactive sign-ins came from $($interactiveCountries -join ', ')). A token used somewhere the user never signed in.$(& $msNote $odd)" }
    }

    # 10. The password was accepted, and only MFA or a policy stopped the sign-in -
    #     from a network this user never completed a sign-in from. On the user's own
    #     network these codes are routine prompts; from anywhere else they mean
    #     someone else has the password.
    $okIPs = @{}; $okASNs = @{}; $okCountries = @{}
    foreach ($row in $ok) {
        if ($row.IP) { $okIPs[[string]$row.IP] = $true }
        if ($row.ASN) { $okASNs[[string]$row.ASN] = $true }
        if ($row.Country) { $okCountries[[string]$row.Country] = $true }
    }
    $stopped = @($entra | Where-Object {
        $_.Result -ne 'Success' -and $_.IP -and (@($script:LTIPasswordAcceptedCodes) -contains [int]$_.ErrorCode) -and
        ($_.Type -eq 'Interactive' -or ($legacy -contains $_.ClientApp) -or $_.AuthProtocol -eq 'ropc') -and
        -not $okIPs.ContainsKey([string]$_.IP) -and -not ($_.ASN -and $okASNs.ContainsKey([string]$_.ASN))
    })
    if ($stopped.Count -gt 0) {
        $sev = 'Medium'
        if ($okCountries.Count -gt 0 -and @($stopped | Where-Object { $_.Country -and -not $okCountries.ContainsKey([string]$_.Country) }).Count -gt 0) { $sev = 'High' }
        $where = @($stopped | ForEach-Object { "$($_.City) $($_.Country) AS$($_.ASN)".Trim() } | Select-Object -Unique | Select-Object -First 4) -join '; '
        & $add $sev 'Password accepted but sign-in stopped at MFA or policy, from a network with no successful sign-in' $stopped "Codes: $(@($stopped | ForEach-Object { $_.ErrorCode } | Select-Object -Unique) -join ', '). From: $where. These codes are only reached after the password is accepted, and nobody completed a sign-in from there - treat the password as known to someone else and reset it."
    }

    $rank = @{ High = 0; Medium = 1; Low = 2 }
    return , @($out | Sort-Object -Property @{ Expression = { $rank[$_.Severity] } }, Indicator)
}

# -----------------------------------------------------------------------------
#  REV 3.0 - MERGED TIMELINE (one per mailbox: 00_Timeline.csv)
# -----------------------------------------------------------------------------
function Add-LTITimelineEach {
    # One timeline row per source row.
    param($List, $Rows, [string]$Source, [string]$TimeProperty = 'Timestamp', [scriptblock]$Label, [scriptblock]$Detail, [string]$IPProperty = 'ClientIP', [bool]$Notable = $false)

    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $t = ConvertTo-LTIUtcDateTime -Value $r.$TimeProperty
        if ($null -eq $t) { continue }
        $List.Add([PSCustomObject]@{ Time = $t; Source = $Source; Event = [string](& $Label $r); Detail = [string](& $Detail $r); IP = [string]$r.$IPProperty; Count = 1; Notable = $Notable })
    }
}

function Add-LTITimelineGroup {
    # High-volume sources are folded: one row per hour + key, with a count.
    param($List, $Rows, [string]$Source, [string]$TimeProperty = 'Timestamp', [scriptblock]$Key, [scriptblock]$Label, [scriptblock]$Detail, [string]$IPProperty = 'ClientIP', [bool]$Notable = $false, [int]$NotableAtCount = 0)

    $items = foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $t = ConvertTo-LTIUtcDateTime -Value $r.$TimeProperty
        if ($null -eq $t) { continue }
        [PSCustomObject]@{ R = $r; T = $t; K = ($t.ToString('yyyy-MM-dd HH') + '|' + [string](& $Key $r)) }
    }
    foreach ($g in @($items | Group-Object -Property K)) {
        $ordered = @($g.Group | Sort-Object -Property T)
        $rows = @($ordered | ForEach-Object { $_.R })
        $isNotable = $Notable
        if ($NotableAtCount -gt 0 -and $rows.Count -ge $NotableAtCount) { $isNotable = $true }
        $List.Add([PSCustomObject]@{ Time = $ordered[0].T; Source = $Source; Event = [string](& $Label $rows); Detail = [string](& $Detail $rows); IP = [string]$rows[0].$IPProperty; Count = $rows.Count; Notable = $isNotable })
    }
}

function Get-LTITimeline {
    # Everything that happened to one mailbox, from every step, in time order.
    # $Data keys: SignIns, Entra, Mailbox, OAuth, RuleChanges, Files, Admin,
    #             EDiscovery, Outbound, MfaMethods, MfaAudit, AppRows, Indicators
    param([hashtable]$Data, [DateTime]$WindowStart)

    $list = [System.Collections.Generic.List[object]]::new()
    $uniq = { param($rows, $prop, $max) (@($rows | ForEach-Object { [string]$_.$prop } | Where-Object { $_ } | Select-Object -Unique | Select-Object -First $max) -join ', ') }

    # Sign-ins. Where the Entra log covers a period it is the better source; the
    # audit-log rows fill in whatever is older than the Entra log reaches.
    $entra = @($Data.Entra | Where-Object { $_ })
    $entraFrom = $null
    foreach ($e in $entra) { $t = ConvertTo-LTIUtcDateTime -Value $e.Timestamp; if ($null -ne $t -and ($null -eq $entraFrom -or $t -lt $entraFrom)) { $entraFrom = $t } }
    $auditSignIns = @($Data.SignIns | Where-Object { $_ })
    if ($null -ne $entraFrom) { $auditSignIns = @($auditSignIns | Where-Object { $t = ConvertTo-LTIUtcDateTime -Value $_.Timestamp; ($null -ne $t) -and ($t -lt $entraFrom) }) }

    Add-LTITimelineGroup -List $list -Rows @($auditSignIns | Where-Object { $_.Operation -eq 'UserLoggedIn' }) -Source 'Sign-in (audit log)' `
        -Key { param($r) $r.ClientIP } -Label { param($rows) "Sign-in OK" } -Detail { param($rows) "$($rows.Count) successful sign-in(s)" }
    Add-LTITimelineGroup -List $list -Rows @($auditSignIns | Where-Object { (Get-LTIAuditOutcome -Row $_) -eq 'Failure' }) -Source 'Sign-in (audit log)' -NotableAtCount 10 `
        -Key { param($r) "$($r.ClientIP)|$($r.ErrorCode)" } -Label { param($rows) "Sign-in FAILED" } -Detail { param($rows) "$($rows.Count) failed sign-in(s), error $($rows[0].ErrorCode) $($rows[0].LogonError)" }
    Add-LTITimelineGroup -List $list -Rows @($auditSignIns | Where-Object { (Get-LTIAuditOutcome -Row $_) -eq 'Interrupted' }) -Source 'Sign-in (audit log)' `
        -Key { param($r) "$($r.ClientIP)|$($r.ErrorCode)" } -Label { param($rows) "Sign-in interrupted (prompt or expired session)" } -Detail { param($rows) "$($rows.Count) interrupted sign-in(s), code $($rows[0].ErrorCode) $($rows[0].LogonError)" }

    Add-LTITimelineEach -List $list -Rows @($entra | Where-Object { $_.Type -eq 'Interactive' -and $_.Result -eq 'Success' }) -Source 'Sign-in (Entra)' -IPProperty 'IP' `
        -Label { param($r) "Interactive sign-in OK" } -Detail { param($r) "$($r.App) via $($r.ClientApp); $($r.DeviceOS) $($r.Browser); $($r.City) $($r.Country)" }
    Add-LTITimelineGroup -List $list -Rows @($entra | Where-Object { $_.Type -eq 'Interactive' -and $_.Result -ne 'Success' -and $_.Result -ne 'Interrupted' }) -Source 'Sign-in (Entra)' -IPProperty 'IP' -NotableAtCount 10 `
        -Key { param($r) "$($r.IP)|$($r.ErrorCode)" } -Label { param($rows) "Interactive sign-in FAILED" } -Detail { param($rows) "$($rows.Count) failure(s), error $($rows[0].ErrorCode): $($rows[0].FailureReason); $($rows[0].City) $($rows[0].Country)" }
    Add-LTITimelineGroup -List $list -Rows @($entra | Where-Object { $_.Type -eq 'Interactive' -and $_.Result -eq 'Interrupted' }) -Source 'Sign-in (Entra)' -IPProperty 'IP' `
        -Key { param($r) "$($r.IP)|$($r.ErrorCode)" } -Label { param($rows) "Interactive sign-in interrupted (prompt or expired session)" } -Detail { param($rows) "$($rows.Count) time(s), code $($rows[0].ErrorCode): $($rows[0].FailureReason); $($rows[0].City) $($rows[0].Country)" }
    Add-LTITimelineGroup -List $list -Rows @($entra | Where-Object { $_.Type -eq 'NonInteractive' }) -Source 'Sign-in (Entra)' -IPProperty 'IP' `
        -Key { param($r) "$($r.IP)|$($r.Result)" } -Label { param($rows) "Background (non-interactive) sign-in $(if ($rows[0].Result -eq 'Success') { 'OK' } elseif ($rows[0].Result -eq 'Interrupted') { 'interrupted' } else { 'FAILED' })" } `
        -Detail { param($rows) "$($rows.Count) token sign-in(s); apps: $(& $uniq $rows 'App' 4); $($rows[0].City) $($rows[0].Country)" }

    # Mailbox activity.
    $mbx = @($Data.Mailbox | Where-Object { $_ })
    Add-LTITimelineEach -List $list -Rows @($mbx | Where-Object { @('Send', 'SendAs', 'SendOnBehalf') -contains $_.Operation }) -Source 'Mailbox' `
        -Label { param($r) "Mail sent ($($r.Operation))" } -Detail { param($r) "Subject: $($r.ItemSubject)" }
    Add-LTITimelineGroup -List $list -Rows @($mbx | Where-Object { @('HardDelete', 'SoftDelete', 'MoveToDeletedItems') -contains $_.Operation }) -Source 'Mailbox' -NotableAtCount 25 `
        -Key { param($r) "$($r.Operation)|$($r.ClientIP)" } -Label { param($rows) "Mail deleted ($($rows[0].Operation))" } -Detail { param($rows) "$($rows.Count) item(s)" }
    Add-LTITimelineGroup -List $list -Rows @($mbx | Where-Object { $_.Operation -eq 'MailItemsAccessed' }) -Source 'Mailbox' `
        -Key { param($r) $r.ClientIP } -Label { param($rows) "Mail read (MailItemsAccessed)" } -Detail { param($rows) "$($rows.Count) access record(s); client: $(& $uniq $rows 'ClientInfo' 2)" }
    Add-LTITimelineGroup -List $list -Rows @($mbx | Where-Object { @('Send', 'SendAs', 'SendOnBehalf', 'HardDelete', 'SoftDelete', 'MoveToDeletedItems', 'MailItemsAccessed') -notcontains $_.Operation }) -Source 'Mailbox' `
        -Key { param($r) "$($r.Operation)|$($r.ClientIP)" } -Label { param($rows) "Mailbox $($rows[0].Operation)" } -Detail { param($rows) "$($rows.Count) item(s)" }

    # Changes that matter on their own - always notable.
    Add-LTITimelineEach -List $list -Rows $Data.RuleChanges -Source 'Rule change' -Notable $true `
        -Label { param($r) $r.Operation } -Detail { param($r) $r.Parameters }
    Add-LTITimelineEach -List $list -Rows $Data.OAuth -Source 'App consent (audit log)' -Notable $true `
        -Label { param($r) $r.Operation } -Detail { param($r) "$($r.Target) $($r.ModifiedProps)" }
    Add-LTITimelineEach -List $list -Rows $Data.Admin -Source 'Admin action' -Notable $true `
        -Label { param($r) $r.Operation } -Detail { param($r) "$($r.Target) $($r.Parameters)" }
    Add-LTITimelineEach -List $list -Rows $Data.EDiscovery -Source 'eDiscovery' -Notable $true `
        -Label { param($r) $r.Operation } -Detail { param($r) $r.Parameters }

    # Files: sharing events one by one, everything else folded.
    $files = @($Data.Files | Where-Object { $_ })
    $sharing = @('SharingSet', 'AnonymousLinkCreated', 'CompanyLinkCreated', 'SharingInvitationCreated', 'AddedToSecureLink')
    Add-LTITimelineEach -List $list -Rows @($files | Where-Object { $sharing -contains $_.Operation }) -Source 'Files' -Notable $true `
        -Label { param($r) "File shared ($($r.Operation))" } -Detail { param($r) "$($r.FileName) - $($r.FileUrl)" }
    Add-LTITimelineGroup -List $list -Rows @($files | Where-Object { $sharing -notcontains $_.Operation }) -Source 'Files' -NotableAtCount 100 `
        -Key { param($r) "$($r.Operation)|$($r.ClientIP)" } -Label { param($rows) $rows[0].Operation } -Detail { param($rows) "$($rows.Count) file(s), e.g. $($rows[0].FileName)" }

    # Outbound mail, per hour.
    Add-LTITimelineGroup -List $list -Rows $Data.Outbound -Source 'Mail flow' -TimeProperty 'Received' -IPProperty 'FromIP' -NotableAtCount 30 `
        -Key { param($r) 'out' } -Label { param($rows) "Outbound mail" } `
        -Detail { param($rows) "$(@($rows | ForEach-Object { $_.MessageId } | Select-Object -Unique).Count) message(s) to $(@($rows | ForEach-Object { $_.RecipientAddress } | Select-Object -Unique).Count) recipient(s)" }

    # MFA.
    Add-LTITimelineEach -List $list -Rows @($Data.MfaMethods | Where-Object { $_ -and $_.Created }) -Source 'MFA method' -TimeProperty 'Created' -IPProperty 'None' -Notable $true `
        -Label { param($r) "MFA method registered: $($r.Method)" } -Detail { param($r) $r.Detail }
    Add-LTITimelineEach -List $list -Rows $Data.MfaAudit -Source 'MFA change (audit log)' -IPProperty 'InitiatedByIP' -Notable $true `
        -Label { param($r) $r.Activity } -Detail { param($r) "by $($r.InitiatedBy); $($r.ResultReason)" }

    # Apps (Graph).
    Add-LTITimelineEach -List $list -Rows @($Data.AppRows | Where-Object { $_ -and $_.Timestamp }) -Source 'App change' -IPProperty 'IP' -Notable $true `
        -Label { param($r) $r.Activity } -Detail { param($r) "$($r.App) by $($r.InitiatedBy); $($r.Detail)" }

    # Indicators, pinned at the moment they were first seen.
    Add-LTITimelineEach -List $list -Rows @($Data.Indicators | Where-Object { $_ -and $_.FirstSeen }) -Source 'INDICATOR' -TimeProperty 'FirstSeen' -IPProperty 'IPs' -Notable $true `
        -Label { param($r) "[$($r.Severity)] $($r.Indicator)" } -Detail { param($r) $r.Detail }

    # Method-registration dates can be years old; keep the window tidy.
    $cut = $WindowStart.ToUniversalTime().AddDays(-1)
    $seq = 0
    foreach ($item in $list) { $item | Add-Member -NotePropertyName Seq -NotePropertyValue $seq; $seq++ }
    return , @($list | Where-Object { $_.Time -ge $cut } | Sort-Object -Property Time, Seq)
}

function Export-LTITimeline {
    param($Rows, [string]$Path)

    $out = foreach ($r in @($Rows)) {
        $firstIp = (([string]$r.IP) -split ';')[0].Trim()
        [PSCustomObject]@{
            TimeUTC = $r.Time.ToString("yyyy-MM-dd HH:mm:ss 'UTC'"); Source = $r.Source; Event = $r.Event; Count = $r.Count
            IP = $r.IP; Geo = $(if ($firstIp) { Get-LTIIPLabel -IP $firstIp } else { "" }); Notable = $(if ($r.Notable) { "Yes" } else { "" }); Detail = $r.Detail
        }
    }
    if (@($out).Count -gt 0) { @($out) | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 }
}

# -----------------------------------------------------------------------------
#  REV 3.0 - SEVERITY SCORE
# -----------------------------------------------------------------------------
function Get-LTISeverity {
    # Turns one mailbox's findings into a 0-100 score, a level and the reasons
    # behind it - most serious first. The weights are judgement calls: they rank
    # mailboxes for attention, they are not a probability of compromise.
    param($F)

    $state = @{ Score = 0 }
    $reasons = [System.Collections.Generic.List[object]]::new()
    $add = { param([int]$points, [string]$text) $state.Score += $points; $reasons.Add([PSCustomObject]@{ Points = $points; Text = $text; Order = $reasons.Count }) }
    $blocked = ([string]$F.AccountEnabled -eq "False")

    if ($F.NewMFAMethods -gt 0) { & $add 30 "$($F.NewMFAMethods) MFA method(s) registered inside the investigation window" }

    $indicatorPoints = 0
    foreach ($ind in @($F.Indicators | Where-Object { $_ })) {
        $p = switch ($ind.Severity) { 'High' { 30 } 'Medium' { 15 } default { 3 } }
        if ($indicatorPoints + $p -gt 60) { $p = [Math]::Max(0, 60 - $indicatorPoints) }
        $indicatorPoints += $p
        & $add $p "$($ind.Indicator) ($($ind.Count))"
    }

    if ($F.ForwardingLookAlike) { & $add 45 "Mail forwarded to a look-alike domain: $($F.ForwardingLookAlike)" }
    elseif ($F.MailboxForwardExternal) { & $add 30 "Mailbox forwards all mail outside the organisation: $($F.MailboxForwardExternal)" }
    elseif ($F.ForwardingUnclassified) { & $add 15 "Mailbox forwarding is on and the target could not be classified as internal or external: $($F.ForwardingUnclassified)" }
    elseif ($F.ForwardingActive) { & $add 5 "Mailbox forwarding is on (internal target): $($F.ForwardingTarget)" }

    $rulePoints = 0
    foreach ($rule in @($F.RuleDetails | Where-Object { $_ -and $_.Suspicious })) {
        $p = 15
        if ($rule.Flags -match 'EXTERNAL') { $p = 30 } elseif ($rule.Hidden) { $p = 25 }
        if ($rule.Flags -match 'currently disabled') { $p = 5 }
        if ($rulePoints + $p -gt 45) { $p = [Math]::Max(0, 45 - $rulePoints) }
        $rulePoints += $p
        & $add $p "Inbox rule '$($rule.Name)': $($rule.Flags)"
    }
    if ($blocked -and ($F.ForwardingActive -or @($F.RuleDetails | Where-Object { $_ -and $_.Flags -match '(forwards|redirects)' }).Count -gt 0)) {
        & $add 10 "Sign-in is blocked but mail is still being forwarded - rules and forwarding keep running on a blocked mailbox"
    }

    if ($F.AbusedApps) { & $add 40 "App often seen in mailbox compromises has consent: $($F.AbusedApps)" }
    if ($F.RiskyApps)  { & $add 15 "Third-party app(s) with mail / file access consented by this user: $($F.RiskyApps)" }
    if ($F.MailApps)   { & $add 0 "Well-known mail app with mailbox access: $($F.MailApps). Expected if the user reads mail in that app - revoke it if they do not" }
    if ($F.AppEvents -gt 0) { & $add 15 "$($F.AppEvents) app consent / permission change(s) in the window" }
    elseif ($F.OAuthConsents -gt 0) { & $add 10 "$($F.OAuthConsents) app consent event(s) in the audit log" }

    $mfa = Get-LTIMFAVerdict -Findings $F
    if ($mfa.NoMFA) { & $add 20 "No MFA method registered on an account that can sign in" }
    elseif (-not $blocked -and $F.MFAEnforcement -eq 'NotEnforced') { & $add 10 "MFA is not enforced for this user ($($F.MFAEnforcedBy))" }
    elseif (-not $blocked -and $F.MFAEnforcement -eq 'Partial') { & $add 5 "MFA is only partly enforced ($($F.MFAEnforcedBy))" }
    if (-not $mfa.Verified) { & $add 0 "MFA could not be verified: $($mfa.Text)" }

    if ($F.SignInsFailed -gt 10) {
        if ($blocked) { & $add 2 "$($F.SignInsFailed) failed sign-ins against a blocked account (nobody is getting in; check whether the password is known - error 50057)" }
        elseif ($F.SignInsFailed -gt 50) { & $add 10 "$($F.SignInsFailed) failed sign-ins" }
        else { & $add 5 "$($F.SignInsFailed) failed sign-ins" }
    }
    # Only a country where a sign-in SUCCEEDED scores. Failed attempts from abroad
    # are what every mailbox on the internet receives.
    if ($F.CountriesOK -gt 1) {
        # An indicator that already scored the foreign sign-in is not counted a second time.
        $countryScored = @($F.Indicators | Where-Object { $_ -and $_.Indicator -match 'country|Impossible travel' }).Count -gt 0
        if ($countryScored) { & $add 0 "Successful sign-ins from $($F.CountriesOK) countries: $($F.SuccessCountries)" }
        elseif ([string]$F.EntraSignInLog -match '^(OK|Partial)') { & $add 10 "Successful sign-ins from $($F.CountriesOK) countries: $($F.SuccessCountries)" }
        else { & $add 4 "Successful sign-ins from IPs registered in $($F.CountriesOK) countries (registry data, not location): $($F.SuccessCountries)" }
    } elseif ($F.CountryCount -gt 1) {
        $onlyFrom = "none of them"
        if ($F.SuccessCountries) { $onlyFrom = [string]$F.SuccessCountries }
        & $add 0 "Sign-in attempts from $($F.CountryCount) countries, successful only from: $onlyFrom"
    }
    if ($F.OutboundBurst) { & $add 25 "Outbound mail burst: $($F.OutboundBurstReason)" }
    if ($F.AuditEnabled -eq $false) { & $add 10 "Mailbox auditing is disabled" }
    if ($F.Protocols -match ' enabled$') { & $add 0 "Password-only mail protocols are switched on for this mailbox: $($F.Protocols)" }
    if (@($F.Errors).Count -gt 0) { & $add 0 "$(@($F.Errors).Count) check(s) failed and were NOT examined: $(@($F.Errors) -join '; ')" }

    $score = [Math]::Min($state.Score, 100)
    $level = "None"
    if ($score -ge 70) { $level = "Critical" } elseif ($score -ge 40) { $level = "High" } elseif ($score -ge 20) { $level = "Medium" } elseif ($score -ge 1) { $level = "Low" }
    $ordered = @($reasons | Sort-Object -Property @{ Expression = 'Points'; Descending = $true }, @{ Expression = 'Order' })
    return [PSCustomObject]@{ Score = $score; Level = $level; Reasons = $ordered; ReasonText = (@($ordered | ForEach-Object { "+$($_.Points) $($_.Text)" }) -join ' | ') }
}

# -----------------------------------------------------------------------------
#  REV 3.0 - EVIDENCE BRIEF (_AI_BRIEF.md) AND CLIENT REPORT (_REPORT.html)
# -----------------------------------------------------------------------------
function ConvertTo-LTIMdCell {
    param($Value)
    $s = [string]$Value
    $s = $s -replace "\r?\n", ' ' -replace '\|', '\|'
    if ($s.Length -gt 400) { $s = $s.Substring(0, 400) + "..." }
    return $s
}

function ConvertTo-LTIMdTable {
    # Objects -> markdown table lines. $Columns: property names, in order.
    param($Rows, [string[]]$Columns, [int]$Max = 0)

    $rows = @($Rows | Where-Object { $_ })
    if ($rows.Count -eq 0) { return @() }
    $shown = $rows
    if ($Max -gt 0 -and $rows.Count -gt $Max) { $shown = @($rows | Select-Object -First $Max) }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("| " + ($Columns -join " | ") + " |")
    $lines.Add("|" + (($Columns | ForEach-Object { "---" }) -join "|") + "|")
    foreach ($r in $shown) { $lines.Add("| " + (@($Columns | ForEach-Object { ConvertTo-LTIMdCell -Value $r.$_ }) -join " | ") + " |") }
    if ($shown.Count -lt $rows.Count) { $lines.Add("") ; $lines.Add("_...$($rows.Count - $shown.Count) more row(s) in the CSV._") }
    return @($lines)
}

function Get-LTIReportModel {
    # Everything both report writers need, gathered once.
    param($Findings, [hashtable]$Run)

    $mailboxes = foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $mfa = Get-LTIMFAVerdict -Findings $f
        [PSCustomObject]@{
            F = $f; Mfa = $mfa
            MfaMethods = @($script:allMFAMethodDetails | Where-Object { $_.UPN -eq $f.UPN })
            MfaAudit   = @($script:allMFAAuditRows | Where-Object { $_.UPN -eq $f.UPN })
            IPRows     = @($script:allIPRollup | Where-Object { $_.UPN -eq $f.UPN } | Sort-Object -Property @{ Expression = { $_.AuditOK + $_.AuditFailed + $_.InteractiveOK + $_.InteractiveFailed + $_.NonInteractiveOK + $_.NonInteractiveFailed }; Descending = $true })
            Forwarding = @($script:allForwarding | Where-Object { $_.UPN -eq $f.UPN })
            Notable    = @($f.TimelineRows | Where-Object { $_ -and $_.Notable })
        }
    }

    $enf = $null
    if ($script:MFAContext) { $enf = $script:MFAContext.Enforcement }
    $apps = $script:LTIAppContext
    return @{
        Run = $Run
        Mailboxes = @($mailboxes)
        Enforcement = $enf
        Forwarding = @($script:allForwarding)
        Apps = $apps
        ThirdPartyGrants = @($(if ($apps) { $apps.Grants | Where-Object { -not $_.Microsoft -and ($_.RiskyScopes -or $_.KnownAbused) } }))
    }
}

function Get-LTIBriefLines {
    # The single file to hand to an analyst (human or AI). It carries its own
    # context: what was run, what could not be checked, and how to read it.
    param([hashtable]$Model)

    $run = $Model.Run
    $L = [System.Collections.Generic.List[string]]::new()
    $mb = @($Model.Mailboxes)

    $L.Add("# Microsoft 365 account investigation - evidence brief")
    $L.Add("")
    $L.Add("| | |"); $L.Add("|---|---|")
    $L.Add("| Tenant domain | $($run.Domain) |")
    $L.Add("| Generated | $($run.Generated) |")
    $L.Add("| Window | $($run.WindowFrom) to $($run.WindowTo) ($($run.DaysBack) days back) |")
    $L.Add("| Mailboxes investigated | $($mb.Count) of $($run.MailboxesLoaded) loaded |")
    $L.Add("| Tool | LTI MS365 Investigation Utility $($run.Version) |")
    $L.Add("| Graph sign-in | $($run.GraphAccount) |")
    $L.Add("")

    $L.Add("## How to read this file")
    $L.Add("")
    $L.Add("- All times are UTC.")
    $L.Add("- **Not checked** and **Unknown** mean the tool has no data. They never mean clean.")
    $L.Add("- **Microsoft network** marks an address inside Microsoft's own network. It is usually a Microsoft service acting for the user (often from a datacenter in another country), but servers anyone can rent in Azure are on the same network, so it is a label to weigh, not a clearance.")
    $L.Add("- **Interrupted** sign-ins are prompts (keep me signed in, MFA, registration) and expired sessions. They are not failed sign-ins and are counted apart. Per-country figures are sign-ins that succeeded / failed there; failed attempts from another country do not mean anyone got in.")
    $L.Add("- Sign-ins come from two logs. The unified audit log (""audit"") covers the whole window. The Entra sign-in log (""interactive"" / ""non-interactive"") is richer but may reach back less far - see the next section. The two logs overlap for interactive sign-ins, so **do not add their counts together**.")
    $L.Add("- MFA **Enabled** means an MFA-capable method is registered. Whether MFA is *required* is the separate **Enforcement** line.")
    $L.Add("- Country and city come from Microsoft's own sign-in geolocation. Where the source column says ""registered country"", it is the country the address block is registered in, which is often not where the device is.")
    $L.Add("- The severity score ranks mailboxes for attention. It is a weighted checklist, not a probability of compromise. The reasons listed next to each score are the evidence.")
    $L.Add("")

    $L.Add("## What was and was not checked")
    $L.Add("")
    $L.Add("- Steps run: $($run.StepsRun -join '; ')")
    if (@($run.StepsSkipped).Count -gt 0) { $L.Add("- **Steps NOT run:** $($run.StepsSkipped -join '; ')") }
    $L.Add("- Extended Graph permissions (Conditional Access, app consents): $($run.Extended)")
    foreach ($line in @($run.LogReach)) { $L.Add("- $line") }
    if (@($run.LogReach).Count -eq 0) { $L.Add("- Entra log reach: not checked (no Graph sign-in, or steps 17-19 not run)") }
    $L.Add("- ASN / network lookup for unlabelled IPs: $($run.GeoLookup)")
    $failed = @($mb | Where-Object { @($_.F.Errors).Count -gt 0 })
    if ($failed.Count -gt 0) {
        $L.Add("- **Checks that failed:**")
        foreach ($m in $failed) { $L.Add("  - $($m.F.UPN): $(@($m.F.Errors) -join '; ')") }
    }
    $L.Add("")

    # ---------------- tenant-wide ----------------
    $L.Add("## Tenant-wide findings")
    $L.Add("")
    $L.Add("### Is MFA enforced?")
    $L.Add("")
    $enf = $Model.Enforcement
    if (-not $enf -or -not $enf.Checked) {
        $L.Add("Not checked. $(if ($enf) { $enf.Reason } else { 'The MFA step did not run.' })")
    } else {
        $sd = "Unknown"
        if ($enf.SecurityDefaults -eq $true) { $sd = "**Enabled** - every user is covered" } elseif ($enf.SecurityDefaults -eq $false) { $sd = "Disabled" }
        $L.Add("- Security Defaults: $sd")
        if ($enf.CAError) { $L.Add("- Conditional Access: could not be read ($($enf.CAError))") }
        else { $L.Add("- Conditional Access: $(@($enf.Policies).Count) policy(ies); $(@($enf.MfaPolicies).Count) enabled and requiring MFA at sign-in$(if ($enf.ReportOnly -gt 0) { "; $($enf.ReportOnly) report-only (enforcing nothing)" })") }
        $L.Add("")
        foreach ($line in (ConvertTo-LTIMdTable -Rows $enf.Rows -Columns @('Policy', 'State', 'Grant', 'Users', 'Apps', 'Conditions', 'CountsAsSignInMFA'))) { $L.Add($line) }
    }
    $L.Add("")

    $L.Add("### Mail forwarding across the tenant")
    $L.Add("")
    $fw = @($Model.Forwarding)
    if ($fw.Count -eq 0) { $L.Add("No mailbox forwarding, forwarding inbox rules (on the investigated mailboxes) or redirecting transport rules were found.") }
    else {
        $look = @($fw | Where-Object { $_.LookAlikeOf })
        if ($look.Count -gt 0) { $L.Add("**Look-alike forwarding target(s):** " + (@($look | ForEach-Object { "$($_.UPN) -> $($_.TargetAddress) (resembles $($_.LookAlikeOf))" }) -join '; ')); $L.Add("") }
        foreach ($line in (ConvertTo-LTIMdTable -Rows $fw -Columns @('UPN', 'Source', 'TargetAddress', 'External', 'LookAlikeOf', 'SignInBlocked', 'Note') -Max 60)) { $L.Add($line) }
        $L.Add("")
        $L.Add("Mailbox-level forwarding covers every loaded mailbox. Inbox-rule forwarding covers only the investigated mailboxes.")
    }
    $L.Add("")

    $L.Add("### Third-party apps with access to mail, files or the directory")
    $L.Add("")
    $apps = $Model.Apps
    if (-not $apps) { $L.Add("Not checked (step 19 did not run).") }
    elseif (-not $apps.GrantsChecked) { $L.Add("Current consents not checked. $($apps.GrantsReason)") }
    elseif (@($Model.ThirdPartyGrants).Count -eq 0) { $L.Add("None. No non-Microsoft app holds mail, file or directory permissions$(if (-not $apps.AppOnlyChecked) { ' (delegated permissions only - app-only permissions could not be read)' }).") }
    else {
        $L.Add("ConsentType: **Principal** = one user consented; **AllPrincipals** = an admin consented for everyone; **Application** = app-only, reaches every mailbox with no user signed in. Check each one is expected - a consented app keeps its access after a password reset.")
        $L.Add("")
        foreach ($line in (ConvertTo-LTIMdTable -Rows $Model.ThirdPartyGrants -Columns @('App', 'Publisher', 'ConsentType', 'Principal', 'RiskyScopes', 'KnownAbused', 'KnownMailClient') -Max 40)) { $L.Add($line) }
    }
    if ($apps -and $apps.AuditChecked) { $L.Add(""); $L.Add("App-related audit events in the window: $(@($apps.AuditRows).Count) (see 19b_Tenant_App_Audit_Events.csv).") }
    $L.Add("")

    # ---------------- ranking ----------------
    $L.Add("## Mailboxes by severity")
    $L.Add("")
    $rank = foreach ($m in $mb) { [PSCustomObject]@{ Mailbox = $m.F.UPN; Severity = $m.F.Level; Score = $m.F.Score; 'Top reasons' = (@($m.F.Reasons | Where-Object { $_.Points -gt 0 } | Select-Object -First 3 | ForEach-Object { $_.Text }) -join '; ') } }
    foreach ($line in (ConvertTo-LTIMdTable -Rows $rank -Columns @('Mailbox', 'Severity', 'Score', 'Top reasons'))) { $L.Add($line) }
    $L.Add("")

    # ---------------- per mailbox ----------------
    $L.Add("## Mailbox details")
    foreach ($m in $mb) {
        $f = $m.F
        $L.Add("")
        $L.Add("### $($f.UPN) - $($f.Level) ($($f.Score))")
        $L.Add("")
        $L.Add("- Name: $($f.DisplayName) | Mailbox type: $($f.MailboxType) | Sign-in allowed: $(if ($f.AccountEnabled) { $f.AccountEnabled } else { 'unknown' })")
        if (@($f.Reasons).Count -gt 0) {
            $L.Add("- **Why this score:**")
            foreach ($r in @($f.Reasons)) { $L.Add("  - +$($r.Points): $($r.Text)") }
        } else { $L.Add("- Nothing flagged.") }
        $L.Add("- MFA: $($m.Mfa.Text)")
        $L.Add("- MFA enforcement: $(if ($f.MFAEnforcement) { "$($f.MFAEnforcement) - $($f.MFAEnforcedBy)" } else { 'not checked' })")
        $L.Add("- Sign-ins (audit log): $($f.SignInsOK) ok / $($f.SignInsFailed) failed$(if ($f.SignInsInterrupted -gt 0) { " / $($f.SignInsInterrupted) interrupted" }). Entra log: $($f.EntraSignInLog)$(if ($f.EntraInteractive) { "; interactive $($f.EntraInteractive)" })$(if ($f.EntraNonInteractive) { "; non-interactive $($f.EntraNonInteractive)" })")
        if ($f.SignInCountries) { $L.Add("- Sign-ins by country (succeeded / failed): $($f.SignInCountries)") }
        $L.Add("- Forwarding: $(if ($f.ForwardingAll) { $f.ForwardingAll } elseif ($f.ForwardingActive) { $f.ForwardingTarget } else { 'none found' })")
        $L.Add("- Inbox rules: $($f.TotalRules) total, $($f.SuspiciousRules) flagged, $($f.HiddenRules) hidden")
        $L.Add("- Apps: $($f.AppStatus)$(if ($f.AppStatus -ne 'Not run') { "; $($f.AppGrants) consent(s) by this user, $($f.AppEvents) change(s) in the window" })$(if ($f.RiskyApps) { "; with mail/file access: $($f.RiskyApps)" })$(if ($f.MailApps) { "; well-known mail apps: $($f.MailApps)" })")
        if ($f.OutboundProfile) { $L.Add("- Outbound mail: $($f.OutboundProfile)$(if ($f.OutboundBurst) { " - **BURST: $($f.OutboundBurstReason)**" })") }
        if ($f.Protocols) { $L.Add("- Protocols: $($f.Protocols)") }
        $L.Add("- Other counts: $($f.OAuthConsents) consent event(s) in the audit log, $($f.AdminActions) admin action(s), $($f.FileEvents) file event(s); mailbox auditing: $(if ($null -eq $f.AuditEnabled) { 'not checked' } else { $f.AuditEnabled })")

        if (@($f.Indicators).Count -gt 0) {
            $L.Add(""); $L.Add("**Sign-in indicators**"); $L.Add("")
            foreach ($line in (ConvertTo-LTIMdTable -Rows $f.Indicators -Columns @('Severity', 'Indicator', 'Count', 'FirstSeen', 'LastSeen', 'IPs', 'Detail'))) { $L.Add($line) }
        }
        if (@($m.IPRows).Count -gt 0) {
            $L.Add(""); $L.Add("**Sign-in IPs** (busiest first)"); $L.Add("")
            foreach ($line in (ConvertTo-LTIMdTable -Rows $m.IPRows -Columns @('IP', 'Country', 'City', 'ASN', 'ASName', 'GeoSource', 'AuditOK', 'AuditFailed', 'InteractiveOK', 'InteractiveFailed', 'NonInteractiveOK', 'NonInteractiveFailed', 'FirstSeen', 'LastSeen') -Max 20)) { $L.Add($line) }
        }
        if (@($m.MfaMethods).Count -gt 0) {
            $L.Add(""); $L.Add("**Registered sign-in methods**"); $L.Add("")
            foreach ($line in (ConvertTo-LTIMdTable -Rows $m.MfaMethods -Columns @('Method', 'CountsAsMFA', 'Detail', 'Created', 'LastUsed'))) { $L.Add($line) }
        }
        if (@($m.MfaAudit).Count -gt 0) {
            $L.Add(""); $L.Add("**MFA / sign-in method changes in the audit log**"); $L.Add("")
            foreach ($line in (ConvertTo-LTIMdTable -Rows $m.MfaAudit -Columns @('Timestamp', 'Activity', 'Service', 'InitiatedBy', 'InitiatedByIP', 'Result', 'ResultReason') -Max 25)) { $L.Add($line) }
        }
        $flagged = @($f.RuleDetails | Where-Object { $_ -and $_.Suspicious })
        if ($flagged.Count -gt 0) {
            $L.Add(""); $L.Add("**Flagged inbox rules**"); $L.Add("")
            foreach ($line in (ConvertTo-LTIMdTable -Rows $flagged -Columns @('Name', 'Enabled', 'Hidden', 'Flags'))) { $L.Add($line) }
        }
        if (@($f.AppRows).Count -gt 0) {
            $L.Add(""); $L.Add("**Apps**"); $L.Add("")
            foreach ($line in (ConvertTo-LTIMdTable -Rows $f.AppRows -Columns @('Kind', 'Timestamp', 'App', 'Publisher', 'RiskyScopes', 'KnownAbused', 'Activity', 'InitiatedBy', 'IP') -Max 20)) { $L.Add($line) }
        }
        if (@($m.Notable).Count -gt 0) {
            $L.Add(""); $L.Add("**Notable events** (full sequence: 00_Timeline.csv in this mailbox's folder)"); $L.Add("")
            $rows = foreach ($n in @($m.Notable | Select-Object -First 40)) { [PSCustomObject]@{ TimeUTC = $n.Time.ToString("yyyy-MM-dd HH:mm:ss"); Source = $n.Source; Event = $n.Event; Count = $n.Count; IP = $n.IP; Detail = $n.Detail } }
            foreach ($line in (ConvertTo-LTIMdTable -Rows $rows -Columns @('TimeUTC', 'Source', 'Event', 'Count', 'IP', 'Detail'))) { $L.Add($line) }
            if (@($m.Notable).Count -gt 40) { $L.Add(""); $L.Add("_...$(@($m.Notable).Count - 40) more notable event(s) in 00_Timeline.csv._") }
        }
    }

    $L.Add("")
    $L.Add("## Files in this folder")
    $L.Add("")
    $L.Add("- ``_AI_BRIEF.md`` - this file. ``_REPORT.html`` - the same findings formatted for a person.")
    $L.Add("- ``_MASTER_SUMMARY.csv`` / ``.txt`` - one row per mailbox. ``_SIGNIN_IP_SUMMARY.csv`` - one row per mailbox + IP. ``_FORWARDING_REVIEW.csv`` - every forwarding path found.")
    $L.Add("- ``17_MFA_Status.csv``, ``17a_MFA_Method_Details.csv``, ``17b_MFA_Config_Audit_Events.csv``, ``17c_MFA_Enforcement_Policies.csv`` - MFA state, methods, changes and what enforces it.")
    $L.Add("- ``19a_Tenant_App_Grants.csv``, ``19b_Tenant_App_Audit_Events.csv`` - app consents and app changes.")
    $L.Add("- One folder per mailbox: ``00_Timeline.csv`` (everything in time order) and the raw output of each step (01-19).")
    return @($L)
}

function ConvertTo-LTIHtml {
    param($Value)
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-LTIHtmlTable {
    # Objects -> a sortable HTML table. $Columns: @{ Name = 'Property'; Label = 'Heading' } or plain property names.
    param($Rows, $Columns, [int]$Max = 0, [string]$Class = "")

    $rows = @($Rows | Where-Object { $_ })
    if ($rows.Count -eq 0) { return "" }
    $shown = $rows
    if ($Max -gt 0 -and $rows.Count -gt $Max) { $shown = @($rows | Select-Object -First $Max) }
    $cols = foreach ($c in @($Columns)) { if ($c -is [hashtable]) { [PSCustomObject]@{ Name = $c.Name; Label = $c.Label } } else { [PSCustomObject]@{ Name = [string]$c; Label = [string]$c } } }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class=""tw""><table class=""sortable $Class""><thead><tr>")
    foreach ($c in $cols) { [void]$sb.Append("<th>$(ConvertTo-LTIHtml $c.Label)</th>") }
    [void]$sb.Append("</tr></thead><tbody>")
    foreach ($r in $shown) {
        [void]$sb.Append("<tr>")
        foreach ($c in $cols) {
            # Short values (IPs, counts, codes) stay on one line; long text wraps at spaces.
            $cell = ConvertTo-LTIHtml $r.($c.Name)
            if ($cell.Length -le 16) { [void]$sb.Append("<td class=""s"">$cell</td>") } else { [void]$sb.Append("<td>$cell</td>") }
        }
        [void]$sb.Append("</tr>")
    }
    [void]$sb.Append("</tbody></table></div>")
    if ($shown.Count -lt $rows.Count) { [void]$sb.Append("<p class=""more"">$($rows.Count - $shown.Count) more row(s) in the CSV files.</p>") }
    return $sb.ToString()
}

function Get-LTIHtmlReport {
    # Self-contained page: no external files, fonts or scripts, so it can be
    # e-mailed or printed as-is.
    param([hashtable]$Model)

    $run = $Model.Run
    $mb = @($Model.Mailboxes)
    $h = { param($v) ConvertTo-LTIHtml $v }
    $count = { param($level) @($mb | Where-Object { $_.F.Level -eq $level }).Count }
    $sb = New-Object System.Text.StringBuilder

    $css = @'
:root{--ink:#16202b;--muted:#5b6876;--line:#d9dee4;--bg:#f4f6f8;--card:#fff;--crit:#a4161a;--high:#c2540a;--med:#8a6d00;--low:#2c6e9b;--none:#3d7a4f}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 24px 60px}
header h1{font-size:24px;margin:0 0 4px;letter-spacing:-.01em}
header p{margin:0;color:var(--muted)}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:6px 24px;margin:18px 0 0;padding:14px 16px;background:var(--card);border:1px solid var(--line);border-radius:8px}
.meta div{font-size:13px}.meta b{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.card{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--line);border-radius:8px;padding:12px 14px}
.card .n{font-size:28px;font-weight:650;line-height:1.1;font-variant-numeric:tabular-nums}.card .l{font-size:12px;color:var(--muted)}
.card.crit{border-left-color:var(--crit)}.card.high{border-left-color:var(--high)}.card.med{border-left-color:var(--med)}.card.low{border-left-color:var(--low)}.card.none{border-left-color:var(--none)}
h2{font-size:17px;margin:34px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--ink)}
h3{font-size:14px;margin:18px 0 6px}
.note{background:#fff8e1;border:1px solid #ecd9a0;border-radius:8px;padding:10px 14px;margin:10px 0}
.note.bad{background:#fdecea;border-color:#f0b4ae}
.note ul{margin:4px 0 0;padding-left:20px}
.tw{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px;margin:8px 0}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
th{background:#eef1f4;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);white-space:nowrap;cursor:pointer;user-select:none}
th.asc:after{content:" \25B2"}th.desc:after{content:" \25BC"}
td{overflow-wrap:break-word}
td.s{white-space:nowrap}
.hint{font-weight:400;color:var(--muted);font-size:12px}
.chip{display:inline-block;min-width:74px;text-align:center;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:650;letter-spacing:.04em;text-transform:uppercase;color:#fff}
.chip.Critical{background:var(--crit)}.chip.High{background:var(--high)}.chip.Medium{background:var(--med)}.chip.Low{background:var(--low)}.chip.None{background:var(--none)}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:10px 0}
summary{cursor:pointer;padding:11px 14px;display:flex;gap:12px;align-items:center;font-weight:600;list-style:none}
summary::-webkit-details-marker{display:none}
summary .score{margin-left:auto;font-variant-numeric:tabular-nums;color:var(--muted);font-weight:500}
details[open] summary{border-bottom:1px solid var(--line)}
.body{padding:6px 16px 16px}
.kv{display:grid;grid-template-columns:170px 1fr;gap:4px 14px;margin:10px 0}.kv dt{color:var(--muted)}.kv dd{margin:0}
.why{margin:6px 0 0;padding-left:0;list-style:none}.why li{padding:3px 0}.why .pts{display:inline-block;min-width:38px;font-variant-numeric:tabular-nums;color:var(--muted)}
.more{color:var(--muted);font-size:12px;margin:4px 2px}
footer{margin-top:40px;color:var(--muted);font-size:12px}
@media print{body{background:#fff}.wrap{max-width:none;padding:0}details{break-inside:avoid;border:0;border-top:1px solid var(--line);border-radius:0}details>.body{display:block!important}summary{padding-left:0}.tw{border-radius:0}th{cursor:default}h2{break-after:avoid}}
'@
    $js = @'
document.querySelectorAll('table.sortable').forEach(function(t){
  t.querySelectorAll('th').forEach(function(th,i){
    th.addEventListener('click',function(){
      var asc=!th.classList.contains('asc');
      t.querySelectorAll('th').forEach(function(x){x.classList.remove('asc','desc')});
      th.classList.add(asc?'asc':'desc');
      var body=t.tBodies[0],rows=Array.prototype.slice.call(body.rows);
      rows.sort(function(a,b){
        var x=a.cells[i].getAttribute('data-sort')||a.cells[i].textContent.trim(),y=b.cells[i].getAttribute('data-sort')||b.cells[i].textContent.trim();
        var nx=parseFloat(x),ny=parseFloat(y),num=!isNaN(nx)&&!isNaN(ny)&&/^-?[\d.]+$/.test(x)&&/^-?[\d.]+$/.test(y);
        var c=num?nx-ny:x.localeCompare(y);
        return asc?c:-c;
      });
      rows.forEach(function(r){body.appendChild(r)});
    });
  });
});
window.addEventListener('beforeprint',function(){document.querySelectorAll('details').forEach(function(d){d.setAttribute('open','')})});
'@

    [void]$sb.Append("<!DOCTYPE html><html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width,initial-scale=1"">")
    [void]$sb.Append("<title>Microsoft 365 investigation - $(& $h $run.Domain)</title><style>$css</style></head><body><div class=""wrap"">")
    [void]$sb.Append("<header><h1>Microsoft 365 account investigation</h1><p>$(& $h $run.Domain) &middot; $($mb.Count) mailbox(es) &middot; $(& $h $run.DaysBack) days back</p>")
    [void]$sb.Append("<div class=""meta""><div><b>Window (UTC)</b>$(& $h $run.WindowFrom) to $(& $h $run.WindowTo)</div><div><b>Generated</b>$(& $h $run.Generated)</div><div><b>Graph sign-in</b>$(& $h $run.GraphAccount)</div><div><b>Tool</b>LTI MS365 Investigation Utility $(& $h $run.Version)</div></div></header>")

    [void]$sb.Append("<div class=""cards"">")
    foreach ($pair in @(@('Critical', 'crit'), @('High', 'high'), @('Medium', 'med'), @('Low', 'low'), @('None', 'none'))) {
        $label = $pair[0]
        if ($label -eq 'None') { $label = 'Nothing flagged' }
        [void]$sb.Append("<div class=""card $($pair[1])""><div class=""n"">$(& $count $pair[0])</div><div class=""l"">$label</div></div>")
    }
    [void]$sb.Append("</div>")

    # What limits this report.
    $limits = [System.Collections.Generic.List[string]]::new()
    if (@($run.StepsSkipped).Count -gt 0) { $limits.Add("Steps not run: $($run.StepsSkipped -join '; ')") }
    foreach ($line in @($run.LogReach)) { if ($line -match 'NOTHING older|could not') { $limits.Add($line) } }
    if ($run.GraphAccount -match '^No ') { $limits.Add("No Microsoft Graph sign-in: MFA, the Entra sign-in log and app consents were not checked.") }
    elseif ($run.Extended -notmatch '^Yes') { $limits.Add("Extended Graph permissions were not granted: MFA enforcement (Conditional Access) and current app consents were not checked.") }
    $failed = @($mb | Where-Object { @($_.F.Errors).Count -gt 0 })
    if ($failed.Count -gt 0) { $limits.Add("$($failed.Count) mailbox(es) had checks that failed - see their details.") }
    if ($limits.Count -gt 0) {
        [void]$sb.Append("<div class=""note""><b>What this report could not cover</b><ul>")
        foreach ($l in $limits) { [void]$sb.Append("<li>$(& $h $l)</li>") }
        [void]$sb.Append("</ul></div>")
    }

    # Ranking table.
    [void]$sb.Append("<h2>Mailboxes by severity</h2><div class=""tw""><table class=""sortable""><thead><tr><th>Mailbox</th><th>Severity</th><th>Score</th><th>MFA</th><th>Enforced</th><th>Sign-ins ok / failed</th><th>Countries</th><th>Main reasons</th></tr></thead><tbody>")
    $order = @{ Critical = 0; High = 1; Medium = 2; Low = 3; None = 4 }
    foreach ($m in $mb) {
        $f = $m.F
        $top = (@($f.Reasons | Where-Object { $_.Points -gt 0 } | Select-Object -First 3 | ForEach-Object { $_.Text }) -join '; ')
        [void]$sb.Append("<tr><td><b>$(& $h $f.DisplayName)</b><br>$(& $h $f.UPN)</td><td data-sort=""$($order[[string]$f.Level])""><span class=""chip $($f.Level)"">$(& $h $f.Level)</span></td><td>$($f.Score)</td><td>$(& $h $f.MFAStatus)</td><td>$(& $h $f.MFAEnforcement)</td><td>$($f.SignInsOK) / $($f.SignInsFailed)</td><td>$(& $h $f.SignInCountries)</td><td>$(& $h $top)</td></tr>")
    }
    [void]$sb.Append("</tbody></table></div>")

    # Tenant-wide.
    [void]$sb.Append("<h2>Tenant-wide findings</h2><h3>Is MFA enforced?</h3>")
    $enf = $Model.Enforcement
    if (-not $enf -or -not $enf.Checked) { [void]$sb.Append("<p>Not checked. $(& $h $(if ($enf) { $enf.Reason } else { 'The MFA step did not run.' }))</p>") }
    else {
        $sd = "unknown"
        if ($enf.SecurityDefaults -eq $true) { $sd = "enabled - every user is covered" } elseif ($enf.SecurityDefaults -eq $false) { $sd = "disabled" }
        [void]$sb.Append("<p>Security Defaults: <b>$sd</b>. Conditional Access: $(@($enf.Policies).Count) policy(ies), $(@($enf.MfaPolicies).Count) enabled and requiring MFA at sign-in$(if ($enf.ReportOnly -gt 0) { "; $($enf.ReportOnly) report-only (enforcing nothing)" }).</p>")
        [void]$sb.Append((ConvertTo-LTIHtmlTable -Rows $enf.Rows -Columns @('Policy', 'State', 'Grant', 'Users', 'Apps', 'Conditions', @{ Name = 'CountsAsSignInMFA'; Label = 'Requires MFA at sign-in' })))
    }

    [void]$sb.Append("<h3>Mail forwarding</h3>")
    $fw = @($Model.Forwarding)
    $look = @($fw | Where-Object { $_.LookAlikeOf })
    if ($look.Count -gt 0) {
        [void]$sb.Append("<div class=""note bad""><b>Forwarding to a look-alike domain</b><ul>")
        foreach ($r in $look) { [void]$sb.Append("<li>$(& $h $r.UPN) &rarr; $(& $h $r.TargetAddress) (resembles $(& $h $r.LookAlikeOf))</li>") }
        [void]$sb.Append("</ul></div>")
    }
    if ($fw.Count -eq 0) { [void]$sb.Append("<p>No mailbox forwarding, forwarding inbox rules or redirecting transport rules were found.</p>") }
    else { [void]$sb.Append((ConvertTo-LTIHtmlTable -Rows $fw -Max 80 -Columns @(@{ Name = 'UPN'; Label = 'Mailbox' }, 'Source', @{ Name = 'TargetAddress'; Label = 'Forwards to' }, 'External', @{ Name = 'LookAlikeOf'; Label = 'Resembles' }, @{ Name = 'SignInBlocked'; Label = 'Sign-in blocked' }, 'Note'))) }

    [void]$sb.Append("<h3>Third-party apps with access to mail, files or the directory</h3>")
    $apps = $Model.Apps
    if (-not $apps) { [void]$sb.Append("<p>Not checked (the app step did not run).</p>") }
    elseif (-not $apps.GrantsChecked) { [void]$sb.Append("<p>Current consents not checked. $(& $h $apps.GrantsReason)</p>") }
    elseif (@($Model.ThirdPartyGrants).Count -eq 0) { [void]$sb.Append("<p>None. No non-Microsoft app holds mail, file or directory permissions$(if (-not $apps.AppOnlyChecked) { ' (delegated permissions only - app-only permissions could not be read)' }).</p>") }
    else { [void]$sb.Append((ConvertTo-LTIHtmlTable -Rows $Model.ThirdPartyGrants -Max 60 -Columns @('App', 'Publisher', @{ Name = 'ConsentType'; Label = 'Consent' }, @{ Name = 'Principal'; Label = 'User' }, @{ Name = 'RiskyScopes'; Label = 'Sensitive permissions' }, @{ Name = 'KnownAbused'; Label = 'Seen in compromises' }, @{ Name = 'KnownMailClient'; Label = 'Well-known mail app' }))) }

    # Per mailbox.
    [void]$sb.Append("<h2>Mailbox details</h2>")
    foreach ($m in $mb) {
        $f = $m.F
        $open = ""
        if (@('Critical', 'High') -contains $f.Level) { $open = " open" }
        [void]$sb.Append("<details$open><summary><span class=""chip $($f.Level)"">$(& $h $f.Level)</span><span>$(& $h $f.DisplayName) &middot; $(& $h $f.UPN)</span><span class=""score"">score $($f.Score)</span></summary><div class=""body"">")

        if (@($f.Reasons).Count -gt 0) {
            [void]$sb.Append("<h3>Why this score</h3><ul class=""why"">")
            foreach ($r in @($f.Reasons)) { [void]$sb.Append("<li><span class=""pts"">+$($r.Points)</span>$(& $h $r.Text)</li>") }
            [void]$sb.Append("</ul>")
        } else { [void]$sb.Append("<p>Nothing flagged.</p>") }

        [void]$sb.Append("<dl class=""kv"">")
        $kv = [ordered]@{
            "Mailbox type"        = "$($f.MailboxType); sign-in allowed: $(if ($f.AccountEnabled) { $f.AccountEnabled } else { 'unknown' })"
            "MFA"                 = $m.Mfa.Text
            "MFA enforcement"     = $(if ($f.MFAEnforcement) { "$($f.MFAEnforcement) - $($f.MFAEnforcedBy)" } else { "not checked" })
            "Sign-ins (audit log)" = "$($f.SignInsOK) ok / $($f.SignInsFailed) failed$(if ($f.SignInsInterrupted -gt 0) { " / $($f.SignInsInterrupted) interrupted (prompts, expired sessions)" })"
            "Entra sign-in log"   = "$($f.EntraSignInLog)$(if ($f.EntraInteractive) { "; interactive $($f.EntraInteractive)" })$(if ($f.EntraNonInteractive) { "; non-interactive $($f.EntraNonInteractive)" })"
            "By country (ok / failed)" = $f.SignInCountries
            "Forwarding"          = $(if ($f.ForwardingAll) { $f.ForwardingAll } elseif ($f.ForwardingActive) { $f.ForwardingTarget } else { "none found" })
            "Inbox rules"         = "$($f.TotalRules) total, $($f.SuspiciousRules) flagged, $($f.HiddenRules) hidden"
            "Apps"                = "$($f.AppStatus)$(if ($f.AppStatus -ne 'Not run') { "; $($f.AppGrants) consent(s), $($f.AppEvents) change(s) in the window" })"
            "Outbound mail"       = "$($f.OutboundProfile)$(if ($f.OutboundBurst) { " - BURST: $($f.OutboundBurstReason)" })"
            "Protocols"           = $f.Protocols
        }
        foreach ($k in $kv.Keys) { if ($kv[$k]) { [void]$sb.Append("<dt>$(& $h $k)</dt><dd>$(& $h $kv[$k])</dd>") } }
        [void]$sb.Append("</dl>")

        if (@($f.Indicators).Count -gt 0) { [void]$sb.Append("<h3>Sign-in indicators</h3>" + (ConvertTo-LTIHtmlTable -Rows $f.Indicators -Columns @('Severity', 'Indicator', 'Count', @{ Name = 'FirstSeen'; Label = 'First seen' }, @{ Name = 'LastSeen'; Label = 'Last seen' }, 'IPs', 'Detail'))) }
        if (@($m.IPRows).Count -gt 0) {
            # ok / failed pairs share a column so the table fits a page.
            $ipView = foreach ($ipr in @($m.IPRows)) {
                [PSCustomObject]@{
                    IP = $ipr.IP; Where = (@($ipr.City, $ipr.Country) | Where-Object { $_ }) -join ', '
                    Network = $(if ($ipr.ASN) { "AS$($ipr.ASN) $($ipr.ASName)".Trim() } else { "" })
                    Audit = "$($ipr.AuditOK) / $($ipr.AuditFailed)"; Interactive = "$($ipr.InteractiveOK) / $($ipr.InteractiveFailed)"; Background = "$($ipr.NonInteractiveOK) / $($ipr.NonInteractiveFailed)"
                    FirstSeen = $ipr.FirstSeen; LastSeen = $ipr.LastSeen
                }
            }
            [void]$sb.Append("<h3>Sign-in IPs <span class=""hint"">(counts are ok / failed)</span></h3>" + (ConvertTo-LTIHtmlTable -Rows $ipView -Max 25 -Columns @('IP', @{ Name = 'Where'; Label = 'Location' }, 'Network', @{ Name = 'Audit'; Label = 'Audit log' }, @{ Name = 'Interactive'; Label = 'Interactive' }, @{ Name = 'Background'; Label = 'Background' }, @{ Name = 'FirstSeen'; Label = 'First seen' }, @{ Name = 'LastSeen'; Label = 'Last seen' })))
        }
        if (@($m.MfaMethods).Count -gt 0) { [void]$sb.Append("<h3>Registered sign-in methods</h3>" + (ConvertTo-LTIHtmlTable -Rows $m.MfaMethods -Columns @('Method', @{ Name = 'CountsAsMFA'; Label = 'Counts as MFA' }, 'Detail', @{ Name = 'Created'; Label = 'Registered' }, @{ Name = 'LastUsed'; Label = 'Last used' }))) }
        if (@($m.MfaAudit).Count -gt 0) { [void]$sb.Append("<h3>MFA / sign-in method changes</h3>" + (ConvertTo-LTIHtmlTable -Rows $m.MfaAudit -Max 30 -Columns @(@{ Name = 'Timestamp'; Label = 'Time (UTC)' }, 'Activity', @{ Name = 'InitiatedBy'; Label = 'By' }, @{ Name = 'InitiatedByIP'; Label = 'IP' }, 'Result', @{ Name = 'ResultReason'; Label = 'Detail' }))) }
        $flagged = @($f.RuleDetails | Where-Object { $_ -and $_.Suspicious })
        if ($flagged.Count -gt 0) { [void]$sb.Append("<h3>Flagged inbox rules</h3>" + (ConvertTo-LTIHtmlTable -Rows $flagged -Columns @(@{ Name = 'Name'; Label = 'Rule' }, 'Enabled', 'Hidden', @{ Name = 'Flags'; Label = 'Why it is flagged' }))) }
        if (@($f.AppRows).Count -gt 0) { [void]$sb.Append("<h3>Apps</h3>" + (ConvertTo-LTIHtmlTable -Rows $f.AppRows -Max 25 -Columns @('Kind', @{ Name = 'Timestamp'; Label = 'Time (UTC)' }, 'App', 'Publisher', @{ Name = 'RiskyScopes'; Label = 'Sensitive permissions' }, 'Activity', @{ Name = 'InitiatedBy'; Label = 'By' }, 'IP'))) }
        if (@($m.Notable).Count -gt 0) {
            $rows = foreach ($n in @($m.Notable | Select-Object -First 60)) { [PSCustomObject]@{ Time = $n.Time.ToString("yyyy-MM-dd HH:mm:ss"); Source = $n.Source; Event = $n.Event; Count = $n.Count; IP = $n.IP; Detail = $n.Detail } }
            [void]$sb.Append("<h3>Notable events</h3>" + (ConvertTo-LTIHtmlTable -Rows $rows -Columns @(@{ Name = 'Time'; Label = 'Time (UTC)' }, 'Source', 'Event', 'Count', 'IP', 'Detail')))
            if (@($m.Notable).Count -gt 60) { [void]$sb.Append("<p class=""more"">$(@($m.Notable).Count - 60) more in 00_Timeline.csv.</p>") }
        }
        if (@($f.Errors).Count -gt 0) { [void]$sb.Append("<div class=""note bad""><b>Checks that failed for this mailbox</b><ul>" + ((@($f.Errors) | ForEach-Object { "<li>$(& $h $_)</li>" }) -join '') + "</ul></div>") }
        [void]$sb.Append("</div></details>")
    }

    [void]$sb.Append("<footer><p>All times are UTC. ""Not checked"" and ""Unknown"" mean no data, never clean. The severity score is a weighted checklist that ranks mailboxes for attention; the reasons listed are the evidence. Audit-log and Entra sign-in counts overlap and must not be added together. Supporting data: the CSV files beside this report.</p></footer>")
    [void]$sb.Append("</div><script>$js</script></body></html>")
    return $sb.ToString()
}

# -----------------------------------------------------------------------------
#  RUN BUTTON
# -----------------------------------------------------------------------------
$btnRun.Add_Click({
    if ($lstMailboxes.SelectedItems.Count -eq 0) { [System.Windows.MessageBox]::Show("Select at least one mailbox.","Required","OK","Warning"); return }
    $enabledSteps=@{}; $enabledCount=0
    for($i=1;$i-le 19;$i++){$enabledSteps[$i]=($chkSteps[$i].IsChecked -eq $true);if($enabledSteps[$i]){$enabledCount++}}
    if ($enabledCount -eq 0) { [System.Windows.MessageBox]::Show("Select at least one step.","Required","OK","Warning"); return }

    $selectedUPNs=[System.Collections.Generic.List[string]]::new()
    foreach ($si in $lstMailboxes.SelectedItems) { if($si -match '<(.+?)>'){$selectedUPNs.Add($Matches[1])} }
    if ($selectedUPNs.Count -eq 0) { [System.Windows.MessageBox]::Show("Could not parse mailboxes.","Error","OK","Error"); return }

    # Steps 17 and 18 read Microsoft Graph, and the Graph sign-in cannot be started
    # from inside a run. Say so now rather than produce a report full of "not checked".
    $cachedForPrompt = @($script:allMFAData | ForEach-Object { $_.UPN })
    $needsGraph = $enabledSteps[18] -or $enabledSteps[19] -or ($enabledSteps[17] -and @($selectedUPNs | Where-Object { $cachedForPrompt -notcontains $_ }).Count -gt 0)
    if ($needsGraph -and -not (Test-LTIGraphToken)) {
        $answer = [System.Windows.MessageBox]::Show("Steps 17 (MFA), 18 (Entra sign-in log) and 19 (app consents) need a Microsoft Graph sign-in, and there isn't one yet.`n`nTo include them: click No, click 'Refresh MFA', complete the sign-in, then run again.`n`nRun now without them?","Graph sign-in needed","YesNo","Warning")
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
    if (($enabledSteps[17] -or $enabledSteps[18] -or $enabledSteps[19]) -and (Test-LTIGraphToken)) {
        $script:LTILogReach = @{ SignIns = (Test-LTIEntraLogReach -Log SignIns); Audit = (Test-LTIEntraLogReach -Log Audit) }
        foreach ($line in (Get-LTILogReachText -Reach $script:LTILogReach -DaysBack $daysBack)) {
            if ($line -match 'NOTHING older') { Add-Log "[WARN] $line" } else { Add-Log $line }
        }
    }

    # --- Tenant-level preparation (once per run) ---
    $script:allForwarding.Clear(); $script:LTIAppContext = $null
    $script:LTIAcceptedDomains = @()
    try { $script:LTIAcceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() } | Where-Object { $_ }) }
    catch { Add-Log "[WARN] The tenant's accepted domains could not be read, so internal and external addresses cannot be told apart: $_" }
    $script:LTIOrgSmtpAuthDisabled = $null
    try { $script:LTIOrgSmtpAuthDisabled = (Get-TransportConfig -ErrorAction Stop).SmtpClientAuthenticationDisabled } catch { Write-Log "Get-TransportConfig failed: $_" "WARN" }
    if ($enabledSteps[3] -or $enabledSteps[4] -or $enabledSteps[5]) {
        $fwPaths = Get-LTITenantForwardingInventory
        Add-Log "Forwarding inventory: $fwPaths mailbox-level / transport-rule forwarding path(s) across $($script:allMailboxes.Count) loaded mailbox(es)"
    }
    if ($enabledSteps[19]) {
        Add-Log ""; Add-Log "======================================================================"; Add-Log "  19. App Consents (tenant-level, runs once)"; Add-Log "======================================================================"
        if (Test-LTIGraphToken) {
            $script:LTIAppContext = Get-LTIAppContext -Start $startDate
            if ($script:LTIAppContext.GrantsChecked) { $null = Export-ResultSet -Name "Tenant app grants" -FileName "19a_Tenant_App_Grants.csv" -OutFolder $rootFolder -Data @($script:LTIAppContext.Grants) }
            if ($script:LTIAppContext.AuditChecked)  { $null = Export-ResultSet -Name "Tenant app audit events" -FileName "19b_Tenant_App_Audit_Events.csv" -OutFolder $rootFolder -Data @($script:LTIAppContext.AuditRows) }
        } else {
            Add-Log "  [SKIP] No Graph sign-in. Click 'Refresh MFA' and sign in before running to include this step."
        }
        Flush-UI
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
            if ($script:MFAContext -and $script:MFAContext.Enforcement -and $script:MFAContext.Enforcement.Checked) {
                $null = Export-ResultSet -Name "MFA Enforcement Policies" -FileName "17c_MFA_Enforcement_Policies.csv" -OutFolder $rootFolder -Data @($script:MFAContext.Enforcement.Rows)
                $notEnforced = @($mfaExportData | Where-Object { $_.MFAEnforcement -eq "NotEnforced" -and $_.AccountEnabled -ne "False" })
                if ($notEnforced.Count -gt 0) { Add-Log "  [WARN] *** MFA IS NOT ENFORCED FOR $($notEnforced.Count) SELECTED USER(S) WHO CAN SIGN IN ***"; foreach ($u in ($notEnforced | Select-Object -First 15)) { Add-Log "    - $($u.DisplayName) ($($u.UPN))" } }
            }
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
            Add-Log ""; Add-Log "  >> Collected. The ranking follows once every mailbox is done."
        } catch { Add-Log "  >> FAILED: $_" }
        Flush-UI
    }

    # ================= AFTER EVERY MAILBOX: label, review, rank, report =================
    Add-Log ""; Add-Log "======================================================================"; Add-Log "  RESULTS"; Add-Log "======================================================================"
    $lblProgress.Text = "Building the reports..."; Flush-UI

    # Sign-in IPs: one lookup for every unlabelled IP in the run, then one row per mailbox + IP.
    if ($script:allIPRollup.Count -gt 0) {
        Update-LTIRollupGeo -Findings $allFindings
        @($script:allIPRollup) | Export-Csv -Path (Join-Path $rootFolder "_SIGNIN_IP_SUMMARY.csv") -NoTypeInformation -Encoding UTF8
        Add-Log "Sign-in IP summary: $($script:allIPRollup.Count) mailbox/IP row(s) -> _SIGNIN_IP_SUMMARY.csv"
    }

    # Forwarding: external and look-alike targets across the tenant.
    Complete-LTIForwardingReview -Findings $allFindings
    if ($script:allForwarding.Count -gt 0) {
        @($script:allForwarding) | Export-Csv -Path (Join-Path $rootFolder "_FORWARDING_REVIEW.csv") -NoTypeInformation -Encoding UTF8
        Add-Log "Forwarding review: $($script:allForwarding.Count) path(s) -> _FORWARDING_REVIEW.csv"
        foreach ($row in @($script:allForwarding | Where-Object { $_.LookAlikeOf })) { Add-Log "  [WARN] *** LOOK-ALIKE FORWARDING TARGET: $($row.UPN) -> $($row.TargetAddress) (resembles $($row.LookAlikeOf)) ***" }
    }

    # Severity and the per-mailbox timeline.
    foreach ($f in $allFindings) {
        $sev = Get-LTISeverity -F $f
        $f.Score = $sev.Score; $f.Level = $sev.Level; $f.Reasons = $sev.Reasons; $f.ReasonText = $sev.ReasonText
        if (@($f.TimelineRows).Count -gt 0 -and $f.OutputFolder) {
            try { Export-LTITimeline -Rows $f.TimelineRows -Path (Join-Path $f.OutputFolder "00_Timeline.csv") } catch { Add-Log "  [WARN] Timeline for $($f.UPN) could not be written: $_" }
        }
    }
    $ranked = @($allFindings | Sort-Object -Property @{ Expression = 'Score'; Descending = $true }, @{ Expression = 'UPN' })
    $levelCount = @{}; foreach ($lv in @('Critical', 'High', 'Medium', 'Low', 'None')) { $levelCount[$lv] = @($ranked | Where-Object { $_.Level -eq $lv }).Count }
    $alertCount = $levelCount['Critical'] + $levelCount['High'] + $levelCount['Medium']

    Add-Log ""
    foreach ($f in $ranked) {
        Add-Log ("[{0,-8} {1,3}] {2}" -f ([string]$f.Level).ToUpper(), $f.Score, $f.UPN)
        foreach ($r in @($f.Reasons | Where-Object { $_.Points -gt 0 } | Select-Object -First 4)) { Add-Log "        +$($r.Points) $($r.Text)" }
    }

    # --- Master CSV (one row per mailbox, most serious first) ---
    $csvPath=Join-Path $rootFolder "_MASTER_SUMMARY.csv"
    # MFAEnabled is True / False, or blank when MFA was not checked or the lookup failed (see MFAStatus).
    $csvData = foreach ($f in $ranked) {
        $mfa = Get-LTIMFAVerdict -Findings $f
        [PSCustomObject]@{
            UPN = $f.UPN; DisplayName = $f.DisplayName; Severity = $f.Level; Score = $f.Score; Reasons = $f.ReasonText
            MFAEnabled = $mfa.EnabledText; MFAStatus = $f.MFAStatus; MFAMethods = $f.MFAMethods
            MFAEnforcement = $f.MFAEnforcement; MFAEnforcedBy = $f.MFAEnforcedBy; NewMFAMethods = $f.NewMFAMethods; SignInAllowed = $f.AccountEnabled
            SignInsOK = $f.SignInsOK; SignInsFailed = $f.SignInsFailed; SignInsInterrupted = $f.SignInsInterrupted; UniqueIPs = $f.UniqueIPs; SignInIPs = $f.SignInIPs
            SuccessCountries = $f.SuccessCountries; SignInCountries = $f.SignInCountries
            SignInIndicators = $f.SignInIndicators
            EntraSignInLog = $f.EntraSignInLog; EntraInteractive = $f.EntraInteractive; EntraNonInteractive = $f.EntraNonInteractive; NonInteractiveIPs = $f.NonInteractiveIPs
            ForwardingActive = $f.ForwardingActive; ForwardingTarget = $f.ForwardingTarget; ForwardingExternal = $f.ForwardingExternal; ForwardingLookAlike = $f.ForwardingLookAlike
            SuspiciousRules = $f.SuspiciousRules; HiddenRules = $f.HiddenRules; TotalRules = $f.TotalRules; RuleFlags = $f.RuleFlags
            OAuthConsents = $f.OAuthConsents; AppCheck = $f.AppStatus; AppGrants = $f.AppGrants; AppChangesInWindow = $f.AppEvents; RiskyApps = $f.RiskyApps; AbusedApps = $f.AbusedApps; MailApps = $f.MailApps
            AdminActions = $f.AdminActions; FileEvents = $f.FileEvents
            OutboundMail = $f.OutboundMail; OutboundProfile = $f.OutboundProfile; OutboundBurst = $f.OutboundBurstReason
            Protocols = $f.Protocols; AuditEnabled = $f.AuditEnabled; Errors = ($f.Errors -join '; ')
        }
    }
    @($csvData)|Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8; Add-Log ""; Add-Log "Master CSV: $csvPath"

    # --- Master TXT ---
    $txtPath=Join-Path $rootFolder "_MASTER_SUMMARY.txt"; $sl=[System.Collections.Generic.List[string]]::new()
    $sl.Add("LTI MS365 Investigation Utility - Master Summary"); $sl.Add("================================================")
    $sl.Add("Generated : $(Get-LTIStamp)"); $sl.Add("Date Range: $(Format-LTIDateTime $startDate) to $(Format-LTIDateTime $endDate) ($daysBack days back; all times in this report are UTC)")
    $sl.Add("Steps Run : $enabledCount  (tool $($script:LTIVersion))"); $sl.Add("Mailboxes : $total investigated"); $sl.Add("")
    $sl.Add("ALERTS  : $alertCount mailbox(es) at Medium or above ($($levelCount['Critical']) critical, $($levelCount['High']) high, $($levelCount['Medium']) medium, $($levelCount['Low']) low, $($levelCount['None']) nothing flagged)")
    $enfChecked = ($script:MFAContext -and $script:MFAContext.Enforcement -and $script:MFAContext.Enforcement.Checked)
    if ($enfChecked) { $sl.Add("MFA NOTE: 'Enabled' means an MFA-capable method is registered. The 'MFA enforcement' line says whether Security Defaults, Conditional Access or per-user MFA makes the user use it.") }
    else { $sl.Add("MFA NOTE: 'Enabled' means an MFA-capable method is registered. It does not prove MFA is enforced - that check needs the extended Graph permissions and was not run.") }
    $sl.Add("IP NOTE : Country / ASN come from Microsoft's sign-in geolocation (step 18)$(if($script:LTIGeoLookup){'; IPs it did not label carry the country their address block is REGISTERED in, which is not a location'}). Audit-log and Entra-log counts overlap for interactive sign-ins - do not add them. Details: _SIGNIN_IP_SUMMARY.csv")
    foreach($line in (Get-LTILogReachText -Reach $script:LTILogReach -DaysBack $daysBack)){$sl.Add("LOG NOTE: $line")}
    $sl.Add("COUNTRY : 'By country' is sign-ins that succeeded / failed in each country. The two logs overlap for interactive sign-ins, so per address the larger count is used, plus background (non-interactive) sign-ins. Prompts and expired sessions are in neither number.")
    $sl.Add("SCORE   : 0-100, a weighted checklist that ranks mailboxes for attention. It is not a probability of compromise; the 'Why' lines are the evidence.")
    # Tenant-wide findings that belong to no single mailbox.
    if ($enfChecked) {
        $enfCtx = $script:MFAContext.Enforcement
        if ($enfCtx.SecurityDefaults -eq $true) { $sl.Add("TENANT  : MFA is enforced for everyone by Security Defaults.") }
        else { $sl.Add("TENANT  : Security Defaults $(if ($enfCtx.SecurityDefaults -eq $false) { 'off' } else { 'not readable' }); $(@($enfCtx.MfaPolicies).Count) Conditional Access policy(ies) enabled and requiring MFA$(if ($enfCtx.ReportOnly -gt 0) { "; $($enfCtx.ReportOnly) report-only (enforce nothing)" }). Details: 17c_MFA_Enforcement_Policies.csv") }
    }
    foreach ($row in @($script:allForwarding | Where-Object { $_.LookAlikeOf })) { $sl.Add("TENANT  : *** LOOK-ALIKE FORWARDING: $($row.UPN) -> $($row.TargetAddress) (resembles $($row.LookAlikeOf)) via $($row.Source)") }
    $extFw = @($script:allForwarding | Where-Object { $_.External -eq 'True' -and -not $_.Selected })
    if ($extFw.Count -gt 0) { $sl.Add("TENANT  : $($extFw.Count) external forwarding path(s) on mailboxes or transport rules that were NOT investigated in this run - see _FORWARDING_REVIEW.csv") }
    if ($script:LTIAppContext -and $script:LTIAppContext.GrantsChecked) {
        $tp = @($script:LTIAppContext.Grants | Where-Object { -not $_.Microsoft -and $_.RiskyScopes })
        $tpAppOnly = @($tp | Where-Object { $_.ConsentType -eq 'Application' })
        $tpAbused = @($script:LTIAppContext.Grants | Where-Object { $_.KnownAbused })
        if ($tpAbused.Count -gt 0) { $sl.Add("TENANT  : *** App(s) often seen in mailbox compromises have consent: $(@($tpAbused | ForEach-Object { "$($_.App) ($($_.Principal))" } | Select-Object -Unique) -join '; ')") }
        if ($tpAppOnly.Count -gt 0) { $sl.Add("TENANT  : *** Non-Microsoft app(s) with tenant-wide (app-only) mail / file access: $(@($tpAppOnly | ForEach-Object { "$($_.App) [$($_.RiskyScopes)]" }) -join '; ')") }
        $tpMail = @($tp | Where-Object { $_.KnownMailClient -and -not $_.KnownAbused }).Count
        $sl.Add("TENANT  : $($tp.Count) non-Microsoft app grant(s) with mail / file / directory access$(if ($tpMail -gt 0) { " ($tpMail of them well-known mail apps such as Apple Mail)" }) - see 19a_Tenant_App_Grants.csv")
    }
    $sl.Add("")
    foreach ($f in $ranked) {
        $mfa = Get-LTIMFAVerdict -Findings $f
        $tag = "[OK]"
        if ($f.Level -ne "None") { $tag = "[{0} {1}]" -f ([string]$f.Level).ToUpper(), $f.Score }
        $sl.Add("$tag $($f.UPN) ($($f.DisplayName))")
        $first = $true
        foreach ($r in @($f.Reasons)) { $sl.Add("      $(if ($first) { 'Why: ' } else { '     ' })+$($r.Points) $($r.Text)"); $first = $false }
        $sl.Add("      MFA: $($mfa.Text)")
        if ($f.MFAEnforcement) { $sl.Add("      MFA enforcement: $($f.MFAEnforcement) - $($f.MFAEnforcedBy)") }
        $sl.Add("      Sign-ins: $($f.SignInsOK) ok / $($f.SignInsFailed) failed / $($f.UniqueIPs) IPs$(if ($f.SignInsInterrupted -gt 0) { " (+$($f.SignInsInterrupted) interrupted - prompts and expired sessions, not failures)" })")
        if($f.SignInIPs){$sl.Add("      IPs: $($f.SignInIPs)")}
        if($f.EntraSignInLog -ne "Not run"){
            if($f.EntraInteractive){$sl.Add("      Entra log: interactive $($f.EntraInteractive)$(if($f.EntraNonInteractive){" | non-interactive $($f.EntraNonInteractive)"})")}
            if($f.EntraSignInLog -ne "OK" -and $f.EntraSignInLog -ne "OK - tenant log only holds the last 7 days"){$sl.Add("      Entra log status: $($f.EntraSignInLog)")}
            if($f.NonInteractiveIPs){$sl.Add("      Non-interactive IPs: $($f.NonInteractiveIPs)")}
        }
        if($f.SignInCountries){$sl.Add("      By country: $($f.SignInCountries)")}
        if($f.ForwardingAll){$sl.Add("      Forwarding: $($f.ForwardingAll)")}elseif($f.ForwardingActive){$sl.Add("      Forwarding: $($f.ForwardingTarget)")}
        if($f.TotalRules -gt 0){$sl.Add("      Inbox rules: $($f.TotalRules) total, $($f.SuspiciousRules) flagged, $($f.HiddenRules) hidden")}
        if($f.AppStatus -ne "Not run"){$sl.Add("      Apps: $($f.AppStatus); $($f.AppGrants) consent(s) by this user, $($f.AppEvents) change(s) in the window")}
        if($f.OutboundProfile){$sl.Add("      Outbound: $($f.OutboundProfile)")}
        if($f.Protocols){$sl.Add("      Protocols: $($f.Protocols)")}
        if($f.AuditEnabled -eq $false){$sl.Add("      *** Auditing DISABLED")}elseif($null -eq $f.AuditEnabled){$sl.Add("      Auditing: not checked")}
        $sl.Add("")
    }
    ($sl -join "`r`n")|Out-File -FilePath $txtPath -Encoding UTF8

    # --- Evidence brief + client report ---
    try {
        $stepNames = @{ 1='Sign-in events (audit log)'; 2='Mailbox activity'; 3='Inbox rules'; 4='Mailbox forwarding'; 5='Transport rules'; 6='Permissions / delegates'; 7='Auto-reply'; 8='Mobile devices'; 9='App consent events (audit log)'; 10='Rule changes'; 11='SharePoint / OneDrive files'; 12='Admin actions'; 13='eDiscovery'; 14='Message trace + outbound profile'; 15='Mailbox audit + protocol settings'; 16='Catch-all audit dump'; 17='MFA status + enforcement'; 18='Entra sign-in log + indicators'; 19='App consents (Graph)' }
        $graphAccount = "No Graph sign-in - MFA, the Entra sign-in log and app consents were not checked"
        if ($script:GraphToken) { $graphAccount = [string]$script:GraphSignedInAs }
        $extendedText = "No - MFA enforcement (Conditional Access) and current app consents were not checked"
        if (Test-LTIExtendedScopes) { $extendedText = "Yes" }
        $runInfo = @{
            Domain = ([string]$txtDomain.Text).Trim(); Generated = (Get-LTIStamp); DaysBack = $daysBack; Version = $script:LTIVersion
            WindowFrom = (Format-LTIDateTime $startDate); WindowTo = (Format-LTIDateTime $endDate); MailboxesLoaded = @($script:allMailboxes).Count
            StepsRun = @(1..19 | Where-Object { $enabledSteps[$_] } | ForEach-Object { "$_ $($stepNames[$_])" })
            StepsSkipped = @(1..19 | Where-Object { -not $enabledSteps[$_] } | ForEach-Object { "$_ $($stepNames[$_])" })
            GraphAccount = $graphAccount; Extended = $extendedText
            LogReach = @(Get-LTILogReachText -Reach $script:LTILogReach -DaysBack $daysBack)
            GeoLookup = $(if ($script:LTIGeoLookup) { "On (Team Cymru; registered country, not location)" } else { "Off" })
        }
        $model = Get-LTIReportModel -Findings $ranked -Run $runInfo
        ((Get-LTIBriefLines -Model $model) -join "`r`n") | Out-File -FilePath (Join-Path $rootFolder "_AI_BRIEF.md") -Encoding UTF8
        (Get-LTIHtmlReport -Model $model) | Out-File -FilePath (Join-Path $rootFolder "_REPORT.html") -Encoding UTF8
        Add-Log "Evidence brief: _AI_BRIEF.md   (the one file to hand to an analyst)"
        Add-Log "Client report : _REPORT.html"
    } catch {
        Write-Log "Report writer error: $_ @ line $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
        Add-Log "[ERROR] The brief / HTML report could not be written: $_  (the CSV and TXT summaries are complete)"
    }

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
