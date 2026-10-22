Add-Type -AssemblyName System.Drawing, System.Windows.Forms

if (-not ("Win32Shots" -as [type])) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32Shots {
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, uint dx, uint dy, int dwData, System.IntPtr dwExtraInfo);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
"@
}

function Save-Window {
    param(
        [Parameter(Mandatory)]$Process,
        [Parameter(Mandatory)][string]$Path,
        [int]$Width = 1400,
        [int]$Height = 880,
        [int]$Pad = 8
    )
    $handle = $Process.MainWindowHandle
    [Win32Shots]::ShowWindow($handle, 9) | Out-Null
    [Win32Shots]::SetWindowPos($handle, [IntPtr](-1), 15, 15, $Width, $Height, 0x0040) | Out-Null
    [Win32Shots]::SetForegroundWindow($handle) | Out-Null
    Start-Sleep -Milliseconds 1200

    $rect = New-Object Win32Shots+RECT
    [Win32Shots]::GetWindowRect($handle, [ref]$rect) | Out-Null
    $w = $rect.Right - $rect.Left - 2 * $Pad
    $h = $rect.Bottom - $rect.Top - 2 * $Pad
    $bitmap = New-Object System.Drawing.Bitmap $w, $h
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($rect.Left + $Pad, $rect.Top + $Pad, 0, 0, (New-Object System.Drawing.Size $w, $h))
    $graphics.Dispose()
    $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bitmap.Dispose()
    return $rect
}

function Click-At {
    param([int]$X, [int]$Y)
    [Win32Shots]::SetCursorPos($X, $Y) | Out-Null
    Start-Sleep -Milliseconds 200
    [Win32Shots]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 80
    [Win32Shots]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
}

