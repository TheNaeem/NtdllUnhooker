using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using NtdllUnhooker.Backend.WinApi;
using Spectre.Console;

namespace NtdllUnhooker.Backend.Extensions;

public static class ProcessExtensions
{
    private static Dictionary<string, IntPtr> _modHandles = new();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryWriteMemory(this Process proc, IntPtr addy, byte[] buf, int size)
    {
        return Kernel32.WriteProcessMemory(proc.Handle, addy, buf, size, out var _);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryWriteMemory(this Process proc, IntPtr addy, byte[] buf)
    {
        return Kernel32.WriteProcessMemory(proc.Handle, addy, buf, buf.Length, out var _);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe bool TryWriteMemory<T>(this Process proc, IntPtr addy, T val) where T : unmanaged
    {
        return Kernel32.WriteProcessMemory(proc.Handle, addy, new IntPtr(&val), sizeof(T), out var _);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteMemory(this Process proc, IntPtr addy, byte[] buf)
    {
        Kernel32.WriteProcessMemory(proc.Handle, addy, buf, buf.Length, out var _);
    }

    public static unsafe bool TryReadMemory<T>(this Process proc, IntPtr addy, out T ret) where T : unmanaged
    {
        ret = new();

        fixed (T* buf = &ret)
        {
            bool result = Kernel32.ReadProcessMemory(proc.Handle, addy, new(buf), sizeof(T), out var _);

            if (!result)
            {
                AnsiConsole.MarkupLine($"[red]ReadProcessMemory for type of {typeof(T).Name} at 0x{addy.ToString("X")} failed with error code 0x{Marshal.GetLastWin32Error().ToString("X")}[/]");
            }

            return result;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryReadArrayMemory<T>(this Process proc, IntPtr addy, int count, out T[] ret) where T : unmanaged
    {
        return proc.TryReadArrayMemory<T>(addy, count, out ret, out _);
    }

    public static unsafe bool TryReadArrayMemory<T>(this Process proc, IntPtr addy, int count, out T[] ret, out IntPtr bytesRead) where T : unmanaged
    {
        var size = sizeof(T) * count;

        ret = new T[count];

        fixed (void* ptr = ret)
        {
            bool result = Kernel32.ReadProcessMemory(proc.Handle, addy, new(ptr), size, out bytesRead);

            if (!result)
            {
                AnsiConsole.MarkupLine($"[red]ReadProcessMemory for an array of {typeof(T).Name} at 0x{addy.ToString("X")} with a count of {count.ToString()} failed with error code 0x{Marshal.GetLastWin32Error().ToString("X")}[/]");
            }

            return result;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static T ReadMemory<T>(this Process proc, IntPtr addy) where T : unmanaged
    {
        proc.TryReadMemory<T>(addy, out var ret);

        return ret;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void ReadMemory<T>(this Process proc, IntPtr addy, T* buf) where T : unmanaged
    {
        Kernel32.ReadProcessMemory(proc.Handle, addy, new(buf), sizeof(T), out var _);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static T[] ReadArrayMemory<T>(this Process proc, IntPtr addy, int count) where T : unmanaged
    {
        proc.TryReadArrayMemory<T>(addy, count, out var ret);

        return ret;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (string, IntPtr) GetModuleFunctionByName(this Process proc, ProcessModule mod, string functionName)
    {
        return proc.GetModuleFunctions(mod).Where(x => x.Item1 == functionName).FirstOrDefault();
    }

    public static IEnumerable<(string, IntPtr)> GetModuleFunctions(this Process proc, ProcessModule mod)
    {
        var header = proc.ReadMemory<IMAGE_DOS_HEADER>(mod.BaseAddress);
        var ntHeaders = proc.ReadMemory<IMAGE_NT_HEADERS64>(mod.BaseAddress + header.e_lfanew);

        var exportDirOffset = ntHeaders.OptionalHeader.ExportTable.VirtualAddress;
        var imageExportDir = proc.ReadMemory<IMAGE_EXPORT_DIRECTORY>(mod.BaseAddress.ResolveOffset(exportDirOffset));

        var functionsOffsets = proc.ReadArrayMemory<uint>(mod.BaseAddress.ResolveOffset(imageExportDir.AddressOfFunctions), (int)imageExportDir.NumberOfNames);
        var namesOffsets = proc.ReadArrayMemory<uint>(mod.BaseAddress.ResolveOffset(imageExportDir.AddressOfNames), (int)imageExportDir.NumberOfNames);
        var nameOrdinalsOffsets = proc.ReadArrayMemory<ushort>(mod.BaseAddress.ResolveOffset(imageExportDir.AddressOfNameOrdinals), (int)imageExportDir.NumberOfNames);

        for (int i = 0; i < imageExportDir.NumberOfNames; i++)
        {
            var functionNameOffset = namesOffsets[i];
            IntPtr functionNameAddy = new(mod.BaseAddress.ToInt64() + functionNameOffset);

            string functionName = Marshal.PtrToStringAnsi(functionNameAddy);

            var functionIdx = nameOrdinalsOffsets[i];

            if (functionIdx >= functionsOffsets.Length)
            {
                break;
            }

            var functionAddyOffset = functionsOffsets[functionIdx];

            yield return (functionName, mod.BaseAddress.ResolveOffset(functionAddyOffset));
        }
    }

    public static void UnhookFunctions(this Process proc, string moduleName, HashSet<string> functionNames)
    {
        foreach (ProcessModule mod in proc.Modules)
        {
            if (moduleName == mod.ModuleName)
            {
                foreach (var fn in proc.GetModuleFunctions(mod))
                {
                    if (!functionNames.TryGetValue(fn.Item1, out var funcName))
                        continue;

                    proc.Unhook(moduleName, funcName, fn.Item2);
                }
            }
        }
    }

    public static unsafe void Unhook(this Process proc, string moduleName, string functionName, IntPtr hookedFunctionAddy, int hookSize = 5)
    {
        IntPtr handle;

        if (_modHandles.ContainsKey(moduleName))
        {
            handle = _modHandles[moduleName];
        }
        else
        {
            handle = Kernel32.LoadLibrary(moduleName);
            _modHandles.Add(moduleName, handle);
        }

        var functionAddy = Kernel32.GetProcAddress(handle, functionName);

        var originalInstruction = new byte[hookSize];

        fixed (byte* dst = originalInstruction)
        {
            Buffer.MemoryCopy(functionAddy.ToPointer(), dst, hookSize, hookSize);
        }

        if (originalInstruction[0] == 0xE9) //then it probably isnt hooked
        {
            return;
        }
        
        AnsiConsole.MarkupLineInterpolated($"Unhooking [39]{functionName}[/] at [39]{hookedFunctionAddy.ToString("X")}[/] ...");

        proc.WriteMemory(hookedFunctionAddy, originalInstruction);
    }
}
