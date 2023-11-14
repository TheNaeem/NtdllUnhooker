using System;
using System.Runtime.CompilerServices;

namespace NtdllUnhooker.Backend.Extensions;

public static class IntPtrExtensions
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IntPtr ResolveOffset(this IntPtr ptr, int offset) //cleaner than adding everything a bunch of times
    {
        return ptr + offset;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IntPtr ResolveOffset(this IntPtr ptr, uint offset) 
    {
        return new(ptr.ToInt64() + offset);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IntPtr ResolveOffset(this IntPtr ptr, long offset) //cleaner than adding everything a bunch of times
    {
        return new(ptr.ToInt64() + offset);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe T Val<T>(this IntPtr ptr) where T : unmanaged
    {
        return *(T*)ptr.ToPointer();
    }
}
