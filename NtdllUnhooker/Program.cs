using Spectre.Console;
using System.Diagnostics;
using NtdllUnhooker.Backend.Extensions;

AnsiConsole.MarkupLine("Getting processes...");

var allProcess = Process.GetProcesses();

AnsiConsole.Clear();

var choice = AnsiConsole.Prompt(
    new SelectionPrompt<string>()
        .Title("Choose the process to unhook")
        .PageSize(10)
        .MoreChoicesText("[grey](Move up and down to reveal more processes)[/]")
        .AddChoices(allProcess.Where(x => x.ProcessName != "svchost").Select(p => $"{p.ProcessName} ({p.Id})").ToArray()));

var pidSplit = choice.Split(' ')[1];
var pid = int.Parse(pidSplit.Substring(1, pidSplit.Length - 2));

var proc = Process.GetProcessById(pid);

int i = 0;

foreach (ProcessModule mod in proc.Modules)
{
    if (mod.ModuleName == "ntdll.dll")
    {
        foreach (var fn in proc.GetModuleFunctions(mod))
        {
            proc.Unhook(mod.ModuleName, fn.Item1, fn.Item2);
            i++;
        }

        break;
    }
}

AnsiConsole.MarkupLine($"\nScanned [39]{i}[/] functions!");
Console.ReadKey();