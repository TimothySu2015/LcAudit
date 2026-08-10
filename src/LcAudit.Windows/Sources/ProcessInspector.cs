using System.Diagnostics;
using LcAudit.Windows.Interop;

namespace LcAudit.Windows.Sources;

/// <inheritdoc cref="IProcessInspector"/>
public sealed class ProcessInspector : IProcessInspector
{
    public IReadOnlyList<ProcessSummary> ListProcesses()
    {
        var results = new List<ProcessSummary>();

        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    // ProcessName 走系統快照，不開 handle，不會觸發反作弊。
                    results.Add(new ProcessSummary(process.Id, process.ProcessName));
                }
                catch (InvalidOperationException)
                {
                    // 程序在列舉過程中結束，略過即可。
                }
            }
        }

        return results;
    }

    public string? TryGetImagePath(int processId) => Kernel32.TryGetProcessImagePath(processId);
}
