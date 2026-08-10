using System.Reflection;

namespace LcAudit.Cli;

/// <summary>本工具的版本資訊。</summary>
public static class ToolVersion
{
    private static readonly Lazy<string> Value = new(Resolve);

    /// <summary>顯示用的版本字串，如 <c>1.0.0</c>。取不到時為 <c>unknown</c>。</summary>
    public static string Current => Value.Value;

    private static string Resolve()
    {
        var assembly = Assembly.GetExecutingAssembly();

        // InformationalVersion 才會帶上 csproj 的 <Version>；AssemblyVersion 只有四段數字，
        // 且發佈時若沒指定會停在 1.0.0.0，看不出實際版本。
        var informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        if (!string.IsNullOrWhiteSpace(informational))
        {
            // 決定性建置會在版本後面接 "+<commit hash>"，顯示時去掉，
            // 但保留 "-preview" 這類預發行標記。
            var plus = informational.IndexOf('+');
            return plus > 0 ? informational[..plus] : informational;
        }

        return assembly.GetName().Version?.ToString(3) ?? "unknown";
    }
}
