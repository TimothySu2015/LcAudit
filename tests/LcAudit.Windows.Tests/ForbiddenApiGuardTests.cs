using Xunit;

namespace LcAudit.Windows.Tests;

/// <summary>
/// 掃描原始碼，確保禁忌 API 不會被寫回去（技術設計 §0 建議的守門測試）。
/// <para>
/// 這些 API 一旦出現，工具的核心檢查就會被最容易的手法繞過，而且**不會有任何測試失敗**
/// —— 因為它們都「能跑」，只是判定結果是錯的。所以必須從原始碼層面攔。
/// </para>
/// </summary>
public sealed class ForbiddenApiGuardTests
{
    /// <summary>簽章驗證的禁忌 API（技術設計 §0）。</summary>
    public static TheoryData<string, string> SignatureBans => new()
    {
        { "CreateFromSignedFile", "它根本不驗證簽章，只掃檔案找像憑證的東西" },
        { "CERT_QUERY_CONTENT_FLAG_ALL", "會掃描資源區段，塞一張憑證就能冒充簽章者" },
    };

    /// <summary>反作弊共存規則的禁忌 API（CLAUDE.md）。</summary>
    public static TheoryData<string, string> AntiCheatBans => new()
    {
        { "PROCESS_VM_READ", "外掛讀取遊戲記憶體用的權限旗標，會觸發反作弊" },
        { "MainModule", "底層帶 PROCESS_VM_READ，改用 QueryFullProcessImageName" },
        { "SeDebugPrivilege", "最強的反作弊觸發器之一，本工具不需要" },
        { "EnumProcessModules", "列舉他人程序的模組會觸發反作弊" },
        { "ReadProcessMemory", "直接讀取他人程序記憶體" },
        { "CreateRemoteThread", "注入手法" },
        { "VirtualAllocEx", "注入手法" },
        { "SetWindowsHookEx", "掛鉤手法" },
    };

    [Theory]
    [MemberData(nameof(SignatureBans))]
    public void 簽章驗證禁忌API不得出現於原始碼(string forbidden, string reason)
        => AssertNotPresent(forbidden, reason);

    [Theory]
    [MemberData(nameof(AntiCheatBans))]
    public void 反作弊禁忌API不得出現於原始碼(string forbidden, string reason)
        => AssertNotPresent(forbidden, reason);

    private static void AssertNotPresent(string forbidden, string reason)
    {
        var offenders = new List<string>();

        foreach (var file in Directory.EnumerateFiles(SourceRoot(), "*.cs", SearchOption.AllDirectories))
        {
            // 排除建置產出
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            {
                continue;
            }

            var lineNumber = 0;
            foreach (var rawLine in File.ReadLines(file))
            {
                lineNumber++;

                // 註解裡「提到」這些 API 是刻意的警語，不算違規。
                var code = StripComment(rawLine);
                if (code.Contains(forbidden, StringComparison.Ordinal))
                {
                    offenders.Add($"{file}:{lineNumber}");
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            $"原始碼中出現禁忌 API「{forbidden}」（{reason}）：{Environment.NewLine}"
            + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>去掉行註解。本專案不使用區塊註解，XML 文件註解也是 <c>///</c> 開頭。</summary>
    private static string StripComment(string line)
    {
        var index = line.IndexOf("//", StringComparison.Ordinal);
        return index >= 0 ? line[..index] : line;
    }

    /// <summary>從測試組件位置往上找到含 <c>LcAudit.slnx</c> 的方案根目錄。</summary>
    private static string SourceRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);

        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "LcAudit.slnx")))
        {
            dir = dir.Parent;
        }

        // 找不到就讓測試失敗，不要略過 —— 守門測試靜默跳過等於沒有守門。
        Assert.True(dir is not null, $"找不到方案根目錄（自 {AppContext.BaseDirectory} 往上尋找 LcAudit.slnx）");

        return Path.Combine(dir!.FullName, "src");
    }
}
