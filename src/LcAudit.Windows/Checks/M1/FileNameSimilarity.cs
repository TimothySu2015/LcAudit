namespace LcAudit.Windows.Checks.M1;

/// <summary>相似檔名的命中原因。</summary>
public enum SimilarityReason
{
    /// <summary>同形字元替換（<c>PurpIe</c> —— 大寫 I 冒充小寫 l）。信心最高。</summary>
    Homoglyph,

    /// <summary>正版名稱加上複製或版本後綴（<c>Purple_new</c>、<c>Purple (1)</c>）。</summary>
    CopySuffix,

    /// <summary>拼字接近（編輯距離 ≤ 2）。</summary>
    NearMiss,
}

/// <summary>單一相似檔名的判定結果。</summary>
public sealed record SimilarFileName(string FileName, string SimilarTo, SimilarityReason Reason);

/// <summary>
/// M1-06 可疑檔名相似度判定。
/// <para>
/// 功能規格只舉了 <c>PurpIe</c>、<c>Purple_new</c> 兩個例子而未定義演算法。
/// 這裡定案為三條各自可解釋的規則，而非單一的模糊比對 ——
/// 純用編輯距離會把安裝目錄裡大量正常的 <c>Purple*.exe</c> 一起掃進來，
/// 那正是誤報風暴的來源。
/// </para>
/// <para>純字串處理，可完整單元測試。</para>
/// </summary>
public static class FileNameSimilarity
{
    /// <summary>
    /// 同形字元對照。把視覺上容易混淆的字元折疊成同一個代表字元後再比對，
    /// <c>PurpIe</c>（大寫 I）就會和 <c>Purple</c>（小寫 l）碰撞。
    /// </summary>
    private static readonly Dictionary<char, char> Homoglyphs = new()
    {
        ['i'] = 'l', ['1'] = 'l', ['|'] = 'l',
        ['0'] = 'o',
        ['5'] = 's',
        ['2'] = 'z',
        ['8'] = 'b',
    };

    /// <summary>暗示「這是複製品」的後綴。</summary>
    private static readonly string[] CopySuffixes =
    [
        "_new", "-new", "new", "_bak", "-bak", "bak", "_copy", "-copy", "copy",
        "_old", "-old", "old", "2", "3", "_1", "(1)", "(2)", "_v2", "-v2", " - 複製",
    ];

    /// <summary>
    /// 找出與正版名稱相似但不相同的檔名。
    /// </summary>
    /// <param name="fileNames">待檢查的檔名（不含路徑）。</param>
    /// <param name="knownGoodNames">正版檔名清單，如 <c>Purple.exe</c>。</param>
    public static IReadOnlyList<SimilarFileName> FindSuspicious(
        IEnumerable<string> fileNames,
        IReadOnlyList<string> knownGoodNames)
    {
        ArgumentNullException.ThrowIfNull(fileNames);
        ArgumentNullException.ThrowIfNull(knownGoodNames);

        var knownGood = knownGoodNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var knownStems = knownGoodNames
            .Select(Path.GetFileNameWithoutExtension)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s!)
            .ToList();

        var results = new List<SimilarFileName>();

        foreach (var fileName in fileNames)
        {
            // 正版檔名本身直接跳過
            if (knownGood.Contains(fileName))
            {
                continue;
            }

            var stem = Path.GetFileNameWithoutExtension(fileName);
            if (string.IsNullOrWhiteSpace(stem))
            {
                continue;
            }

            var match = Classify(stem, knownStems);
            if (match is not null)
            {
                results.Add(new SimilarFileName(fileName, match.Value.SimilarTo, match.Value.Reason));
            }
        }

        return results;
    }

    private static (string SimilarTo, SimilarityReason Reason)? Classify(string stem, IReadOnlyList<string> knownStems)
    {
        var folded = Fold(stem);

        foreach (var known in knownStems)
        {
            var knownFolded = Fold(known);

            // 規則 1：折疊後完全相同，但原始字串不同 → 同形字元替換。信心最高。
            if (folded.Equals(knownFolded, StringComparison.Ordinal)
                && !stem.Equals(known, StringComparison.OrdinalIgnoreCase))
            {
                return (known, SimilarityReason.Homoglyph);
            }

            // 規則 2：正版名稱 + 複製後綴
            if (folded.StartsWith(knownFolded, StringComparison.Ordinal) && folded.Length > knownFolded.Length)
            {
                var suffix = folded[knownFolded.Length..];
                if (CopySuffixes.Any(s => suffix.Equals(Fold(s), StringComparison.Ordinal)))
                {
                    return (known, SimilarityReason.CopySuffix);
                }
            }

            // 規則 3：編輯距離 ≤ 2 且長度相近。刻意排除長度差異大的，
            // 否則安裝目錄裡正常的 PurpleUpdater 之類會被掃進來。
            if (Math.Abs(folded.Length - knownFolded.Length) <= 2
                && !folded.Equals(knownFolded, StringComparison.Ordinal)
                && LevenshteinDistance(folded, knownFolded) <= 2)
            {
                return (known, SimilarityReason.NearMiss);
            }
        }

        return null;
    }

    /// <summary>小寫化並折疊同形字元。</summary>
    internal static string Fold(string value)
    {
        var chars = value.ToLowerInvariant().ToCharArray();

        for (var i = 0; i < chars.Length; i++)
        {
            if (Homoglyphs.TryGetValue(chars[i], out var replacement))
            {
                chars[i] = replacement;
            }
        }

        // rn 視覺上等同 m，vv 等同 w
        return new string(chars).Replace("rn", "m", StringComparison.Ordinal)
                                .Replace("vv", "w", StringComparison.Ordinal);
    }

    internal static int LevenshteinDistance(string a, string b)
    {
        if (a.Length == 0)
        {
            return b.Length;
        }

        if (b.Length == 0)
        {
            return a.Length;
        }

        var previous = new int[b.Length + 1];
        var current = new int[b.Length + 1];

        for (var j = 0; j <= b.Length; j++)
        {
            previous[j] = j;
        }

        for (var i = 1; i <= a.Length; i++)
        {
            current[0] = i;

            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                current[j] = Math.Min(Math.Min(current[j - 1] + 1, previous[j] + 1), previous[j - 1] + cost);
            }

            (previous, current) = (current, previous);
        }

        return previous[b.Length];
    }
}
