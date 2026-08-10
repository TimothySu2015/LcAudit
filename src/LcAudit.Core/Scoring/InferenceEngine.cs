using LcAudit.Core.Abstractions;
using LcAudit.Core.Model;

namespace LcAudit.Core.Scoring;

/// <summary>
/// 入侵途徑推論（功能規格 S-06 決策表）。
/// <para>規則依嚴重度排序，最該先看的在前；多條規則可同時成立。</para>
/// </summary>
public sealed class InferenceEngine : IInferenceEngine
{
    public IReadOnlyList<Inference> Infer(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var hits = findings.Where(f => f.IsHit)
                           .Select(f => f.Id)
                           .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var results = new List<Inference>();

        // R1｜假紫P／釣魚安裝檔。命中即代表端點本身不可信，優先序最高。
        var fakePurple = MatchAny(hits, "M1-01", "M1-02", "M1-04");
        if (fakePurple.Count > 0)
        {
            results.Add(new Inference("R1",
                "假紫P／釣魚安裝檔 — 端點已不可信。本工具其餘結果均不應全然採信，建議直接重灌並在乾淨裝置上更改密碼。",
                fakePurple,
                RiskLevel.Extreme));
        }

        // R2｜防毒遭主動停用。需 M3-10 與 M3-11 同時成立。
        var defenderDisabled = MatchAny(hits, "M3-10", "M3-11");
        if (defenderDisabled.Count == 2)
        {
            results.Add(new Inference("R2",
                "防毒遭主動停用（排除清單與即時防護關閉同時成立）— 高度可疑，這是惡意程式落地後的典型動作。",
                defenderDisabled,
                RiskLevel.High));
        }

        // R3｜RDP 遭爆破或帳號被建立。需「有遠端登入跡證」且「有帳號異動」同時成立。
        var remoteLogon = MatchAny(hits, "M2-01", "M2-04");
        var accountChange = MatchAny(hits, "M3-03", "M3-04");
        if (remoteLogon.Count > 0 && accountChange.Count > 0)
        {
            results.Add(new Inference("R3",
                "RDP 遭爆破或帳號被建立 — 遠端登入跡證與本機帳號異動同時出現。",
                [.. remoteLogon, .. accountChange],
                RiskLevel.High));
        }

        // R4｜第三方遠端工具遭入侵。限 M1 全數未命中 —— 若紫P 本身就有問題，
        // 入侵途徑應歸因於 R1，而非遠端工具。
        var remoteTools = MatchAny(hits, "M2-06", "M2-07", "M2-08");
        var m1Clean = !findings.Any(f => f.Module == "M1" && f.IsHit);
        if (remoteTools.Count > 0 && m1Clean)
        {
            // 這正是「紫P 是正版，但電腦被植入 AnyDesk」的情境。
            // 加總只有 10 分（單一 High 的 Warning）會落在「低」，但結論明明是端點已被他人存取。
            results.Add(new Inference("R4",
                "第三方遠端工具遭入侵 — 紫P 本身未見異常，但偵測到遠端工具的連入紀錄。"
                + "攻擊者不需要動紫P，只要能遠端操作你的電腦，就能在你自己登入遊戲時取走一切。",
                remoteTools,
                RiskLevel.High));
        }

        // R5｜全數未命中。
        if (results.Count == 0 && hits.Count == 0)
        {
            var inconclusive = findings.Count(f => f.Status == CheckStatus.Inconclusive);

            // 有 Inconclusive 時不能說「端點未見異常」—— 那些項目是「沒檢查成功」，
            // 不是「檢查過沒問題」。混為一談會給出不實的安全感。
            results.Add(inconclusive == 0
                ? new Inference("R5",
                    "端點未見異常，被盜途徑偏向帳號側（釣魚網頁／信箱被打穿／OTP 社交工程）。",
                    [])
                : new Inference("R5-P",
                    $"未命中任何異常，但有 {inconclusive} 項無法判定（多半因未提權或路徑不存在）。"
                    + "在補齊這些項目前，不宜逕行認定端點乾淨。",
                    []));
        }

        return results;
    }

    /// <summary>回傳 <paramref name="ids"/> 中確實命中的項目，保持傳入順序。</summary>
    private static List<string> MatchAny(HashSet<string> hits, params string[] ids)
        => [.. ids.Where(hits.Contains)];
}
