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

        // 明確異常（Fail）與需人工研判（Warning）必須分開。
        //
        // 實際案例：一台紫P 完全正版的機器（M1-01/M1-02 皆 Pass），只因為 M1-04 是
        // Warning（安裝程式解壓出來的檔案本來就沒有 MOTW），就被推論為「假紫P，
        // 端點已不可信，建議直接重灌」。使用者若照做就是白白重灌一台乾淨的電腦。
        //
        // S-05 的 Critical 強制升等早就採「只認 Fail」，同樣的道理必須套用到推論規則。
        var failures = findings.Where(f => f.Status == CheckStatus.Fail)
                               .Select(f => f.Id)
                               .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var results = new List<Inference>();

        // R1｜假紫P／釣魚安裝檔。這條結論會叫人重灌，只能由 Fail 觸發。
        var fakePurple = MatchAny(failures, "M1-01", "M1-02", "M1-04");
        if (fakePurple.Count > 0)
        {
            results.Add(new Inference("R1",
                "假紫P／釣魚安裝檔 — 端點已不可信。本工具其餘結果均不應全然採信，建議直接重灌並在乾淨裝置上更改密碼。",
                fakePurple,
                RiskLevel.Extreme));
        }

        // R2｜防毒遭主動停用。M3-11（即時防護關閉）必須是 Fail 才算數 ——
        // M3-10 排除清單存在只是 Warning，單獨出現不足以斷定防毒「被主動停用」。
        var defenderDisabled = failures.Contains("M3-11")
            ? MatchAny(hits, "M3-10", "M3-11")
            : [];

        if (defenderDisabled.Count == 2)
        {
            results.Add(new Inference("R2",
                "防毒遭主動停用（排除清單與即時防護關閉同時成立）— 高度可疑，這是惡意程式落地後的典型動作。",
                defenderDisabled,
                RiskLevel.High));
        }

        // R3｜遠端登入與帳號異動同時出現。
        //
        // 兩邊都是「設計上就只會產出 Warning」的檢查項（有遠端登入紀錄、有非預期帳號），
        // 所以這條規則的組成必然是兩個 Warning。實測一台正常使用公司 RDP 的筆電就會命中，
        // 而且原本會被拉到「高」並宣告「RDP 遭爆破」—— 但 M2-03（登入失敗爆量）
        // 根本沒命中，完全沒有爆破跡證。
        //
        // 因此：
        // 1. 有爆破或公網登入跡證（M2-02 / M2-03）才敢說「遭爆破」，等級下限「高」
        // 2. 否則只陳述「這個組合值得核對」，等級下限降為「中」
        var remoteLogon = MatchAny(hits, "M2-01", "M2-04");
        var accountChange = MatchAny(hits, "M3-03", "M3-04");

        if (remoteLogon.Count > 0 && accountChange.Count > 0)
        {
            var attackEvidence = MatchAny(hits, "M2-02", "M2-03");

            results.Add(attackEvidence.Count > 0
                ? new Inference("R3",
                    "RDP 遭爆破或帳號被建立 — 遠端登入跡證、本機帳號異動，"
                    + "以及來自公網的登入或密碼嘗試失敗爆量同時出現。",
                    [.. remoteLogon, .. accountChange, .. attackEvidence],
                    RiskLevel.High)
                : new Inference("R3-P",
                    "有遠端登入紀錄，同時也有非預期的本機帳號 —— 這個組合值得核對。"
                    + "但沒有發現密碼爆破或來自公網的登入跡證，"
                    + "所以也可能只是你自己或公司 IT 的正常遠端使用。"
                    + "請確認那些帳號與登入時間是否都是你認可的。",
                    [.. remoteLogon, .. accountChange],
                    RiskLevel.Medium));
        }

        // R4｜第三方遠端工具遭**入侵**。必須是 Fail —— 也就是確實有連入紀錄。
        //
        // 「偵測到 AnyDesk 已安裝但沒有任何連入紀錄」是 Warning，那代表「值得問一下」，
        // 不代表「遭入侵」。用它下這個結論同樣是過度推論。
        //
        // M1 全數未命中才歸因於遠端工具 —— 若紫P 本身有問題，途徑應歸因於 R1。
        var remoteTools = MatchAny(failures, "M2-06", "M2-07", "M2-08");
        var m1Clean = !findings.Any(f => f.Module == "M1" && f.Status == CheckStatus.Fail);
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
            // 措辭要同時對兩種人成立：出事來查的、以及只是想順手檢查電腦的。
            // 原本寫死「被盜途徑偏向帳號側」，對後者會讓人以為自己漏看了什麼。
            results.Add(inconclusive == 0
                ? new Inference("R5",
                    "這台電腦未見異常。若你的帳號確實被盜，"
                    + "途徑偏向帳號側（釣魚網頁／信箱被打穿／OTP 社交工程）而非這台電腦。",
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
