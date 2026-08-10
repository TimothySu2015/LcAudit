namespace LcAudit.Windows.Sources;

/// <summary>簽章驗證的判定結果（技術設計 §4.1 的 HRESULT 對照表）。</summary>
public enum SignatureTrust
{
    /// <summary>簽章有效且受信任。</summary>
    Valid,

    /// <summary>完全未簽章。</summary>
    NoSignature,

    /// <summary><b>檔案被竄改</b> —— 最高優先警示。</summary>
    BadDigest,

    /// <summary>憑證被明確列為不信任。</summary>
    ExplicitDistrust,

    /// <summary>主體不受信任。</summary>
    SubjectNotTrusted,

    /// <summary>憑證鏈不完整，常見於自簽。</summary>
    ChainIncomplete,

    /// <summary>憑證過期。</summary>
    Expired,

    /// <summary>政策阻擋，非簽章本身的問題。</summary>
    SecuritySettings,

    /// <summary>檔案不存在、讀不到、或根本不是 PE 檔。</summary>
    FileNotReadable,

    /// <summary>未列於對照表的 HRESULT。</summary>
    Unknown,
}

/// <summary>單一檔案的簽章驗證結果。</summary>
public sealed record SignatureVerdict
{
    public required string FilePath { get; init; }

    /// <summary>由 <c>WinVerifyTrust</c> 判定，這是「簽章是否有效」的唯一依據。</summary>
    public required SignatureTrust Trust { get; init; }

    /// <summary>原始 HRESULT，供報告附上原始證據。</summary>
    public required int HResult { get; init; }

    /// <summary>
    /// 由 <c>CryptQueryObject</c> + PKCS7_SIGNED_EMBED 抽出的簽章者組織（DN 的 O= 欄位）。
    /// 無簽章或抽取失敗為 <c>null</c>。
    /// </summary>
    public string? SignerOrganization { get; init; }

    /// <summary>簽章者憑證的完整 Subject DN，供報告顯示。</summary>
    public string? SignerSubject { get; init; }

    public DateTimeOffset? NotBefore { get; init; }

    public DateTimeOffset? NotAfter { get; init; }

    /// <summary>簽章有效且成功取得簽章者 —— M1-01 與 M1-02 都要靠這兩件事同時成立。</summary>
    public bool IsTrustedAndIdentified => Trust == SignatureTrust.Valid && SignerOrganization is not null;
}
