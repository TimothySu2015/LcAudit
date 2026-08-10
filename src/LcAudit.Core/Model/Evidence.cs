namespace LcAudit.Core.Model;

/// <summary>
/// 單筆原始證據。取證優先原則：所有發現都必須附上來源與時間點。
/// </summary>
/// <param name="Key">證據名稱，如 <c>"HostUrl"</c>、<c>"IpAddress"</c>、<c>"路徑"</c>。</param>
/// <param name="Value">原始值，原樣保留，不做美化或截斷。</param>
/// <param name="Timestamp">該證據對應的時間點（若有）。</param>
public sealed record Evidence(string Key, string Value, DateTimeOffset? Timestamp = null);
