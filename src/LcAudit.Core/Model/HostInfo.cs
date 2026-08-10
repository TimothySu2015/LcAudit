namespace LcAudit.Core.Model;

/// <summary>受檢主機資訊（功能規格 §8.2 的 <c>host</c> 區塊）。</summary>
public sealed record HostInfo
{
    public required string ComputerName { get; init; }

    public required string OsVersion { get; init; }

    /// <summary>時區識別碼。所有時間軸都以本機時間呈現，必須標示時區才可跨機比對。</summary>
    public required string TimeZone { get; init; }
}
