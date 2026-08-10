using LcAudit.Core.Validation;
using LcAudit.Windows.Sources;

namespace LcAudit.Windows.Checks.M2;

/// <summary>一筆已正規化的登入事件（由 4624 / 4625 轉出）。</summary>
public sealed record LogonRecord(
    DateTimeOffset Time,
    string UserName,
    string DomainName,
    int LogonType,
    string? IpAddress,
    string? IpPort,
    string? WorkstationName)
{
    public AddressScope Scope => PrivateAddressClassifier.Classify(IpAddress);

    /// <summary>顯示用的帳號全名。</summary>
    public string Account => string.IsNullOrWhiteSpace(DomainName) ? UserName : $"{DomainName}\\{UserName}";

    /// <summary>
    /// 是否為應排除的系統帳號。
    /// <para>
    /// 電腦帳號（結尾為 <c>$</c>）與 ANONYMOUS LOGON 是網路登入的正常雜訊，
    /// 不排除的話 M2-02 會對每台正常的網域機器噴 Fail。
    /// </para>
    /// </summary>
    public bool IsSystemAccount =>
        UserName.EndsWith('$')
        || UserName.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase)
        || UserName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase)
        || UserName.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase)
        || UserName.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase)
        || UserName.Equals("-", StringComparison.Ordinal)
        || string.IsNullOrWhiteSpace(UserName);

    /// <summary>由具名欄位陣列轉出，欄位順序須對應 <see cref="EventQueries.LogonProperties"/>。</summary>
    public static LogonRecord FromEvent(EventRecordData record)
    {
        ArgumentNullException.ThrowIfNull(record);

        _ = int.TryParse(record.Property(2), out var logonType);

        return new LogonRecord(
            record.TimeCreated,
            record.Property(0) ?? string.Empty,
            record.Property(1) ?? string.Empty,
            logonType,
            record.Property(3),
            record.Property(4),
            record.Property(5));
    }
}
