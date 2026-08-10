namespace LcAudit.Core.Model;

/// <summary>
/// 檢查項的嚴重度。
/// <para>
/// 列舉底值「就是」命中時計入的風險分數（功能規格 S-01）。新增成員時務必維持此不變量，
/// <see cref="Finding.Score"/> 直接對其做數值轉型。
/// </para>
/// </summary>
public enum Severity
{
    Info = 0,
    Low = 5,
    Medium = 10,
    High = 20,
    Critical = 40,
}
