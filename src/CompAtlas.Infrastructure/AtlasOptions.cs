namespace CompAtlas.Infrastructure;

public sealed class AtlasOptions
{
    public string DependencyTrackUrl { get; set; } = "";
    public string DependencyTrackApiKey { get; set; } = "";
    public string? ProxyUrl { get; set; }
    public string MalwareDirectory { get; set; } = "";
    public int ConcurrentJobs { get; set; } = 2;
    public int SnapshotRetentionDays { get; set; } = 90;
    public int ReleaseRetentionDays { get; set; } = 365;
    public int NightlyHourUtc { get; set; } = 1;
    public Dictionary<string, string> AzureTokens { get; set; } = [];
    public bool AzureUseDefaultCredentials { get; set; } = true;
}
