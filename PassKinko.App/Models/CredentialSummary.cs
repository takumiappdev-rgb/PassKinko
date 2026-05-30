using System;

namespace PassKinko.App.Models;

public sealed class CredentialSummary
{
    public long Id { get; set; }
    public string ServiceName { get; set; } = string.Empty;
    public string Website { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Memo { get; set; } = string.Empty;
    public DateTime UpdatedAt { get; set; }
}
