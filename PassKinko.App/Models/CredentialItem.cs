using System;
namespace PassKinko.App.Models;

public sealed class CredentialItem
{
    public long Id { get; set; }
    public string ServiceName { get; set; } = string.Empty;
    public string Website { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Memo { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
