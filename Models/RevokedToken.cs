using System;
using System.Collections.Generic;

namespace JWT.Models;

public partial class RevokedToken
{
    public int Id { get; set; }

    public string Jti { get; set; } = null!;

    public DateTime ExpiresAt { get; set; }
}
