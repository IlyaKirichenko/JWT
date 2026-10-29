using System;
using System.Collections.Generic;

namespace JWT.Models;

public partial class User
{
    public int Id { get; set; }

    public string Login { get; set; } = string.Empty;

    public string Role { get; set; } = null!;

    public string PasswordHash { get; set; } = string.Empty;
}
