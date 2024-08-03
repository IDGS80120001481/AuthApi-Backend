using Microsoft.AspNetCore.Identity;

namespace AuthApi.Models
{
    public class AppUser : IdentityUser
    {
        public String? Fullname { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
