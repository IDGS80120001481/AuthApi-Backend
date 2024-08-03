using System.ComponentModel.DataAnnotations;

namespace AuthApi.Dtos
{
    public class ForgotPasswordDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
    }
}
