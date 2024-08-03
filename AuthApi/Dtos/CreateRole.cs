using System.ComponentModel.DataAnnotations;

namespace AuthApi.Dtos
{
    public class CreateRole
    {
        [Required(ErrorMessage = "Role Name is required")]
        public string RoleName { get; set; } = null!;
    }
}
