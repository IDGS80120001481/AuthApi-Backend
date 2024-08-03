using AuthApi.Dtos;
using AuthApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Controllers
{
    [Authorize(Roles = "Admin, User")]
    [Route("api/[controller]")]
    [ApiController]
    public class RolesController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<AppUser> _userManager;

        public RolesController(RoleManager<IdentityRole> roleManager, UserManager<AppUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        [HttpPost]
        public async Task<IActionResult> CreateRole([FromBody] CreateRole createRoleDto)
        {
            if (string.IsNullOrEmpty(createRoleDto.RoleName))
            {
                return BadRequest("El nombre del rol es requerido");
            }

            var roleExist = await _roleManager.RoleExistsAsync(createRoleDto.RoleName);

            if (roleExist)
            {
                return BadRequest("Este rol ya existe");
            }

            var roleResult = await _roleManager.CreateAsync(new IdentityRole(createRoleDto.RoleName));

            if (roleResult.Succeeded)
            {
                return Ok(new { message = "Rol creado exitosamente" });
            }

            return BadRequest("La creacion del ha fallado.");
        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<RoleResponseDto>>> GetRoles()
        {
            var roles = await _roleManager.Roles.Select(r => new RoleResponseDto
            {
                Id = r.Id,
                Name = r.Name,
            }).ToListAsync();

            foreach (var role in roles)
            {
                role.TotalUsers = _userManager.GetUsersInRoleAsync(role.Name!).Result.Count;
            }

            return Ok(roles);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);

            if (role is null)
            {
                return NotFound("Rol no encontrado.");
            }

            var result = await _roleManager.DeleteAsync(role);

            if (result.Succeeded)
            {
                return Ok(new { message = "Rol eliminado exitosamente." });
            }

            return BadRequest("La eliminacion del rol ha fallado.");
        }

        [HttpPost("assign")]
        public async Task<IActionResult> AssignRole([FromBody] RoleAssignDto roleAssignDto)
        {
            var user = await _userManager.FindByIdAsync(roleAssignDto.UserId);

            if (user is null)
            {
                return NotFound("Usuario no encontrado.");
            }

            var role = await _roleManager.FindByIdAsync(roleAssignDto.RoleId);

            if (role is null)
            {
                return NotFound("Rol no encontado.");
            }

            var result = await _userManager.AddToRoleAsync(user, role.Name!);

            if (result.Succeeded)
            {
                return Ok(new { message = "Rol asignado exitosamente." });
            }

            var error = result.Errors.FirstOrDefault();

            return BadRequest(error!.Description);
        }
    }
}
