using AuthApi.Dtos;
using AuthApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RestSharp;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthApi.Controllers
{
    [Authorize(Roles = "Admin, User")]
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AccountController(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<ActionResult<string>> Register(RegisterDto registerDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new AppUser
            {
                Email = registerDto.Email,
                Fullname = registerDto.FullName,
                UserName = registerDto.Email,
            };
            var result = await _userManager.CreateAsync(user, registerDto.Password);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            if (registerDto.Roles is null)
            {
                await _userManager.AddToRoleAsync(user, "User");
            }
            else
            {
                foreach (var role in registerDto.Roles)
                {
                    await _userManager.AddToRoleAsync(user, role);
                }
            }

            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Message = "Cuenta creada exitosamente"
            });
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<ActionResult<AuthResponseDto>> Login(LoginDto loginDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(loginDto.Email);

            if (user == null)
            {
                return Unauthorized(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "Usuario no encontrado con el email seleccionado"
                });
            }

            var result = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!result)
            {
                return Unauthorized(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "Contraseña Invalida"
                });
            }

            var token = GenerateToken(user);
            var refreshToken = GenerateRefreshToken();
            _ = int.TryParse(_configuration.GetSection("JWTSettings").GetSection("RefreshTokenValidityIn").Value!, out int RefreshTokenValidityIn);
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(RefreshTokenValidityIn);
            await _userManager.UpdateAsync(user);

            return Ok(new AuthResponseDto
            {
                Token = token,
                IsSuccess = true,
                Message = "Inicio de sesion correcto",
                RefreshToken = refreshToken,
            });
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public async Task<ActionResult<AuthResponseDto>> RefreshToken(TokenDto tokenDto)
        {

            if (string.IsNullOrEmpty(tokenDto.Token) || string.IsNullOrEmpty(tokenDto.Email))
            {
                return BadRequest(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "Token o email no cuentan con informacion."
                });
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var principal = GetPrincipalFromExpiredToken(tokenDto.Token);
            var user = await _userManager.FindByEmailAsync(tokenDto.Email);

            if (principal is null || user is null || user.RefreshToken != tokenDto.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
                return BadRequest(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "Cliente Invalido"
                });

            var newJwtToken = GenerateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            _ = int.TryParse(_configuration.GetSection("JWTSettings").GetSection("RefreshTokenValidityIn").Value!, out int RefreshTokenValidityIn);
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(RefreshTokenValidityIn);

            await _userManager.UpdateAsync(user);

            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Token = newJwtToken,
                RefreshToken = newRefreshToken,
                Message = "Token refrescado exitosamente"
            });

        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                throw new ArgumentNullException(nameof(token), "No existe el token o se encuentra vacio.");
            }
            var tokenParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("JWTSetting").GetSection("securityKey").Value!)),
                ValidateLifetime = false

            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }

        [AllowAnonymous]
        [HttpPost("forgot-password")]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordDto forgotPasswordDTO)
        {
            var user = await _userManager.FindByEmailAsync(forgotPasswordDTO.Email);
            if (user is null)
            {
                return Ok(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "No hay usuarios registrados con este email"
                });
            }
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = $"http://localhost:4200/reset-password?email={user.Email}&token={WebUtility.UrlEncode(token)}";

            var client = new RestClient("https://sandbox.api.mailtrap.io/api/send/7089654");
            var request = new RestRequest
            {
                Method = Method.Post,
                RequestFormat = DataFormat.Json,
            };

            request.AddHeader("Authorization", "Bearer be4b8fc7084b3ee91a36badb7d364275");
            request.AddJsonBody(new
            {
                from = new { email = "mailtrap@demomailtrap.com" },
                to = new[] { new { email = user.Email } },
                template_uuid = "bd9bbc2e-221d-4447-aede-5f9b241bee6a",
                template_variables = new { user_email = user.Email, pass_reset_link = resetLink }
            });

            var response = client.Execute(request);
            if (response.IsSuccessful)
            {
                return Ok(new AuthResponseDto
                {
                    IsSuccess = true,
                    Message = "Email enviado con la contraseña de verificacion"
                });
            }
            else
            {
                return BadRequest(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = response.Content!.ToString()
                });
            }
        }

        [AllowAnonymous]
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordDto.Email);


            if (user is null)
            {
                return BadRequest(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "No existe usuarios registrados con este email"
                });
            }

            var result = await _userManager.ResetPasswordAsync(user, resetPasswordDto.Token, resetPasswordDto.NewPassword);

            if (result.Succeeded)
            {
                return Ok(new AuthResponseDto
                {
                    IsSuccess = true,
                    Message = "Contraseña reseatada exitosamente"
                });
            }

            return BadRequest(new AuthResponseDto
            {
                IsSuccess = false,
                Message = result.Errors.FirstOrDefault()?.Description
            });
        }

        [HttpPost("change-password")]
        public async Task<ActionResult> ChangePassword(ChangePasswordDto changePasswordDto)
        {
            var user = await _userManager.FindByEmailAsync(changePasswordDto.Email);
            if (user is null)
            {
                return BadRequest(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "No existe usuario registrado con este email"
                });
            }

            var result = await _userManager.ChangePasswordAsync(user, changePasswordDto.CurrentPassword, changePasswordDto.NewPassword);
            if (result.Succeeded)
            {
                return Ok(new AuthResponseDto
                {
                    IsSuccess = true,
                    Message = "Contraseña modificada exitosamente"
                });
            }

            return BadRequest(new AuthResponseDto
            {
                IsSuccess = false,
                Message = result.Errors.FirstOrDefault()!.Description
            });
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private string GenerateToken(AppUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(_configuration.GetSection("JWTSetting").GetSection("securityKey").Value!);

            var roles = _userManager.GetRolesAsync(user).Result;

            List<Claim> claims = [
                new (JwtRegisteredClaimNames.Email, user.Email??""),
       new (JwtRegisteredClaimNames.Name, user.Fullname??""),
       new (JwtRegisteredClaimNames.NameId, user.Id??""),
       new (JwtRegisteredClaimNames.Aud, _configuration.GetSection("JWTSetting").GetSection("ValidAudience").Value!),
       new (JwtRegisteredClaimNames.Iss, _configuration.GetSection("JWTSetting").GetSection("ValidIssuer").Value!)
            ];

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256
                )
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        [HttpGet("detail")]
        public async Task<ActionResult<UserDetailDto>> GetUserDetail()
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(currentUserId!);

            if (user == null)
            {
                return NotFound(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "Usuario no encontrado."
                });
            }

            return Ok(new UserDetailDto
            {
                Id = user.Id,
                Email = user.Email,
                FullName = user.Fullname,
                Roles = [.. await _userManager.GetRolesAsync(user)],
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                AccessFailedCount = user.AccessFailedCount
            });
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<UserDetailDto>>> GetUsers()
        {
            try
            {
                var users = await Task.Run(() =>
                {
                    var userList = _userManager.Users.Select(u => new UserDetailDto
                    {
                        Id = u.Id,
                        Email = u.Email,
                        FullName = u.Fullname,
                        Roles = _userManager.GetRolesAsync(u).Result.ToArray()
                    }).ToListAsync();


                    return userList;

                });

                return Ok(users);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
                return StatusCode(StatusCodes.Status500InternalServerError, "Error interno en el servidor");
            }
        }

        [HttpGet("all")]
        public async Task<ActionResult<IEnumerable<UserDetailDto>>> GetUsersAll()
        {
            try
            {
                var users = await Task.Run(() =>
                {
                    var userList = _userManager.Users.Select(u => new UserDetailDto
                    {
                        Id = u.Id,
                        Email = u.Email,
                        FullName = u.Fullname,
                        Roles = _userManager.GetRolesAsync(u).Result.ToArray()
                    }).ToListAsync();


                    return userList;

                });

                return Ok(users);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ha ocurrido un error: {ex.Message}");
                return StatusCode(StatusCodes.Status500InternalServerError, "Error interno en el servidor");
            }
        }

    }
}