using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SchoolWebApp.Models;

namespace SchoolWebApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private IConfiguration _config;

        public AccountController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Register register)
        {
            var user = new IdentityUser { UserName = register.UserName };
            var result = await _userManager.CreateAsync(user,register.Password);

            if (result.Succeeded)
            {
                return Ok(new { message = "User registered successfully" });
            }
            return BadRequest(result.Errors);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRole = await _userManager.GetRolesAsync(user);

                var authclaims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),

                };
                authclaims.AddRange(userRole.Select(role => new Claim(ClaimTypes.Role, role)));

                var token = new JwtSecurityToken(
                    issuer: _config["Jwt:Issuer"],
                    expires: DateTime.UtcNow.AddMinutes(Double.Parse(_config["Jwt:ExpiryMinutes"]!)),
                    claims: authclaims,
                    signingCredentials: new
                    SigningCredentials(new  SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:key"]!)),
                    SecurityAlgorithms.HmacSha256)
                    
                    );
                return Ok(new {Token = new JwtSecurityTokenHandler().WriteToken(token)});
            }
            return Unauthorized();
        }


        [HttpPost("add-role")]
        public async Task<IActionResult> AddRole([FromBody] string role)
        {
            if(!await _roleManager.RoleExistsAsync(role))
            {
                var result = await _roleManager.CreateAsync(new IdentityRole(role));
                if (result.Succeeded)
                {
                    return Ok(new {message = "Role Added Successfully" , Role = role});
                }
                return BadRequest(result.Errors);
            }
            return BadRequest("Role already exist ");
        }


        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] UserRole model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user == null)
            {
                return BadRequest("User Not found");
            }
            var result = await _userManager.AddToRoleAsync(user,model.Role);
            if (result.Succeeded)
            {
                return Ok(new { message = "Role assign successfully" });
            }
            return BadRequest(result.Errors);
        }

    }
}
