using Auth.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using System.Text;

namespace Auth.Controllers
{
    [Route("/api/Auth")]
    [ApiController]
    public class AuthController:ControllerBase
    {
        private const string V = "admin";
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthController(UserManager<IdentityUser> _userManager, RoleManager<IdentityRole> _roleManager, IConfiguration _configuration) {
                this._userManager = _userManager;
                this._roleManager = _roleManager;
                this._configuration = _configuration;
                }
        [HttpPost("/login")]
        public async Task<IActionResult> Login([FromBody]LoginModel loginmodel)
        {
            try { 
            var user =await  _userManager.FindByEmailAsync(loginmodel.Username);
            if (user == null)
            {
                user= await _userManager.FindByNameAsync(loginmodel.Username);
            }
            Boolean test = await _userManager.CheckPasswordAsync(user, loginmodel.Password);
            if (user != null && await _userManager.CheckPasswordAsync(user, loginmodel.Password)) {

                var userRoles = await _userManager.GetRolesAsync(user);
                var AuthClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name,user.Email),
                    
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())

                };
                foreach (var role in userRoles) {
                    AuthClaims.Add(new Claim(ClaimTypes.Role, role));

                }
                var AuthSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(7),
                    claims: AuthClaims,
                    signingCredentials:new SigningCredentials(AuthSigningKey,SecurityAlgorithms.HmacSha256));

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            return Unauthorized();
            }
            catch (Exception ex) { return StatusCode(500, ex.Message); }
        }

        [HttpPost("/SignUp")]
        public async Task<IActionResult> SignUp([FromBody] RegisterModel registerModel)
        {
            try
            {
                var userExist = await _userManager.FindByEmailAsync(registerModel.Email);
                var userExist2 = await _userManager.FindByNameAsync(registerModel.Username);
                if (userExist2 != null)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Username already exists" });
                }
                if (userExist != null)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Email already exists" });
                }
                IdentityUser user = new()
                {
                    Email = registerModel.Email,
                    UserName = registerModel.Username,
                    SecurityStamp = Guid.NewGuid().ToString()

                };


                var result = await _userManager.CreateAsync(user, registerModel.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Something went wrong. Try Another Time!!!" });
                }

                //amelioration : créer un endpoint pour affecter le role user (est ce que ca peut affecter les performances)

                await _userManager.AddToRoleAsync(user, "user");

                return Ok(new Response { Status = "OK", Message = "User created succesfully" });


            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }
}
}
