using JWT.Helpers;
using JWT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;
// var userIdFromToken = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
namespace JWT.Services
{
    public class Auth : IAuth
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<Auth> _logger;
        private readonly Jwt _jwt;
        private readonly RoleManager<IdentityRole> _roleManager;
        public Auth(UserManager<ApplicationUser> userManager, IOptions<Jwt> jwt, ApplicationDbContext context, RoleManager<IdentityRole> roleManager)
        {
            _context = context;
            _jwt = jwt.Value;
            _userManager = userManager;
            _roleManager = roleManager;
        }
        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            ApplicationUser? userCheack =  await _userManager.FindByEmailAsync(model.Email) ;
            if (userCheack is not null)
            {
                return new AuthModel { Message= "Email is aready exixt"};
            }
            userCheack = await _userManager.FindByNameAsync(model.Username);
            if (userCheack is not null)
            {
                return new AuthModel { Message = "UserName is aready exixt" };
            }
            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName
            };

            var Result = await _userManager.CreateAsync(user,model.Password);
            if (!Result.Succeeded)
            {
                string errors = System.String.Empty; 
                foreach(var error in Result.Errors)
                {
                   // error += e.Description;
                    errors += $"{error.Description},";
                    return new AuthModel { Message = errors };
                }

            }
           
                // add to role 
                await _userManager.AddToRoleAsync(user,"User");
                var userClaims = await _userManager.GetClaimsAsync(user);
                var roles = await _userManager.GetRolesAsync(user);
                var roleClaims = new List<Claim>();

               foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id) ,

            }
            .Union(userClaims)
            .Union(roleClaims);
            await _userManager.AddClaimsAsync(user, claims);
            var jwtSecurityToken = await CreateJwtToken(user);

                return new AuthModel
                {
                    Email = user.Email,
                    ExpiresOn = jwtSecurityToken.ValidTo,
                    IsAuthenticated = true,
                    Roles = new List<string> { "User" },
                    Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                    Username = user.UserName
                };
            

        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id) ,
               
            }
            .Union(userClaims)
            .Union(roleClaims);
            //await _userManager.AddClaimsAsync(user, claims);
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
            issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var authModel = new AuthModel();

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password is incorrect!";
                return authModel;
            }

            var jwtSecurityToken = await CreateJwtToken(user);
            var rolesList = await _userManager.GetRolesAsync(user);

            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            authModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authModel.Roles = rolesList.ToList();

            return authModel;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);

            if (user is null || !await _roleManager.RoleExistsAsync(model.Role))
                return "Invalid user ID or Role";

            if (await _userManager.IsInRoleAsync(user, model.Role))
                return "User already assigned to this role";

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            return result.Succeeded ? string.Empty : "Sonething went wrong";
        }

    }
}
