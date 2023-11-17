using LoginRegisterApi.Data.Models;
using LoginRegisterApi.Models;
using LoginRegisterApi.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LoginRegisterApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IAutherServ _autherServ;

        /* private readonly UserManager<AppUser> _userManager;
private readonly IConfiguration _conf;*/
        public AccountController(IAutherServ autherServ)
        {
            _autherServ = autherServ;
        }

        /* public AccountController(UserManager<AppUser> userManager,IConfiguration conf)
         {
         _userManager = userManager;
             _conf = conf;
         }*/
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var resulit = await _autherServ.RegisterAsync(model);
            if (!resulit.IsAuth)
                return BadRequest(resulit.Message);
            return Ok(resulit);
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var resulit = await _autherServ.LoginAsync(model);
            if (!resulit.IsAuth)
                return BadRequest(resulit.Message);
            if (!string.IsNullOrEmpty(resulit.RefreshToken))
                setRefreshtokenCookes(resulit.RefreshToken, resulit.RefreshTokenExpiration);
            return Ok(resulit);
        }
        [HttpPost("Addrole")]
        public async Task<IActionResult> Addrole([FromBody] RoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var resulit = await _autherServ.AddRoleAsync(model);
            
            return Ok(resulit);
        }

        [HttpGet("refreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            var result = await _autherServ.RefreshTokenAsync(refreshToken);

            if (!result.IsAuth)
                return BadRequest(result);

            setRefreshtokenCookes(result.RefreshToken, result.RefreshTokenExpiration);

            return Ok(result);
        }

        [HttpPost("revokeToken")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeToken model)
        {
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest("Token is required!");

            var result = await _autherServ.RevokeTokenAsync(token);

            if (!result)
                return BadRequest("Token is invalid!");

            return Ok();
        }
        [HttpPost("Reset-token")]
        public async Task<IActionResult> ResetTokenPassword([FromBody] ResetPassTokenModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var resulit = await _autherServ.ResetPasswordTokenAsync(model);
            if (!resulit.IsAuth)
                return BadRequest(resulit.Message);

            return Ok(resulit);
        }
       
        [HttpPost("Reset")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPassModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var resulit = await _autherServ.ResetPasswordAsync(model);
            if (!resulit.IsAuth)
                return BadRequest(resulit.Message);

            return Ok(resulit);
        }
        private void setRefreshtokenCookes(string refeshtoken, DateTime expirs)
        {
            var cookOption = new CookieOptions
            {
                HttpOnly = true,
                Expires = expirs.ToLocalTime()
            };
            Response.Cookies.Append("refreshToken", refeshtoken, cookOption);
        }

        /*  public async Task<IActionResult> Register(RegisterModel newUser)
          {
              if(ModelState.IsValid)
              {
                  AppUser _appUser = new AppUser()
                  {
                      UserName = newUser.UserName,
                      Email = newUser.Email,
                  };
                  IdentityResult result=await _userManager.CreateAsync(_appUser,newUser.Password);
                  if(result.Succeeded)
                  {
                      return Ok("succes");
                  }
                  else
                  {
                      foreach (var item in result.Errors)
                          ModelState.AddModelError("", item.Description);
                  }
              }
              return BadRequest(ModelState);

          }*/

        // [HttpPost("login")]
        /*  public async Task<IActionResult> Login(LoginModel login)
          {
              if (ModelState.IsValid)
              {
                  AppUser user = await _userManager.FindByNameAsync(login.UserName);
                  if (user != null)
                  {
                      if(await _userManager.CheckPasswordAsync(user,login.Password))
                      {
                          var claims = new List<Claim>();
                          claims.Add(new Claim(ClaimTypes.Name, user.UserName));
                          claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
                          claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
                          var roles =await  _userManager.GetRolesAsync(user);
                          foreach(var role in roles)
                          {
                              claims.Add(new Claim(ClaimTypes.Role,role.ToString()));  
                          }
                          // sign cradintioal
                          var key =new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_conf["JWT:SecretKey"]));
                          var sc=new SigningCredentials(key,SecurityAlgorithms.HmacSha256);
                          var token = new JwtSecurityToken(
                              claims: claims,
                              issuer: _conf["JWT:Issuer"],
                              audience: _conf["Jwt:Audience"],
                              expires:DateTime.Now.AddHours(1)
                          );
                          var _token = new
                          {
                              token = new JwtSecurityTokenHandler().WriteToken(token),
                              expiration = token.ValidTo
                          };
                      }
                      else
                      {
                          return Unauthorized();
                      }
                  }
              }
              return BadRequest(ModelState);

          }*/

    }
}
