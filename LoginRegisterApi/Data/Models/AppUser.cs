using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;

namespace LoginRegisterApi.Data.Models
{
    public class AppUser :IdentityUser
    {

       public List<RefreshToken>? RefreshTokens { get; set; }
    }
}
