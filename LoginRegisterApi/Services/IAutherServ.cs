using LoginRegisterApi.Models;
using Microsoft.AspNetCore.Mvc;

namespace LoginRegisterApi.Services
{
    public interface IAutherServ
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> LoginAsync(LoginModel model);
        Task<AuthModel> ResetPasswordAsync(ResetPassModel model);
        Task<string> AddRoleAsync(RoleModel model);
        Task<AuthModel> RefreshTokenAsync(string token);
        Task<bool> RevokeTokenAsync(string token);
        Task<AuthModel> ResetPasswordTokenAsync(ResetPassTokenModel model);
    }

}
