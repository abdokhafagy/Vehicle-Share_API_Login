using Microsoft.EntityFrameworkCore;

namespace LoginRegisterApi.Data.Models
{
    [Owned]
    public class RefreshToken
    {
        public string Token { get; set; }
        public DateTime ExpiresOn { get; set; }
        public DateTime CreatedOn { get; set; }
        public DateTime? RevokeOn { get; set; }
        public bool IsExpire => DateTime.UtcNow >= ExpiresOn;
        public bool IsActive => RevokeOn == null && !IsExpire;
    }
}
