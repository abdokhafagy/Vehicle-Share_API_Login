using System.Text.Json.Serialization;

namespace LoginRegisterApi.Models
{
    public class AuthModel
    {
        public string        Message    { get; set; }
        public bool          IsAuth     { get; set; }
        public string        UserName   { get; set; }
        public string        Email      { get; set; }
        public List<string>  Roles      { get; set; }
        public string        Token      { get; set; }
      
        public DateTime      Expiration { get; set; }

        [JsonIgnore]
        public string? RefreshToken { get; set; }
      
        public DateTime RefreshTokenExpiration { get; set; }

    }
}
