using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace JWT.Models
{
    // 1
    public class ApplicationUser : IdentityUser
    {
        [Required, MaxLength(50)]
        public string FirstName { get; set; }

        [Required, MaxLength(50)]
        public string LastName { get; set; }
    }
}
