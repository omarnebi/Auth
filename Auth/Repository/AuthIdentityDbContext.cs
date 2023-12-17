using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Auth.Repository
{
    public class AuthIdentityDbContext: IdentityDbContext<IdentityUser>
    {
        public AuthIdentityDbContext(DbContextOptions<AuthIdentityDbContext> options) : base(options) { }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }
    }
}
