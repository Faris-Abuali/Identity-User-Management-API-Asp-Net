using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace User.Management.API.Configurations
{
    public class IdentityRoleEntityTypeConfiguration : IEntityTypeConfiguration<IdentityRole>
    {
        public void Configure(EntityTypeBuilder<IdentityRole> builder)
        {
            this.SeedRoles(builder);
        }


        // Seed data for Roles table
        private void SeedRoles(EntityTypeBuilder<IdentityRole> builder)
        {
            var roles = new List<IdentityRole>
            {
                new IdentityRole()
                {
                    Name = "Admin",
                    ConcurrencyStamp = "1", // a random value that should change whenever a role is persisted to the data store
                    NormalizedName = "Admin"
                },
                new IdentityRole()
                {
                    Name = "User",
                    ConcurrencyStamp = "2", // a random value that should change whenever a role is persisted to the data store
                    NormalizedName = "User"
                },
                new IdentityRole()
                {
                    Name = "HR",
                    ConcurrencyStamp = "3", // a random value that should change whenever a role is persisted to the data store
                    NormalizedName = "HR"
                },
            };


            builder.HasData(roles);
        }
    }
}
