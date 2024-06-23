using Microsoft.EntityFrameworkCore;
using Task1_1.Models;

namespace Task1_1.Data
{
    public class YourDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        public YourDbContext(DbContextOptions<YourDbContext> options) : base(options) { }
    }
}