using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Elsa.Persistence.EntityFrameworkCore.DbContexts
{
    public class SqlServerContextFactory : IDesignTimeDbContextFactory<SqlServerContext>
    {
        public SqlServerContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<SqlServerContext>();
            var migrationAssembly = typeof(SqlServerContext).Assembly.FullName;
            var connectionString = @"Server=DESKTOP-48PT01K\SQLEXPRESS;Database=Elsa;User=elsa;Password=123;"; // @Environment.GetEnvironmentVariable("EF_CONNECTIONSTRING");

            if(connectionString == null)
                throw new InvalidOperationException("Set the EF_CONNECTIONSTRING environment variable to a valid SQL Server connection string. E.g. SET EF_CONNECTIONSTRING=Server=DESKTOP-48PT01K\\SQLEXPRESS;Database=Elsa;User=elsa;Password=123;");
            
            optionsBuilder.UseSqlServer(
                connectionString,
                x => x.MigrationsAssembly(migrationAssembly)
            );

            return new SqlServerContext(optionsBuilder.Options);
        }
    }
}