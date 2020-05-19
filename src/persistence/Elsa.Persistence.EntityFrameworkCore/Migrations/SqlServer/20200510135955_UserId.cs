using Microsoft.EntityFrameworkCore.Migrations;

namespace Elsa.Persistence.EntityFrameworkCore.Migrations.SqlServer
{
    public partial class UserId : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
            name: "UserId",
            table: "WorkflowDefinitionVersions",
            nullable: true,
            defaultValue: "");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
            name: "UserId",
            table: "WorkflowDefinitionVersions");
        }
    }
}
