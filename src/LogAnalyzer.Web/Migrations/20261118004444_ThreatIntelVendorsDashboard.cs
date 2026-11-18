using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace LogAnalyzer.Web.Migrations
{
    /// <inheritdoc />
    public partial class ThreatIntelVendorsDashboard : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "AttributesJson",
                table: "IpReputations",
                type: "nvarchar(max)",
                maxLength: 16000,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(4000)",
                oldMaxLength: 4000,
                oldNullable: true);

            migrationBuilder.AddColumn<string>(
                name: "VendorVerdict",
                table: "IpReputations",
                type: "nvarchar(120)",
                maxLength: 120,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "VendorVerdict",
                table: "IpReputations");

            migrationBuilder.AlterColumn<string>(
                name: "AttributesJson",
                table: "IpReputations",
                type: "nvarchar(4000)",
                maxLength: 4000,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)",
                oldMaxLength: 16000,
                oldNullable: true);
        }
    }
}
