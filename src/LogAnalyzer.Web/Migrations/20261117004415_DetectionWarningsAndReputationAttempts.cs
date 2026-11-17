using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace LogAnalyzer.Web.Migrations
{
    /// <inheritdoc />
    public partial class DetectionWarningsAndReputationAttempts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "DetectionWarnings",
                table: "LogFiles",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastAttemptAt",
                table: "IpReputations",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastAttemptError",
                table: "IpReputations",
                type: "nvarchar(500)",
                maxLength: 500,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DetectionWarnings",
                table: "LogFiles");

            migrationBuilder.DropColumn(
                name: "LastAttemptAt",
                table: "IpReputations");

            migrationBuilder.DropColumn(
                name: "LastAttemptError",
                table: "IpReputations");
        }
    }
}
