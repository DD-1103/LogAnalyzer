using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace LogAnalyzer.Web.Migrations
{
    /// <inheritdoc />
    public partial class FirewallLogs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Format",
                table: "LogFiles",
                type: "nvarchar(300)",
                maxLength: 300,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RequestedFormat",
                table: "LogFiles",
                type: "nvarchar(40)",
                maxLength: 40,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Source",
                table: "LogFiles",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "WebAccess");

            migrationBuilder.AddColumn<string>(
                name: "Action",
                table: "LogEvents",
                type: "nvarchar(10)",
                maxLength: 10,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DestinationIp",
                table: "LogEvents",
                type: "nvarchar(45)",
                maxLength: 45,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "DestinationPort",
                table: "LogEvents",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Device",
                table: "LogEvents",
                type: "nvarchar(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "EventType",
                table: "LogEvents",
                type: "nvarchar(40)",
                maxLength: 40,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RuleName",
                table: "LogEvents",
                type: "nvarchar(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "SourcePort",
                table: "LogEvents",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ThreatName",
                table: "LogEvents",
                type: "nvarchar(300)",
                maxLength: 300,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Transport",
                table: "LogEvents",
                type: "nvarchar(16)",
                maxLength: 16,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ActionFilter",
                table: "DetectionRules",
                type: "nvarchar(60)",
                maxLength: 60,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AppliesTo",
                table: "DetectionRules",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "WebAccess");

            migrationBuilder.AddColumn<string>(
                name: "PortFilter",
                table: "DetectionRules",
                type: "nvarchar(200)",
                maxLength: 200,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Format",
                table: "LogFiles");

            migrationBuilder.DropColumn(
                name: "RequestedFormat",
                table: "LogFiles");

            migrationBuilder.DropColumn(
                name: "Source",
                table: "LogFiles");

            migrationBuilder.DropColumn(
                name: "Action",
                table: "LogEvents");

            migrationBuilder.DropColumn(
                name: "DestinationIp",
                table: "LogEvents");

            migrationBuilder.DropColumn(
                name: "DestinationPort",
                table: "LogEvents");

            migrationBuilder.DropColumn(
                name: "Device",
                table: "LogEvents");

            migrationBuilder.DropColumn(
                name: "EventType",
                table: "LogEvents");

            migrationBuilder.DropColumn(
                name: "RuleName",
                table: "LogEvents");

            migrationBuilder.DropColumn(
                name: "SourcePort",
                table: "LogEvents");

            migrationBuilder.DropColumn(
                name: "ThreatName",
                table: "LogEvents");

            migrationBuilder.DropColumn(
                name: "Transport",
                table: "LogEvents");

            migrationBuilder.DropColumn(
                name: "ActionFilter",
                table: "DetectionRules");

            migrationBuilder.DropColumn(
                name: "AppliesTo",
                table: "DetectionRules");

            migrationBuilder.DropColumn(
                name: "PortFilter",
                table: "DetectionRules");
        }
    }
}
