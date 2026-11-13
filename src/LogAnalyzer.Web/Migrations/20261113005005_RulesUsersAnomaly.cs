using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace LogAnalyzer.Web.Migrations
{
    /// <inheritdoc />
    public partial class RulesUsersAnomaly : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<double>(
                name: "ScoreThreshold",
                table: "DetectionRules",
                type: "float",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "CreatedAt",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: false,
                defaultValueSql: "SYSUTCDATETIME()");

            migrationBuilder.AddColumn<bool>(
                name: "IsDisabled",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastLoginAt",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Details",
                table: "Alerts",
                type: "nvarchar(1000)",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.AddColumn<double>(
                name: "Score",
                table: "Alerts",
                type: "float",
                nullable: true);

            // Default anomaly-detection rule (Isolation Forest). Inserted here rather than in DbSeeder
            // so that existing databases get it too; skipped if an admin already created one with this name.
            migrationBuilder.Sql("""
                IF NOT EXISTS (SELECT 1 FROM DetectionRules WHERE Name = N'Anomalous client behaviour (Isolation Forest)')
                INSERT INTO DetectionRules (Name, Description, AttackType, Severity, Kind, Field, Threshold, ScoreThreshold, IsEnabled, CreatedAt)
                VALUES (N'Anomalous client behaviour (Isolation Forest)',
                        N'Machine-learning rule: flags IPs whose overall behaviour (rate, errors, unique paths, URL length, special characters...) is unusual compared with the other clients in the same log file.',
                        N'Anomaly', N'Low', N'Anomaly', N'Url', 20, 0.62, 1, SYSUTCDATETIME());
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ScoreThreshold",
                table: "DetectionRules");

            migrationBuilder.DropColumn(
                name: "CreatedAt",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "IsDisabled",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "LastLoginAt",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "Details",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "Score",
                table: "Alerts");
        }
    }
}
