using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace LogAnalyzer.Web.Migrations
{
    /// <inheritdoc />
    public partial class ProcessingLimitsAndIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_LogEvents_LogFileId",
                table: "LogEvents");

            migrationBuilder.DropIndex(
                name: "IX_LogEvents_Timestamp",
                table: "LogEvents");

            migrationBuilder.AddColumn<int>(
                name: "ProcessingAttempts",
                table: "LogFiles",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateTable(
                name: "LogFileHourStats",
                columns: table => new
                {
                    LogFileId = table.Column<int>(type: "int", nullable: false),
                    Hour = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Total = table.Column<int>(type: "int", nullable: false),
                    Flagged = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LogFileHourStats", x => new { x.LogFileId, x.Hour });
                    table.ForeignKey(
                        name: "FK_LogFileHourStats_LogFiles_LogFileId",
                        column: x => x.LogFileId,
                        principalTable: "LogFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_LogEvents_LogFileId_LineNumber",
                table: "LogEvents",
                columns: new[] { "LogFileId", "LineNumber" });

            migrationBuilder.CreateIndex(
                name: "IX_LogEvents_LogFileId_Timestamp_LineNumber",
                table: "LogEvents",
                columns: new[] { "LogFileId", "Timestamp", "LineNumber" });

            // Hourly dashboard statistics for the files that already exist.
            migrationBuilder.Sql("""
                INSERT INTO [LogFileHourStats] ([LogFileId], [Hour], [Total], [Flagged])
                SELECT e.[LogFileId], h.[Hour], COUNT(*), COUNT(f.[LogEventId])
                FROM [LogEvents] AS e
                CROSS APPLY (SELECT DATEADD(hour, DATEDIFF(hour, CAST('2000-01-01' AS datetime2), CAST(e.[Timestamp] AS datetime2)),
                                            CAST('2000-01-01' AS datetime2)) AS [Hour]) AS h
                LEFT JOIN (SELECT DISTINCT [LogEventId] FROM [AlertEvidence]) AS f ON f.[LogEventId] = e.[Id]
                GROUP BY e.[LogFileId], h.[Hour];
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "LogFileHourStats");

            migrationBuilder.DropIndex(
                name: "IX_LogEvents_LogFileId_LineNumber",
                table: "LogEvents");

            migrationBuilder.DropIndex(
                name: "IX_LogEvents_LogFileId_Timestamp_LineNumber",
                table: "LogEvents");

            migrationBuilder.DropColumn(
                name: "ProcessingAttempts",
                table: "LogFiles");

            migrationBuilder.CreateIndex(
                name: "IX_LogEvents_LogFileId",
                table: "LogEvents",
                column: "LogFileId");

            migrationBuilder.CreateIndex(
                name: "IX_LogEvents_Timestamp",
                table: "LogEvents",
                column: "Timestamp");
        }
    }
}
