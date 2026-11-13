using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace LogAnalyzer.Web.Migrations
{
    /// <inheritdoc />
    public partial class ProcessingTimings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "DetectionMilliseconds",
                table: "LogFiles",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "ParseMilliseconds",
                table: "LogFiles",
                type: "bigint",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DetectionMilliseconds",
                table: "LogFiles");

            migrationBuilder.DropColumn(
                name: "ParseMilliseconds",
                table: "LogFiles");
        }
    }
}
