using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace LogAnalyzer.Web.Migrations
{
    /// <inheritdoc />
    public partial class UserTiersAndDeletion : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_LogFiles_AspNetUsers_UploadedById",
                table: "LogFiles");

            migrationBuilder.AlterColumn<string>(
                name: "UploadedById",
                table: "LogFiles",
                type: "nvarchar(450)",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");

            migrationBuilder.AddColumn<string>(
                name: "UploadedByName",
                table: "LogFiles",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Tier",
                table: "AspNetUsers",
                type: "nvarchar(10)",
                maxLength: 10,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "EscalatedAt",
                table: "Alerts",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "EscalatedBy",
                table: "Alerts",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddForeignKey(
                name: "FK_LogFiles_AspNetUsers_UploadedById",
                table: "LogFiles",
                column: "UploadedById",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            // Who uploaded each existing file (kept when the account is deleted later).
            migrationBuilder.Sql("""
                UPDATE f SET f.[UploadedByName] = u.[Email]
                FROM [LogFiles] AS f INNER JOIN [AspNetUsers] AS u ON u.[Id] = f.[UploadedById];
                """);

            // Existing analysts start as SOC 1 (least privilege); an administrator promotes them to SOC 2.
            migrationBuilder.Sql("""
                UPDATE u SET u.[Tier] = 'Soc1'
                FROM [AspNetUsers] AS u
                INNER JOIN [AspNetUserRoles] AS ur ON ur.[UserId] = u.[Id]
                INNER JOIN [AspNetRoles] AS r ON r.[Id] = ur.[RoleId]
                WHERE r.[Name] = 'Analyst';
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_LogFiles_AspNetUsers_UploadedById",
                table: "LogFiles");

            migrationBuilder.DropColumn(
                name: "UploadedByName",
                table: "LogFiles");

            migrationBuilder.DropColumn(
                name: "Tier",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "EscalatedAt",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "EscalatedBy",
                table: "Alerts");

            migrationBuilder.AlterColumn<string>(
                name: "UploadedById",
                table: "LogFiles",
                type: "nvarchar(450)",
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "nvarchar(450)",
                oldNullable: true);

            migrationBuilder.AddForeignKey(
                name: "FK_LogFiles_AspNetUsers_UploadedById",
                table: "LogFiles",
                column: "UploadedById",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }
    }
}
