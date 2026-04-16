-- VoiceCoder AI — Microsoft SQL Server Auth Schema


USE master;
GO

-- Create database 
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'VoiceCoderDB')
BEGIN
    CREATE DATABASE VoiceCoderDB;
END
GO

USE VoiceCoderDB;
GO

--  USERS TABLE
IF OBJECT_ID('dbo.Users', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.Users (
        id          INT IDENTITY(1,1) PRIMARY KEY,
        name        NVARCHAR(100)   NOT NULL,
        email       NVARCHAR(255)   NOT NULL,
        password    NVARCHAR(255)   NOT NULL,   -- bcrypt hash
        created_at  DATETIME2       NOT NULL DEFAULT GETDATE(),
        last_login  DATETIME2       NULL,
        is_active   BIT             NOT NULL DEFAULT 1,

        CONSTRAINT UQ_Users_Email UNIQUE (email)
    );
END
GO

--  SESSIONS TABLE  
IF OBJECT_ID('dbo.Sessions', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.Sessions (
        id          INT IDENTITY(1,1) PRIMARY KEY,
        user_id     INT             NOT NULL
                        REFERENCES dbo.Users(id) ON DELETE CASCADE,
        token       NVARCHAR(512)   NOT NULL,   -- JWT or random token
        expires_at  DATETIME2       NOT NULL,
        created_at  DATETIME2       NOT NULL DEFAULT GETDATE(),
        ip_address  NVARCHAR(45)    NULL,
        user_agent  NVARCHAR(500)   NULL,

        CONSTRAINT UQ_Sessions_Token UNIQUE (token)
    );
END
GO

-- Index: quickly look up sessions by token
CREATE INDEX IF NOT EXISTS IX_Sessions_Token
    ON dbo.Sessions (token)
    WHERE expires_at > GETDATE();
GO

--  STORED PROCEDURES
-- SP: Register a new user
CREATE OR ALTER PROCEDURE dbo.sp_CreateUser
    @name       NVARCHAR(100),
    @email      NVARCHAR(255),
    @password   NVARCHAR(255)   -- pass the bcrypt hash from Node
AS
BEGIN
    SET NOCOUNT ON;

    IF EXISTS (SELECT 1 FROM dbo.Users WHERE email = LOWER(@email))
    BEGIN
        SELECT 0 AS success, 'EMAIL_EXISTS' AS error_code;
        RETURN;
    END

    INSERT INTO dbo.Users (name, email, password)
    VALUES (@name, LOWER(@email), @password);

    SELECT 1 AS success, SCOPE_IDENTITY() AS user_id, '' AS error_code;
END
GO

-- SP: Fetch user by email
CREATE OR ALTER PROCEDURE dbo.sp_GetUserByEmail
    @email NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;
    SELECT id, name, email, password, is_active
    FROM   dbo.Users
    WHERE  email = LOWER(@email);
END
GO

-- SP: Update last_login timestamp
CREATE OR ALTER PROCEDURE dbo.sp_UpdateLastLogin
    @user_id INT
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE dbo.Users
    SET    last_login = GETDATE()
    WHERE  id = @user_id;
END
GO

-- SP: Store a new session token
CREATE OR ALTER PROCEDURE dbo.sp_CreateSession
    @user_id    INT,
    @token      NVARCHAR(512),
    @expires_at DATETIME2,
    @ip_address NVARCHAR(45)  = NULL,
    @user_agent NVARCHAR(500) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.Sessions (user_id, token, expires_at, ip_address, user_agent)
    VALUES (@user_id, @token, @expires_at, @ip_address, @user_agent);
END
GO

-- SP: Validate a session token
CREATE OR ALTER PROCEDURE dbo.sp_ValidateSession
    @token NVARCHAR(512)
AS
BEGIN
    SET NOCOUNT ON;
    SELECT s.token, s.expires_at, u.id, u.name, u.email
    FROM   dbo.Sessions s
    JOIN   dbo.Users    u ON u.id = s.user_id
    WHERE  s.token      = @token
      AND  s.expires_at > GETDATE()
      AND  u.is_active  = 1;
END
GO

-- SP: Delete / invalidate a session (sign out)
CREATE OR ALTER PROCEDURE dbo.sp_DeleteSession
    @token NVARCHAR(512)
AS
BEGIN
    SET NOCOUNT ON;
    DELETE FROM dbo.Sessions WHERE token = @token;
END
GO

-- SP: Clean up expired sessions (run as a scheduled job)
CREATE OR ALTER PROCEDURE dbo.sp_PurgeExpiredSessions
AS
BEGIN
    SET NOCOUNT ON;
    DELETE FROM dbo.Sessions WHERE expires_at <= GETDATE();
    SELECT @@ROWCOUNT AS deleted_rows;
END
GO

PRINT 'VoiceCoderDB schema created successfully.';
