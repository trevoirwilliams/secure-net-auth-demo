# SecureAuthDemo Solution

A teaching sample for **Secure Authentication in ASP.NET Core**, demonstrating Identity, JWT, and MFA (TOTP).

## Projects

### 1. SecureAuthDemo.Api
ASP.NET Core Web API (minimal hosting) with:
- ASP.NET Core Identity + Entity Framework Core (SQLite)
- JWT Bearer authentication with intentionally lax security settings
- Endpoints for registration, login, and orders (user-scoped and admin-only)
- **Intentional security weaknesses** for teaching purposes (marked with `// INCORRECT:` comments)

### 2. SecureAuthDemo.Web
ASP.NET Core Razor Pages with:
- ASP.NET Core Identity UI (login, register, account management)
- **TOTP-based Multi-Factor Authentication (MFA)** using authenticator apps
- Custom authorization policy requiring 2FA for sensitive pages
- Shares the same Identity database with SecureAuthDemo.Api

## Database

Both projects use the **same SQLite database** (`secureauthdemo.db`) containing:
- ASP.NET Core Identity tables (AspNetUsers, AspNetRoles, etc.)
- Orders table (for authorization demos)

## Quick Start

### Build and Run

```powershell
# Build solution
dotnet build SecureAuthDemo.sln

# Run API (default: http://localhost:5000)
cd SecureAuthDemo.Api
dotnet run

# Run Web (default: http://localhost:5001) - in another terminal
cd SecureAuthDemo.Web
dotnet run
```

### Pre-seeded Admin User
- Email: `admin@example.com`
- Password: `Admin123!`
- Role: Admin
- Has sample orders seeded

## MFA (TOTP) Flow in SecureAuthDemo.Web

### Enable Authenticator App
1. Navigate to `/Identity/Account/Manage/TwoFactorAuthentication` (or use the home page link)
2. Click **Add authenticator app**
3. Scan the QR code with an authenticator app (Microsoft Authenticator, Google Authenticator, Authy, etc.)
   - Or manually enter the shared key
4. Enter a verification code from the app to activate 2FA
5. Save the recovery codes displayed

### Accessing MFA-Protected Content
- Navigate to `/Admin/SensitiveSettings`
- If 2FA is **not enabled**, you'll be denied access (policy `RequireTwoFactorEnabled`)
- If 2FA **is enabled**, you can access the sensitive admin page

### Login with 2FA
1. Enter email and password at `/Identity/Account/Login`
2. If 2FA is enabled, you'll be redirected to `/Identity/Account/LoginWith2fa`
3. Enter the current TOTP code from your authenticator app
4. Successfully authenticated with MFA

## Key Classes and Configuration

### SecureAuthDemo.Web

**Program.cs**
- Configures shared `ApplicationDbContext` from `SecureAuthDemo.Api.Data`
- Sets up Identity with TOTP token providers
- Registers custom authorization policy `RequireTwoFactorEnabled`
- Intentionally **missing HTTPS redirection** for teaching

**Authorization/TwoFactorRequirement.cs**
- Custom authorization requirement for MFA

**Authorization/TwoFactorRequirementHandler.cs**
- Checks `user.TwoFactorEnabled` from the database
- Succeeds only if 2FA is enabled

**Admin/SensitiveSettings.cshtml.cs**
- Protected with `[Authorize(Policy = "RequireTwoFactorEnabled")]`
- Demonstrates MFA-gated sensitive content

**Areas/Identity/Pages/**
- Scaffolded Identity UI pages for:
  - Account management (`/Account/Manage/Index`)
  - Two-factor authentication (`/Account/Manage/TwoFactorAuthentication`)
  - Enable authenticator (`/Account/Manage/EnableAuthenticator`)
  - Show/generate recovery codes
  - Disable 2FA
  - Login with 2FA code

## Intentional Security Weaknesses (For Teaching)

The solution includes **intentional insecure practices** marked with `// INCORRECT:` comments:

1. **Not using proven authentication frameworks**
   - `/api/auth/insecure-login` bypasses Identity entirely
   - Uses plaintext credential check in `Auth/InsecureAuthStore.cs`

2. **Hardcoded credentials and roles**
   - `InsecureAuthStore.cs` has hardcoded users with plaintext passwords
   - Admin seeding hardcodes password in `IdentitySeeder.cs`

3. **Weak password hashing**
   - Insecure endpoint uses plaintext equality check

4. **Missing HTTPS enforcement**
   - No `app.UseHttpsRedirection()` in Program.cs

5. **Weak brute-force protection**
   - Lockout disabled: `options.Lockout.AllowedForNewUsers = false`

6. **User enumeration via leaky error messages**
   - Login errors distinguish "User does not exist" vs "Invalid password"

7. **Misconfigured JWT tokens**
   - Issuer/audience validation disabled
   - Lifetime validation disabled (accepts expired tokens)
   - `RequireHttpsMetadata = false`
   - Symmetric key stored in appsettings.json
   - 1-day token expiration (too long)

## Security Hardening TODOs (Course Topics)

- **Remove** insecure login endpoint and `InsecureAuthStore`
- **Enable** HTTPS redirection (`app.UseHttpsRedirection()`)
- **Enable** account lockout for brute-force protection
- **Unify** error messages to prevent user enumeration
- **Restore** JWT validation (issuer, audience, lifetime)
- **Move** JWT signing key to secure storage (User Secrets, Azure Key Vault)
- **Shorten** JWT lifetime and add refresh tokens
- **Enforce** MFA for all admin users (policy)
- **Add** rate limiting and CAPTCHA for login endpoints
- **Implement** audit logging for sensitive operations
- **Configure** secure cookie options (SameSite, Secure, HttpOnly)

## Testing MFA

### Register a New User
```powershell
# Via API
Invoke-RestMethod -Method Post -Uri http://localhost:5000/api/auth/register -ContentType "application/json" -Body (@{ email="testuser@example.com"; password="Test123" } | ConvertTo-Json)
```

### Enable 2FA for the User
1. Go to http://localhost:5001 (SecureAuthDemo.Web)
2. Log in with the registered user
3. Navigate to **Manage Account** → **Two-factor authentication**
4. Click **Add authenticator app**
5. Scan QR code or enter manual key in your authenticator app
6. Enter verification code to activate

### Try Accessing Sensitive Page
- Before enabling 2FA: Navigate to `/Admin/SensitiveSettings` → **Forbidden (403)**
- After enabling 2FA: Navigate to `/Admin/SensitiveSettings` → **Success (200)**

## Architecture

```
SecureAuthDemo/
├── SecureAuthDemo.Api/
│   ├── Auth/
│   │   ├── ITokenService.cs
│   │   ├── TokenService.cs
│   │   └── InsecureAuthStore.cs (INCORRECT)
│   ├── Configuration/
│   │   ├── IdentitySeeder.cs
│   │   └── SampleDataSeeder.cs
│   ├── Data/
│   │   └── ApplicationDbContext.cs (shared)
│   ├── Domain/
│   │   └── Order.cs
│   ├── Dtos/
│   │   ├── LoginRequest.cs
│   │   └── RegisterRequest.cs
│   ├── Migrations/
│   ├── Program.cs
│   └── appsettings.json (JWT config)
│
└── SecureAuthDemo.Web/
    ├── Admin/
    │   ├── SensitiveSettings.cshtml
    │   └── SensitiveSettings.cshtml.cs (MFA-protected)
    ├── Areas/Identity/Pages/
    │   ├── Account/
    │   │   ├── Login.cshtml
    │   │   ├── Register.cshtml
    │   │   ├── LoginWith2fa.cshtml
    │   │   └── Manage/
    │   │       ├── TwoFactorAuthentication.cshtml
    │   │       ├── EnableAuthenticator.cshtml
    │   │       ├── ShowRecoveryCodes.cshtml
    │   │       └── ...
    ├── Authorization/
    │   ├── TwoFactorRequirement.cs
    │   └── TwoFactorRequirementHandler.cs
    ├── Pages/
    │   ├── Index.cshtml
    │   ├── Privacy.cshtml
    │   └── Shared/
    │       ├── _Layout.cshtml
    │       └── _LoginPartial.cshtml
    ├── Program.cs (MFA config)
    └── appsettings.json (shared connection string)
```

## License

Educational use only. Not for production deployment without security hardening.

