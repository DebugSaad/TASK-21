# Task 21

This documentation provides details on the available API endpoints in the server. IT includes mock JSON data for request bodies to help developers test the APIs purely.

## Auth Features

**Base URL:** `/api/auth`

### 1. Register User

**Endpoint:** `POST /api/auth/register`
**Description:** Registers a new user account.

**Mock Request Body (Success):**

```json
{
  "email": "testuser@example.com",
  "password": "StrongPassword123!",
  "username": "testuser",
  "mfa": {
    "enabled": true,
    "mode": "FIRST_LOGIN_ONLY"
  }
}
```

**Mock Request Body (Minimal):**

```json
{
  "email": "minimal@example.com",
  "password": "AnotherPassword456"
}
```

**Response (Success - 201 Created):**

```json
{
  "message": "User registered. OTP sent to email. Please verify to activate account.",
  "mfaMode": "FIRST_LOGIN_ONLY",
  "action": "VERIFY_OTP_REQUIRED",
  "email": "testuser@example.com"
}
```

**Response (Error - 400 Bad Request):**

```json
{
  "message": "Email already exists"
}
```

---

### 2. Verify OTP (Account Activation)

**Endpoint:** `POST /api/auth/verify-otp`
**Description:** Verifies the OTP sent to email after registration to activate the account.

**Mock Request Body:**

```json
{
  "email": "testuser@example.com",
  "otp": "123456"
}
```

_(Note: Replace `123456` with the actual OTP received via email/logs)_

**Response (Success - 200 OK):**

```json
{
  "message": "Email verified successfully.",
  "user": {
    "id": 1,
    "email": "testuser@example.com",
    "username": "testuser"
  },
  "tokens": {
    "accessToken": "eyJhbG...",
    "refreshToken": "eyJhbG..."
  }
}
```

---

### 3. Login

**Endpoint:** `POST /api/auth/login`
**Description:** Authenticates a user. May require MFA verification steps depending on user settings.

**Mock Request Body:**

```json
{
  "email": "testuser@example.com",
  "password": "StrongPassword123!"
}
```

**Response (Success - Direct Login - 200 OK):**

```json
{
  "message": "Login successful",
  "user": {
    "id": 1,
    "email": "testuser@example.com",
    "username": "testuser"
  },
  "tokens": {
    "accessToken": "eyJhbG...",
    "refreshToken": "eyJhbG..."
  },
  "mfaRequired": false
}
```

**Response (Success - MFA Required - 200 OK):**

```json
{
  "message": "OTP sent to email. Please verify to complete login.",
  "mfaRequired": true,
  "userId": 1,
  "email": "testuser@example.com"
}
```

**Response (Error - Invalid Credentials - 401/403):**

```json
{
  "message": "Invalid credentials"
}
```

---

### 4. Verify Login OTP (MFA)

**Endpoint:** `POST /api/auth/verify-login-otp`
**Description:** Verifies the OTP sent during the login process if MFA is enabled.

**Mock Request Body:**

```json
{
  "email": "testuser@example.com",
  "otp": "654321"
}
```

**Response (Success - 200 OK):**

```json
{
  "message": "Login verified successfully.",
  "user": {
    "id": 1,
    "email": "testuser@example.com",
    "username": "testuser"
  },
  "tokens": {
    "accessToken": "eyJhbG...",
    "refreshToken": "eyJhbG..."
  }
}
```

---

### 5. Forgot Password

**Endpoint:** `POST /api/auth/forgot-password`
**Description:** Initiates the password reset flow by sending an OTP to the user's email.

**Mock Request Body:**

```json
{
  "email": "testuser@example.com"
}
```

**Response (Success - 200 OK):**

```json
{
  "message": "OTP sent to your email"
}
```

---

### 6. Reset Password

**Endpoint:** `POST /api/auth/reset-password`
**Description:** Resets the user's password using the OTP received.

**Mock Request Body:**

```json
{
  "email": "testuser@example.com",
  "otp": "987654",
  "newPassword": "NewSecurePassword789!"
}
```

**Response (Success - 200 OK):**

```json
{
  "message": "Password has been reset successfully"
}
```

---

### 7. Google Login (Initiate)

**Endpoint:** `GET /api/auth/google`
**Description:** Redirects the user to Google for authentication.

---

### 8. Google Callback

**Endpoint:** `GET /api/auth/google/callback`
**Description:** Callback URL for Google OAuth flow. This is triggered by Google after user authentication.

**Response (Success):**

```json
{
  "status": "success",
  "accessToken": "...",
  "refreshToken": "..."
}
```
