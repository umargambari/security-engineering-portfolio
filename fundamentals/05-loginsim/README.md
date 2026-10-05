# Login Simulator

A mock authentication system that stores passwords as salted hashes, enforces account lockout after failed attempts, and tracks sessions. Understand how authentication works from the inside before you try to break or defend it.

## Why this matters

Every web app, API, and system you'll ever secure uses some form of authentication. Understanding password hashing, salting, lockout policies, and session management at the code level — not just the concept level — is what separates security engineers from people who've read about security.

## What you'll build

- Register users with bcrypt-hashed passwords
- Authenticate users by comparing password hashes
- Lock accounts after N consecutive failed login attempts
- Track login history (timestamps, success/failure, lockout events)

## Skills you'll prove

- Password hashing with bcrypt (salting, work factors)
- State management with JSON file storage
- Rate limiting and lockout logic
- Secure authentication patterns

## Getting started

```bash
make install
python src/main.py --help
```

## Commands

| Command | Description |
|---------|-------------|
| `register` | Create a new user account |
| `login` | Authenticate as a user |
| `status` | Show account status (locked/unlocked, login history) |

## Example usage

```bash
# Register a user
python src/main.py register alice

# Login
python src/main.py login alice

# Check account status
python src/main.py status alice
```

## Stretch goals

- Configurable lockout threshold and duration
- Password complexity requirements at registration
- Session tokens with expiration
- Brute-force timing analysis (constant-time comparison)
