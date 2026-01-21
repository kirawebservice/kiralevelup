# Admin & User Management System

## Overview
This system provides role-based access control for managing Free Fire bot accounts. It supports two user roles:
- **Admin**: Full control over users and accounts
- **User**: Limited access to their assigned account only

## Features

### Admin Features
✅ **User Management**
- Create new users (admin or regular users)
- Delete users
- Set user validity/expiration dates
- Assign specific Free Fire accounts to users
- Update user passwords and roles

✅ **Account Management**
- Add/Edit/Delete Free Fire accounts
- Start/Stop accounts
- Start/Stop auto-join loops
- Update team codes
- View real-time account status

### User Features
✅ **Limited Account Control**
- View only their assigned account
- Start/Stop their account
- Start/Stop auto-join loop for their account
- Update team code for their account
- **Cannot** access other users' accounts

## Default Credentials
```
Username: admin
Password: admin123
```
⚠️ **Change these credentials immediately after first login!**

## User Structure

### Users (stored in `users.json`)
```json
{
  "username": {
    "password_hash": "hashed_password",
    "role": "admin" or "user",
    "assigned_account": "account_id",
    "valid_until": "2025-12-31T23:59:59",
    "created_at": "2025-11-21T...",
    "created_by": "admin"
  }
}
```

### Accounts (stored in `bd.json`)
```json
{
  "accounts": {
    "account_id": {
      "password": "encrypted_password",
      "name": "Display Name",
      "team_code": "1234567",
      "enabled": true
    }
  }
}
```

## Admin Workflow

### Creating a User
1. Login as admin
2. Go to Dashboard → User Management
3. Click "+ Add User"
4. Fill in:
   - Username (required)
   - Password (required, min 6 characters)
   - Role (admin/user)
   - Assign Account (optional, select from dropdown)
   - Validity Days (optional, leave empty for unlimited)
5. Click "Save"

### Assigning Account to User
- When creating/editing a user, select an account from the dropdown
- Each account can only be assigned to ONE user
- Admin can see which accounts are already assigned
- Once assigned, only that user can control the account

### Setting User Validity
- Set validity in days (e.g., 30 for 30 days)
- Leave empty for unlimited validity
- Expired users cannot login
- Admin can extend validity by editing the user

## User Workflow

### User Login & Access
1. User logs in with credentials provided by admin
2. Dashboard shows only their assigned account
3. User can:
   - Start/Stop their account
   - Start/Stop auto-join loop
   - Update team code
4. User **cannot**:
   - See or control other accounts
   - Add/Edit/Delete accounts
   - Access admin features

### Account Control
Users can control their assigned account just like admin, but only for that one account.

## API Endpoints

### User Management (Admin Only)
- `GET /api/users` - Get all users
- `POST /api/users` - Create new user
- `PUT /api/users/<username>` - Update user
- `DELETE /api/users/<username>` - Delete user
- `GET /api/available-accounts` - Get all accounts and their assignments

### Account Management
- `GET /api/accounts` - Get accounts (admin sees all, user sees only theirs)
- `POST /api/accounts` - Add account (admin only)
- `PUT /api/accounts/<id>` - Update account (admin only)
- `DELETE /api/accounts/<id>` - Delete account (admin only)
- `POST /api/accounts/<id>/start` - Start account
- `POST /api/accounts/<id>/stop` - Stop account
- `POST /api/accounts/<id>/loop/start` - Start auto-join loop
- `POST /api/accounts/<id>/loop/stop` - Stop auto-join loop
- `POST /api/accounts/<id>/teamcode` - Update team code

## Security Features

### Role-Based Access Control
- Admin routes protected with `@admin_required` decorator
- User routes check if user has permission for specific account
- Automatic validity checking on each request
- Expired users automatically logged out

### Account Assignment Rules
1. One account can only be assigned to one user
2. Users can only control their assigned account
3. Admin cannot assign already-assigned accounts to another user
4. When account is deleted, assignment is removed

### Password Security
- Passwords hashed using werkzeug's scrypt algorithm
- Minimum 6 characters required
- Password field hidden in API responses

## Example Use Cases

### Scenario 1: Team with Multiple Operators
Admin creates users for each team member and assigns specific Free Fire accounts. Each operator can only control their assigned account, preventing conflicts.

### Scenario 2: Temporary Access
Admin creates a user with 7-day validity. After 7 days, the user cannot login anymore. Admin can extend validity at any time.

### Scenario 3: Account Rotation
Admin can reassign accounts by:
1. Edit user 1 → Remove account assignment
2. Edit user 2 → Assign the account

### Scenario 4: Multiple Admins
Admin can create other admin users who have full access to manage everything.

## Troubleshooting

### User Cannot Login
- Check if account is expired (valid_until)
- Verify username and password
- Check if user exists in users.json

### User Cannot See Account
- Verify account is assigned to user
- Check if account exists in bd.json
- Check account is enabled

### User Gets "Permission Denied"
- Verify user is trying to access only their assigned account
- Check user role is not expired
- Ensure user is logged in

### Account Already Assigned Error
- Check which user has the account assigned
- Unassign from current user first
- Then assign to new user

## Security Recommendations

1. **Change default admin password immediately**
2. **Use strong passwords** for all users
3. **Set validity periods** for temporary users
4. **Regularly review** user accounts and remove unused ones
5. **Monitor logs** for unauthorized access attempts
6. **Backup** users.json and bd.json regularly

## File Locations
- Users data: `users.json`
- Accounts data: `bd.json`
- Session data: `sessions.json`
- Approved users: `approved.txt`
- Blacklist: `blacklist.txt`

## Support
For issues or questions about this system, contact the system administrator.

---

**System Version**: 1.0  
**Last Updated**: November 21, 2025

