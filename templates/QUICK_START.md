# Quick Start Guide - Admin & User Management System

## 🚀 Getting Started in 5 Minutes

### Step 1: Start the Application
```bash
python app.py
```

The application will start on: `http://localhost:1528`

### Step 2: Login as Admin
```
Username: admin
Password: admin123
```

### Step 3: Change Admin Password (IMPORTANT!)
1. Click on "Settings" (top right)
2. Enter current password: `admin123`
3. Enter new strong password
4. Confirm new password
5. Click "Change Password"
6. You'll be logged out - login again with new password

### Step 4: Create Your First User

1. **Go to Dashboard**
2. **Find "User Management" section**
3. **Click "+ Add User"**
4. **Fill in the form:**
   ```
   Username: test_user
   Password: test123456
   Role: user
   Assign Account: Select one from dropdown (e.g., 4262774807)
   Validity Days: 30
   ```
5. **Click "Save"**

### Step 5: Test User Login

1. **Logout from admin account**
2. **Login as the new user:**
   ```
   Username: test_user
   Password: test123456
   ```
3. **You should see:**
   - Only the assigned account (4262774807)
   - Limited controls (Start, Stop, Team Code, Loop)
   - No admin features

## 📋 What Each User Role Can Do

### Admin Can:
✅ Create/Edit/Delete users  
✅ Assign accounts to users  
✅ Add/Edit/Delete accounts  
✅ Control all accounts  
✅ Set user validity  
✅ View all system information  

### Regular User Can:
✅ View only their assigned account  
✅ Start/Stop their account  
✅ Start/Stop auto-join loop  
✅ Update team code for their account  
❌ Cannot see other accounts  
❌ Cannot access admin features  

## 🎯 Common Tasks

### How to Assign an Account to a User?

**Method 1: When Creating User**
1. Click "+ Add User"
2. Fill username, password, role
3. Select account from "Assign Account" dropdown
4. Click "Save"

**Method 2: Edit Existing User**
1. Find user in User Management table
2. Click "Edit" button
3. Select account from dropdown
4. Click "Save"

### How to Change User's Account?

1. **Remove from current user:**
   - Edit current user
   - Set "Assign Account" to "-- No Account --"
   - Save

2. **Assign to new user:**
   - Edit new user
   - Select the account
   - Save

### How to Extend User's Validity?

1. Find user in User Management table
2. Click "Edit"
3. Enter new number of days in "Validity Days"
4. Click "Save"
   - This will extend from TODAY, not from original date
   - Example: If entering 30, user will be valid for 30 days from today

### How to Make a User Admin?

1. Find user in User Management table
2. Click "Edit"
3. Change "Role" to "Admin"
4. Click "Save"

## 🔧 Account Management

### Add New Account (Admin Only)

1. Go to "Account Management" section
2. Click "+ Add Account"
3. Fill in:
   ```
   Account ID: Your Free Fire account ID
   Password: Account password (encrypted)
   Name: Display name (optional)
   Team Code: Team code (optional)
   ```
4. Click "Save"

### Control Account (Both Admin & User)

For each account in the table:
- **Start Button**: Start the account connection
- **Stop Button**: Stop the account connection
- **Team Code Input**: Enter team code and click "Update"
- **Start Level UP**: Start auto-join loop
- **Stop Loop**: Stop auto-join loop

## 📊 Dashboard Overview

### Admin Dashboard Shows:
- **User Management Table**
  - All users
  - Their roles
  - Assigned accounts
  - Validity status
  - Actions (Edit/Delete)

- **Account Management Table**
  - All accounts
  - Account status (Running/Stopped)
  - Loop status
  - Actions (Start/Stop/Edit/Delete)

### User Dashboard Shows:
- **My Account Control**
  - Only assigned account
  - Account status
  - Loop status
  - Control buttons

## 🛡️ Security Best Practices

1. **Change default admin password immediately**
2. **Use strong passwords** (8+ characters, mix of letters & numbers)
3. **Set validity periods** for temporary users
4. **Regular audits** - Check and remove inactive users
5. **Backup** users.json and bd.json files regularly

## ⚠️ Important Notes

### Account Assignment Rules
- One account = One user only
- Admin can reassign accounts
- User cannot change their own assignment
- When user is deleted, account becomes unassigned

### User Validity
- Empty validity = Never expires
- Set number of days = Expires after X days from creation/update
- Expired users cannot login
- Admin can extend validity anytime

### Password Management
- Minimum 6 characters
- Stored as secure hash (scrypt)
- Cannot be recovered if forgotten
- Admin can reset user passwords

## 🔍 Troubleshooting

### Problem: Cannot login after changing password
**Solution:** Clear browser cookies and try again

### Problem: User sees "No account assigned"
**Solution (Admin):** Edit user and assign an account

### Problem: Account already assigned error
**Solution (Admin):** 
1. Check which user has the account
2. Edit that user → Remove assignment
3. Then assign to new user

### Problem: User account expired
**Solution (Admin):** 
1. Edit user
2. Enter new validity days
3. Save

## 📞 Support

For any issues:
1. Check this guide
2. Check USER_MANAGEMENT_README.md for detailed info
3. Check BANGLA_GUIDE.md for Bengali guide
4. Contact system administrator

## 🎉 Success!

You now have a fully functional multi-user system where:
- ✅ Admin controls everything
- ✅ Users access only their assigned accounts
- ✅ Accounts are protected
- ✅ System is secure

**Happy managing! 🚀**

---

**System Version**: 1.0  
**Last Updated**: November 21, 2025

