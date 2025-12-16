# JetForm Register - Approve 🚀

**JetForm Register - Approve** is a powerful administrative tool for WordPress, specifically designed to bridge the gap between user registration and manual moderation within **JetFormBuilder** workflows.

Instead of logging into the dashboard for every new user, administrators can approve or reject registrations directly from their email inbox using secure, time-limited tokens.

---

## 🛠 Features

* **Automated Token Generation**: Secure 48-character tokens created upon user registration.
* **One-Click Approval**: Automatically promote users to a predefined role (e.g., Customer, Member).
* **One-Click Deletion**: Instantly remove spam or unwanted registrations.
* **Custom Expiration**: Define how long the links remain valid (from 1 to 720 hours).
* **Seamless JetForm Integration**: Uses simple placeholders to inject links into form notification emails.

---

## 📋 Installation

1.  Download or copy the plugin file (`jetform-register-approve.php`).
2.  Upload it to your `/wp-content/plugins/` directory.
3.  Activate the plugin through the **Plugins** menu in WordPress.
4.  Go to **Settings > JetForm Approve** to set your default approval role.

---

## 📧 Usage in JetFormBuilder

To include the action links in your **"Send Email"** post-submit action, insert the following placeholders into the email body:

### 1. The Approval Link
Changes the user's role to the one defined in settings.
`::RCTL_LINK::%user_email%|Click here to approve::`

### 2. The Deletion Link
Permanently deletes the user from the database.
`::RCTL_DELETE_LINK::%user_email%|Click here to delete user::`

> **Note**: You can use JetFormBuilder's dynamic tags (like `%user_email%`) to automatically fetch the registrant's email.

---

## ⚙️ Technical Workflow



1.  **User Registers**: The plugin hooks into `user_register` and stores encrypted metadata.
2.  **Email Sent**: JetFormBuilder sends an email to the admin with the generated REST API links.
3.  **Admin Action**: Clicking the link triggers a `GET` request to a custom namespace (`rctl/v1`).
4.  **Verification**: The plugin performs a `hash_equals` check and verifies the expiration timestamp.
5.  **Execution**: The user role is updated (or the user is deleted), and the admin is redirected with a success message.

---

## 🔒 Security

* **REST API Protection**: Endpoints are public but require a valid UID and a high-entropy secret token.
* **Timing Attack Prevention**: Uses constant-time string comparison for token validation.
* **Sanitization**: All inputs are sanitized using WordPress core functions (`absint`, `sanitize_key`, `sanitize_text_field`).

---

## ⚖️ License

Distributed under the GPL2 License. Free to use, modify, and distribute.

**Author**: Angelo Marra
**Version**: 2.1
