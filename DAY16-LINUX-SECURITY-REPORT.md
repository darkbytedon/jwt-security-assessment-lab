# Day 16 – Linux Security and Permissions Investigation

## 1. Objective

Investigate Linux user accounts, groups, file permissions, directory permissions, ownership, default permissions and authentication-file security.

## 2. Environment

- Operating system: Ubuntu on WSL
- Username: dondon
- Working directory: ~/cybersecurity/day16/linux-permissions-lab
- Tools: Linux terminal, chmod, chown, umask, sudo and standard Linux utilities.

## 3. User and Group Investigation

Commands used:

```bash
whoami
id
```

Observations:

- Current user: dondon
- UID: 1000
- Primary GID: 1000
- Account belongs to several groups, including sudo.

Security finding:

The account has sudo privileges and can execute commands with elevated privileges. Compromise of this account could therefore result in serious system compromise.

## 4. File Permission Investigation

Commands used:

```bash
touch security-test.txt
ls -l security-test.txt
chmod 600 security-test.txt
chmod 777 security-test.txt
```

Observed permissions:

| Permission | Meaning |
|---|---|
| 644 | Owner can read/write; others can read |
| 600 | Only owner can read/write |
| 777 | Everyone has read/write/execute |

Security finding:

Permission 777 can expose files to unauthorized modification and access. Sensitive files should use restrictive permissions appropriate to their purpose.

Final test-file permissions were restored to 600.

## 5. Directory Permission Investigation

Commands used:

```bash
mkdir private-folder
chmod 700 private-folder
chmod 600 private-folder
chmod 700 private-folder
```

Observations:

- Permission 700 allowed the owner full directory access.
- Permission 600 removed directory traversal permission.
- Attempting to enter the directory without execute permission resulted in Permission denied.
- Permission 700 was restored successfully.

Security finding:

Directory execute permission is necessary for traversal. Incorrect directory permissions can prevent legitimate access or expose directory contents.

## 6. File Ownership Investigation

Commands used:

```bash
sudo chown www-data security-test.txt
ls -l security-test.txt
sudo chown dondon:dondon security-test.txt
```

Observations:

- File ownership was changed from dondon to www-data.
- Ownership was subsequently restored to dondon.
- Group ownership remained dondon.

Security finding:

Incorrect file ownership can create unauthorized access or modification risks. File ownership should be reviewed during security assessments.

## 7. Umask Investigation

Initial umask:

```bash
umask
```

Observed value:

```text
0022
```

Created test file and directory:

```bash
touch umask-test.txt
mkdir umask-test-folder
```

Observed default permissions:

- File: 644
- Directory: 755

Changed umask:

```bash
umask 0077
```

Created additional test objects.

Observed permissions:

- File: 600
- Directory: 700

Restored original umask:

```bash
umask 0022
```

Security finding:

A restrictive umask helps prevent newly created files and directories from being unnecessarily accessible to other users.

## 8. Linux Account Security

Commands used:

```bash
cat /etc/passwd | grep dondon
ls -l /etc/passwd /etc/shadow
```

Observations:

- /etc/passwd contains general account information.
- /etc/passwd permissions: 644.
- /etc/shadow permissions: 640.
- /etc/shadow is owned by root and belongs to the shadow group.

Security finding:

The shadow file contains password hashes and related password information. Restricting access reduces the risk of unauthorized offline password-cracking attempts.

The contents of /etc/shadow were not displayed or copied.

## 9. Sudo Privilege Investigation

Command used:

```bash
sudo -l
```

Observation:

The dondon account can execute all commands as any user or group through sudo.

Security finding:

Full sudo privileges create a significant security impact if the account is compromised. Administrative access should be limited to trusted users and necessary commands.

## 10. Key Lessons Learned

- Linux permissions control access to files and directories
