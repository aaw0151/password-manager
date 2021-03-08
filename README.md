# password-manager
Header:

This program was original created by Megan Luthra and Alexander Williams for a programming assignment for CSCE 3550 (Introduction to Computer Security) at the University of North Texas.

The program was later edited by Alexander Williams for a personal project.


Information:

Uses PBKDF2 (HMAC) for encrypting master password and AES for encryping each password in the password database.

Salts are added at the end of the password before encryption.


Usage:

Run using "python passwordman.py [sitename]". This will initialize the password.pwm and the salts.slt file if they do not exist. If the previous files do not exist, the user will be asked to create a master password.

Adding the "[sitename]" argument will allow for a password to be added for that sitename or to access the password associated with that sitename if already created.

Not adding the "[sitename]" argument, when the password database has been initialized, will display all passwords currently stored.
