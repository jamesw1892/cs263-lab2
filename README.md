# Lab 2 of CS263: Cyber Security

My code for lab 2, completing the code for a simple web server. It allows users to register an account, login and logout using a database. The users passwords are hashed using pbkdf2 with a salt and global iteration and key size configuration.

## Ex4

Implemented `LoginController.register` which:

1. Generates a 16 byte salt from a cryptographically-secure pseudo-random number generator
1. Gets the number of iterations and key size from the global pbkdf2 configuration
1. Generates the hashed password using pbkdf2
1. Adds the newly generated user to the database