# Lab 2 of CS263: Cyber Security

My code for lab 2, completing the code for a simple web server. It allows users to register, login and logout using a database. The users' passwords are hashed using pbkdf2 with a salt unique to the user and a global configuration defining the number of iterations and key size.

# Ex4

Implemented `LoginController.register` which:

1. Generates a 16 byte salt from a cryptographically-secure pseudo-random number generator
1. Gets the number of iterations and key size from the global pbkdf2 configuration
1. Generates the hashed password using pbkdf2
1. Adds the newly generated user to the database

# Ex5

Implemented `LoginController.authenticate` which:

1. Looks up the username in the database and denies access if it is not in it
1. Generates password hash based on entered password and original configuration (salt, number of iterations, key size). It denies access if this does not match the saved password hash
1. Grants access if it has not already denied it