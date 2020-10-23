package dcs;

import static dcs.SessionUtil.*;

import java.util.HashMap;
import java.util.Map;

import spark.*;

public class LoginController {

    // the DCS master database, very volatile, don't turn off the power
    private static Database database = new Database();

    // Serve the registration page (GET request)
    public static Route serveRegisterPage = (Request request, Response response) -> {
        Map<String, Object> model = new HashMap<>();

        return ViewUtil.render(request, model, "/velocity/register.vm");
    };

    // Handle an attempt to register a new user
    public static Route handleRegistration = (Request request, Response response) -> {
        Map<String, Object> model = new HashMap<>();

        String username = request.queryParams("username");
        String password = request.queryParams("password");

        if(!LoginController.register(username, password)) {
            model.put("registrationFailed", true);
            return ViewUtil.render(request, model, "/velocity/register.vm");
        }

        // the user is now logged in with their new "account"
        request.session().attribute("currentUser", username);

        // redirect the user back to the front page
        response.redirect("/");
        return null;
    };

    // Serve the login page
    public static Route serveLoginPage = (Request request, Response response) -> {
        Map<String, Object> model = new HashMap<>();

        model.put("loggedOut", removeSessionAttrLoggedOut(request));
        model.put("loginRedirect", removeSessionAttrLoginRedirect(request));

        return ViewUtil.render(request, model, "/velocity/login.vm");
    };

    // Handle a login request
    public static Route handleLoginPost = (Request request, Response response) -> {
        Map<String, Object> model = new HashMap<>();

        // perform secure authentication
        if (!authenticate(request.queryParams("username"), request.queryParams("password"))) {
            model.put("authenticationFailed", true);
            return ViewUtil.render(request, model, "/velocity/login.vm");
        }

        // authentication "successful"
        model.put("authenticationSucceeded", true);

        // the user is now logged in
        request.session().attribute("currentUser", request.queryParams("username"));

        // redirect the user somewhere, if this was requested
        if (getQueryLoginRedirect(request) != null) {
            response.redirect(getQueryLoginRedirect(request));
        }

        // otherwise just redirect the user to the index
        response.redirect("/");
        return null;
    };

    // log a user out
    public static Route handleLogoutPost = (Request request, Response response) -> {
        request.session().removeAttribute("currentUser");
        request.session().attribute("loggedOut", true);
        response.redirect("/login/");
        return null;
    };

    // registers a new user
    public static boolean register(String username, String password) {

        // cannot create a user with empty username
        if (username.isBlank()) {
            return false;
        }

        // cannot create a user with the same name as an existing user
        if (database.lookup(username) != null) {
            return false;
        }

        // check password is strong enough
        if (!SecurityConfiguration.isPasswordStrongEnough(password)) {
            return false;
        }

        // create the user object
        DCSUser newUser = new DCSUser(username);

        // update details including generating salt and hashing password
        updateUserSecurityDetails(newUser, password);

        // add the user to the database
        database.addUser(newUser);

        return true;
    }

    // performs the authentication process
    public static boolean authenticate(String username, String password) {

        // make sure the username and password aren't empty
        if (username.isEmpty() || password.isEmpty()) {
            return false;
        }

        // if the user is not in the database, deny access
        DCSUser user = database.lookup(username);
        if (user == null) {
            return false;
        }

        // calculate hash of entered password
        // with same configuration as original password
        String hashedPassword = SecurityConfiguration.pbkdf2(
            password,
            user.getSalt(),
            user.getIterations(),
            user.getKeySize()
        );

        // if the newly generated hash does not match
        // the one in the database, deny access
        if (!hashedPassword.equals(user.getHashedPassword())) {
            return false;
        }

        // rehash the password if the security configuration has changed
        if (SecurityConfiguration.hasChanged(user)) {
            updateUserSecurityDetails(user, password);
        }

        // grant access
        return true;
    }

    // update the salt, key size and num iterations and rehash the user's password
    private static void updateUserSecurityDetails(DCSUser user, String password) {
        
        // update the user's security configuration to match the global ones
        int iterations = SecurityConfiguration.ITERATIONS;
        int keySize = SecurityConfiguration.KEY_SIZE;

        String salt = SecurityConfiguration.generateSalt();

        // generate the hashed password using pbkdf2
        String hashedPassword = SecurityConfiguration.pbkdf2(
            password,
            salt,
            iterations,
            keySize
        );

        // Update the details in the database
        user.setIterations(iterations);
        user.setKeySize(keySize);
        user.setSalt(salt);
        user.setHashedPassword(hashedPassword);
    }
}