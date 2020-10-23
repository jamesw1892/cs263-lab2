package dcs;

import static dcs.SessionUtil.*;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import spark.*;

public class LoginController {

    // the DCS master database, very volatile, don't turn off the power
    private static Database database = new Database();

    // create a cryptographically secure pseudo random number generator
    private static SecureRandom cprng = new SecureRandom();

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

        // generate a 16-byte salt using a cprng
        byte[] slt = new byte[16];
        cprng.nextBytes(slt);
        String salt = new String(slt);

        // use the defined security configuration
        int keySize = SecurityConfiguration.KEY_SIZE;
        int iterations = SecurityConfiguration.ITERATIONS;

        // generate the hashed password using pbkdf2
        String hashedPassword = SecurityConfiguration.pbkdf2(password, salt, iterations, keySize);

        // create the user object and add to database
        DCSUser new_user = new DCSUser(username);
        new_user.setIterations(iterations);
        new_user.setKeySize(keySize);
        new_user.setSalt(salt);
        new_user.setHashedPassword(hashedPassword);
        database.addUser(new_user);

        return true;
    }

    // performs the authentication process
    public static boolean authenticate(String username, String password) {

        // make sure the username and password aren't empty
        if (username.isEmpty() || password.isEmpty()) {
            return false;
        }

        // lookup the user in the database
        DCSUser user = database.lookup(username);

        // if the user is not in the database, deny access
        if (user == null) {
            return false;
        }

        // calculate hash of entered password
        // with same configuration as original password
        String hashedPassword = SecurityConfiguration.pbkdf2(
            password, user.getSalt(), user.getIterations(), user.getKeySize());

        // if the newly generated hash does not match
        // the one in the database, deny access
        if (!hashedPassword.equals(user.getHashedPassword())) {
            return false;
        }

        // rehash the password if the security configuration has changed
        rehashPassword(user, password);

        // grant access
        return true;
    }

    // rehash the user's password if the security configuration has changed
    public static void rehashPassword(DCSUser user, String password) {

        // if security configuration has changed
        if (user.getIterations() != SecurityConfiguration.ITERATIONS
            || user.getKeySize() != SecurityConfiguration.KEY_SIZE) {

            // rehash the password with the new configuration
            String hashedPassword = SecurityConfiguration.pbkdf2(password, user.getSalt(), SecurityConfiguration.ITERATIONS, SecurityConfiguration.KEY_SIZE);

            // update the configuration for that user in the database
            user.setHashedPassword(hashedPassword);
            user.setIterations(SecurityConfiguration.ITERATIONS);
            user.setKeySize(SecurityConfiguration.KEY_SIZE);
        }
    }
}