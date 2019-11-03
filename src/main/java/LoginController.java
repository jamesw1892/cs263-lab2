package dcs;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import spark.*;
import java.util.*;
import java.security.SecureRandom;

import static dcs.SessionUtil.*;

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
        // check that no user with this name exists
        if(database.lookup(username) != null) {
            return false; // user does already exist
        }

        // we may wish to perform additional checks on `username` and
        // `password` here to ensure that they of acceptable formats
        // (e.g. a non-empty username, password of a certain length);
        // no such requirements are given in the spec, but we add some
        // for demonstration purposes here
        if(StringUtils.isBlank(username) || 
           StringUtils.isBlank(password) || 
           password.length() < 8) {
               return false; // invalid username or password
        }

        // initialise the DCSUser object for the new user with the
        // specified username
        DCSUser user = new DCSUser(username);
        
        // obtain the security configuration; we store these values in
        // locals since we need to refer to them twice and it would be
        // really bad if they happened to change between uses (this is
        // not really possible in this example application since the
        // security configuration is constant, but in a real system it
        // might change dynamically)
        int iterations = SecurityConfiguration.ITERATIONS;
        int keySize = SecurityConfiguration.KEY_SIZE;

        // store the configuration in the user entry so that we can later
        // use the same settings when hashing passwords supplied during
        // the authentication process in order to arrive at the same hash
        user.setIterations(iterations);
        user.setKeySize(keySize);

        // generate a random salt: we use a cryptographically secure RNG
        // (SecureRandom) to populate a 16 byte array with random bytes
        // which we then turn into a hexadecimal String representation for
        // the salt / use with 
        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);
        String salt = Hex.encodeHexString(saltBytes);

        user.setSalt(salt);

        // hash the password according to the
        user.setHashedPassword(SecurityConfiguration.pbkdf2(
            password,
            salt,
            iterations,
            keySize
        ));
        
        // add the user to the (in-memory) database
        database.addUser(user);

        // the account was successfully created
        return true;
    }

    // performs the authentication process
    public static boolean authenticate(String username, String password) {
        // make sure the username and password aren't empty
        if (username.isEmpty() || password.isEmpty()) {
            return false;
        }

        // try to look up the user object in the database
        DCSUser user = database.lookup(username);

        // the user could not be found; authentication fails
        if(user == null) return false;

        // compute the hash for the password provided by the client using the
        // settings and salt that we have previously stored for the user
        String hash = SecurityConfiguration.pbkdf2(
            password,
            user.getSalt(),
            user.getIterations(),
            user.getKeySize()
        );

        // compare the hashes to check that they are the same
        if(user.getHashedPassword().equals(hash)) {
            // check whether the number of iterations and the key size stored
            // for this user are different than those in the global security
            // configuration 
            if(user.getIterations() != SecurityConfiguration.ITERATIONS ||
               user.getKeySize() != SecurityConfiguration.KEY_SIZE) 
            {
                // calculate a new hash using the current, global settings
                rehashPassword(username, password);
            }

            // authentication was successful
            return true;
        }

        // the hashes do not match: a wrong password was provided
        return false;
    }

    // changes a user's password
    public static void rehashPassword(String username, String password) {
        DCSUser user = database.lookup(username);

        // obtain the security configuration; we store these values in
        // locals since we need to refer to them twice and it would be
        // really bad if they happened to change between uses (this is
        // not really possible in this example application since the
        // security configuration is constant, but in a real system it
        // might change dynamically)
        int iterations = SecurityConfiguration.ITERATIONS;
        int keySize = SecurityConfiguration.KEY_SIZE;

        // update the configuration in the user entry so that we can later
        // use the same settings when hashing passwords supplied during
        // the authentication process in order to arrive at the same hash
        user.setIterations(iterations);
        user.setKeySize(keySize);

        // update the user object with the new hash
        user.setHashedPassword(SecurityConfiguration.pbkdf2(
            password,
            user.getSalt(),
            iterations,
            keySize
        ));
    }

}
