package dcs;

import static spark.Spark.*;

public class Main {
    // the main entry point for this hot mess of an application
    public static void main(String[] args) {
        // tell the Spark framework where to find static files
        staticFiles.location("/static");

        // map routes to controllers
        get("/", IndexController.serveIndexPage);
        get("/register/", LoginController.serveRegisterPage);
        get("/login/", LoginController.serveLoginPage);
        post("/register/", LoginController.handleRegistration);
        post("/login/", LoginController.handleLoginPost);
        post("/logout/", LoginController.handleLogoutPost);
    }
}
