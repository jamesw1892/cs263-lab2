package dcs;

import spark.Spark;
import static spark.Spark.*;

public class Main {
    // the main entry point for this hot mess of an application
    public static void main(String[] args) {
        // pick an arbitrary port
        port(0);

        // tell the Spark framework where to find static files
        staticFiles.location("/static");

        // map routes to controllers
        get("/", IndexController.serveIndexPage);
        get("/register/", LoginController.serveRegisterPage);
        get("/login/", LoginController.serveLoginPage);
        post("/register/", LoginController.handleRegistration);
        post("/login/", LoginController.handleLoginPost);
        post("/logout/", LoginController.handleLogoutPost);

        // wait for the server to start
        awaitInitialization();

        // get the port we are running on
        int port = Spark.port();

        // print something useful to stdout to tell users that the server
        // started successfully
        System.out.printf("\n\nServer running on  http://localhost:%d\n", port);
    }
}
