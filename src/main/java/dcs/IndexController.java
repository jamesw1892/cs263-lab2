package dcs;

import spark.*;
import java.util.*;

import static dcs.SessionUtil.*;

public class IndexController {

    // Serve the index page (GET request)
    public static Route serveIndexPage = (Request request, Response response) -> {
        Map<String, Object> model = new HashMap<>();

        return ViewUtil.render(request, model, "/velocity/index.vm");
    };

}
