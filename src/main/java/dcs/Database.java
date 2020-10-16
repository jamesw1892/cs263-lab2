package dcs;

import java.util.*;

// MongoDB is so last year, it's all about HighlyVolatileDB now
public class Database {
    // the most efficient way to store a list of users that all have a key
    // and that we need to look up by their key all the time -- it is
    // impossible to improve on O(n) lookup time
    private ArrayList<DCSUser> users;

    // initialise the HighlyVolatileDB with an empty list of users,
    // we do this every time the system starts because none of our
    // users will stick around for long enough to care anyway
    public Database() {
        this.users = new ArrayList<DCSUser>();
    }

    // add a new user to the HighlyVolatileDB: unknown time complexity
    // because I cba to look up how ArrayList works internally 
    public void addUser(DCSUser user) {
        this.users.add(user);
    }

    // look up a user by their username, this operation is O(n) because
    // we will never have enough users for it to matter anyway
    public DCSUser lookup(String username) {
        // find the user using efficient linear search
        for(DCSUser user : this.users) {
            if(user.getUsername().equals(username)) {
                return user;
            }
        }

        // don't forget to deal with this when you are using this method:
        // of course we don't indicate in any way that this method
        // may return null
        return null;
    }
}
