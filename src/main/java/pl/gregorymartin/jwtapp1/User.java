package pl.gregorymartin.jwtapp1;

class User {
    private String name;
    private String username;
    private String password;
    private boolean isAdmin;

    public User(final String name, final String username, final String password, final boolean isAdmin) {
        this.name = name;
        this.username = username;
        this.password = password;
        this.isAdmin = isAdmin;
    }

    public String getName() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    public boolean isAdmin() {
        return isAdmin;
    }

    public void setAdmin(final boolean admin) {
        isAdmin = admin;
    }
}
