# ZZINGRUSH
#### Video Demo:  <https://www.youtube.com/watch?v=5FTZR9tk09I>
#### Description:  Zzingrush is a web application for managing inventory and user roles within an inventory, created for small, medium, and big companies. Each one of the users that registers themselves to the app will be added to a team so that the higher hierarchy  users in that said team, assigns them a role, each role has different cappabalities to manage and manipulate the data of that said team, different teams have their own product listings, The data in question is the inputs of the team, the app is mainly designed to be used as a tracker for products in a warehouse, but in reality it can be used  to track anything you want when you have workers or customers that you would like to track your inventory too.

Project/

instance/
   products.db:  #SQLite database file contains 5 tables; PRODUCTS wich contains id,user_id, team_id, price, quantity, name  and image_filenamerole,                            ROLE wich contains the id and the name of the role; TEAM wich contains, id,name of the team and  manager_id; TEAM MEMBERS wich contains the user_id and Team_id; USER wich contains, id, username, hash, role_id and email.
static/
    product_images/: Directory for storing product images.
    styles.css:  "MOSTLY AI GENERATED" CSS file containing styles for the application, including light and dark mode styles.
templates/.
     apology.htmlTemplate for displaying error messages and apologies to the user i usedmostly all of the code from finance problem, but instead of an image i use a kendrick lamar gif:D
     esqueleto.html: Base template that includes the common structure of the web pages, including the navigation bar, footer, dark mode button and script and the password       toggle script.
     index.html:Template for the homepage, displaying a list of products or main content.
     login.html: Template for the login page, allowing users to log into their accounts i used some of the code from finance problem.
     register.html: Template for the registration page, allowing new users to create accounts i used some of the code from finance problem.
     roles.html: Template for managing user roles, allowing admins to update roles and delete users.
     app.py: Main application file that sets up the Flask app, routes, and manages user sessions. I used mostly of the log in and register code from finance problem but i used sql alchemy to manage the db explanation of the functions in app.py:
     ///////////////////////////////////
     app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False: Disables SQLAlchemy event system overhead.
app.config['UPLOAD_FOLDER'] = 'static/product_images': Sets the folder for uploading product images.
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key'): Configures the secret key for session management.
Database Models

db = SQLAlchemy(app): Initializes the SQLAlchemy object.
class User(db.Model): Defines the User model with fields for user information and relationships to roles and teams.
class Role(db.Model): Defines the Role model with fields for role information and relationships to users.
class Team(db.Model): Defines the Team model with fields for team information and relationships to users and products.
team_members = db.Table('team_members'): Defines a many-to-many relationship between users and teams.
class Product(db.Model): Defines the Product model with fields for product information and relationships to users and teams.
Routes

@app.route('/Admin/roles', methods=['GET', 'POST']): Manages user roles with an admin interface.
@app.route("/register", methods=["GET", "POST"]): Handles user registration with validation and hashing.
@app.route("/login", methods=["GET", "POST"]): Manages user login with session management and authentication.
@app.route("/logout"): Logs out the user by clearing the session.
@app.route('/uploads/<filename>'): Serves uploaded files from the configured upload folder.
@app.route('/add_role', methods=['POST']): Allows admin users to add new roles.
@app.route('/delete_role/<int:role_id>', methods=['POST']): Allows admin users to delete roles.
@app.route('/', methods=['GET', 'POST']): Displays the homepage, lists products, and allows product addition.
Main Block

if __name__ == "__main__":: Ensures the app runs only if the script is executed directly.
with app.app_context(): Ensures the application context is available.
db.create_all(): Creates database tables if they don't exist.
roles = ['customer', 'manager', 'admin', 'supplier', 'support', 'guest']: Inserts default roles into the database.
app.run(debug=True): Runs the Flask application in debug mode.
///////////

functions.py: File containing helper functions used in the application for various operations, i used some functions from finance like the password_ complex and the apolofy functions


