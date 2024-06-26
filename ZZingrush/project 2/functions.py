
from flask import redirect, render_template, session
from functools import wraps
import re
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


def is_password_complex(password):
    pattern = r"^(?=.*[a-zA-Z])(?=.*\d)(?=.*[@#$%^&/¡+=.,!]).{8,}$"
    if re.match(pattern, password):
        return True
    else:
        return False

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def is_password_complex(password):
    pattern = r"^(?=.*[a-zA-Z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}$"
    if re.match(pattern, password):
        return True
    else:
        return False
def is_admin(self):
        return self.role and self.role.name == 'Admin'
