from flask import Flask, render_template, redirect, flash, request, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, URL
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
    logout_user,
)
import os
from werkzeug.utils import secure_filename
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask import send_file
from flask_wtf.file import FileField, FileRequired, FileAllowed
import datetime


app = Flask(__name__)
app.config["SECRET_KEY"] = "secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
app.config["UPLOAD_FOLDER"] = "static/"


from flask_mail import Mail, Message

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = "wiktor.szczurek1@gmail.com"
app.config["MAIL_PASSWORD"] = "hdgdpdmrmikeakcm"
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True
app.config["ADMIN_EMAIL"] = "wiktor.szczurek1@gmail.com"

mail = Mail(app)


user_exercises = db.Table(
    "user_exercises",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column(
        "exercise_id", db.Integer, db.ForeignKey("exercise.id"), primary_key=True
    ),
)

user_photos = db.Table(
    "user_photos",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("photo_id", db.Integer, db.ForeignKey("photo.id"), primary_key=True),
)
from werkzeug.security import generate_password_hash

moj_mail = "wiktor.szczurek1@gmail.com"

import datetime


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    surname = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    admin = db.Column(db.Boolean, default=False)
    first_login = db.Column(db.Boolean, default=False)
    registration_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    training_plans = db.relationship(
        "TrainingPlan", backref="user", lazy=True, cascade="all,delete"
    )
    exercises = db.relationship(
        "Exercise",
        secondary=user_exercises,
        backref=db.backref("users", lazy="dynamic"),
    )
    photos = db.relationship(
        "Photo",
        secondary=user_photos,
        backref=db.backref("users", lazy="dynamic"),
    )
    messages = db.relationship("Message", backref="user", lazy=True)
    email_confirmed = db.Column(db.Boolean, default=False)

    def is_active(self):
        return self.confirmed


class RegistrationForm(FlaskForm):
    name = StringField(
        "Imię", validators=[DataRequired()], render_kw={"placeholder": "Imię"}
    )
    surname = StringField(
        "Nazwisko", validators=[DataRequired()], render_kw={"placeholder": "Nazwisko"}
    )
    username = StringField(
        "Nazwa użytkownika",
        validators=[DataRequired()],
        render_kw={"placeholder": "Nazwa użytkownika"},
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email()],
        render_kw={"placeholder": "E-mail"},
    )
    password = PasswordField(
        "Hasło",
        validators=[DataRequired()],
        render_kw={"placeholder": "Hasło"},
    )
    confirm_password = PasswordField(
        "Potwierdź hasło",
        validators=[
            DataRequired(),
            EqualTo("password", message="Hasła muszą być takie same"),
        ],
        render_kw={"placeholder": "Potwierdź hasło"},
    )
    submit = SubmitField("Zarejestruj się")


from wtforms.validators import DataRequired, Length, Email


class LoginForm(FlaskForm):
    email_or_username = StringField(
        "Email or Username",
        validators=[DataRequired()],
        render_kw={"placeholder": "E-mail lub nazwa użytkownika"},
    )
    password = PasswordField(
        "Password", validators=[DataRequired()], render_kw={"placeholder": "Hasło"}
    )
    submit = SubmitField("Zaloguj się")


class AdminChangeCredentialsForm(FlaskForm):
    username = StringField("Nowa nazwa użytkownika", validators=[DataRequired()])
    password = PasswordField("Nowe hasło", validators=[DataRequired()])
    confirm_password = PasswordField(
        "Potwierdź nowe hasło", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Zmień dane")


class TrainingPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False, unique=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    @property
    def filepath(self):
        return os.path.join(app.config["UPLOAD_FOLDER"], self.filename)


class UploadTrainingPlanForm(FlaskForm):
    file = FileField(
        "Plik",
        validators=[FileRequired(), FileAllowed(["txt"], "Tylko pliki tekstowe!")],
    )
    submit = SubmitField("Prześlij")


class TrainingPlanForm(FlaskForm):
    file = FileField(
        "Plik",
        validators=[FileRequired(), FileAllowed(["txt"], "Tylko pliki tekstowe!")],
    )
    submit = SubmitField("Prześlij")


class Exercise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    youtube_link = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class AddExerciseForm(FlaskForm):
    name = StringField("Nazwa ćwiczenia", validators=[DataRequired()])
    youtube_link = StringField("Link do YouTube", validators=[DataRequired(), URL()])
    submit = SubmitField("Dodaj")


class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    data = db.Column(db.String(500), nullable=False)  
    note = db.Column(db.String(500))


from datetime import datetime


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    is_read = db.Column(db.Boolean, default=False)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


from wtforms import TextAreaField


class AddArticleForm(FlaskForm):
    title = StringField("Tytuł", validators=[DataRequired()])
    content = TextAreaField("Treść", validators=[DataRequired()])
    submit = SubmitField("Dodaj Artykuł")


from itsdangerous import URLSafeTimedSerializer

# utworzenie instancji URLSafeTimedSerializer
s = URLSafeTimedSerializer(app.config["SECRET_KEY"])


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()

        if user:
            token = s.dumps(email, salt="recover-key")
            msg = MailMessage(
                "Zresetuj hasło", sender="noreply@website.com", recipients=[email]
            )
            link = url_for("reset_with_token", token=token, _external=True)
            msg.body = "Twoje łącze do resetowania hasła: {}".format(link)
            mail.send(msg)

        flash(
            "E-mail z instrukcjami do zresetowania hasła został wysłany na podany adres, jeśli istnieje w naszej bazie danych."
        )

        return redirect(url_for("login"))

    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_with_token(token):
    try:
        email = s.loads(token, salt="recover-key", max_age=600)

    except SignatureExpired:
        flash("Link do resetowania hasła wygasł.")
        return redirect(url_for("forgot"))

    user = User.query.filter_by(email=email).first()

    if request.method == "POST":
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        if new_password == confirm_password:
            user.password = generate_password_hash(new_password, method="sha256")
            db.session.add(user)
            db.session.commit()

            flash("Twoje hasło zostało zaktualizowane.")
            return redirect(url_for("login"))

        else:
            flash("Hasła nie są zgodne. Spróbuj ponownie.")

    return render_template("reset_with_token.html")


@app.route("/change_admin_credentials", methods=["GET", "POST"])
@login_required
def change_admin_credentials():
    if not current_user.admin or not current_user.first_login:
        return redirect(url_for("home"))
    form = AdminChangeCredentialsForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method="sha256")
        current_user.username = form.username.data
        current_user.password = hashed_password
        current_user.first_login = False
        db.session.commit()
        flash("Dane uwierzytelniające zostały zmienione!", "success")
        logout_user()
        return redirect(url_for("login"))
    return render_template("change_admin_credentials.html", form=form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
@login_required
def home():
    users = User.query.all()
    return render_template("index.html", users=users)


@app.route("/admin")
@login_required
def admin():
    if not current_user.admin:
        return redirect(url_for("home"))
    users = User.query.filter_by(email_confirmed=True, confirmed=True).all()
    return render_template("admin.html", users=users)


@app.route("/admin/users_manage")
@login_required
def users_manage():
    if not current_user.admin:
        return redirect(url_for("home"))
    users = User.query.all()
    return render_template("users_manage.html", users=users)


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.admin:
        return redirect(url_for("home"))

    user = User.query.get_or_404(user_id)
    if user:
        
        messages = Message.query.filter_by(user_id=user.id).all()
        for message in messages:
            db.session.delete(message)

        sent_messages = ChatMessage.query.filter_by(sender_id=user.id).all()
        for message in sent_messages:
            db.session.delete(message)

        
        received_messages = ChatMessage.query.filter_by(recipient_id=user.id).all()
        for message in received_messages:
            db.session.delete(message)

       
        db.session.delete(user)
        db.session.commit()

    return redirect(url_for("users_manage"))


@app.route("/admin/user/<int:user_id>", methods=["GET", "POST"])
@login_required
def admin_user(user_id):
    user = User.query.get_or_404(user_id)
    form = TrainingPlanForm()
    if form.validate_on_submit():
        flash("Plan treningowy został dodany.", "success")
        return redirect(url_for("admin_user", user_id=user_id))
    return render_template("admin_user.html", user=user, form=form)


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return serializer.dumps(email)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method="sha256")
        new_user = User(
            name=form.name.data,
            surname=form.surname.data,
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            registration_date=datetime.utcnow(),
            email_confirmed=False,
            confirmed=False,
        )
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash("Podana nazwa użytkownika już istnieje.")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Podany E-mail już istnieje.")
            return redirect(url_for("register"))

        db.session.add(new_user)
        db.session.commit()

       
        token = generate_confirmation_token(new_user.email)

        confirm_url = url_for("confirm_email", token=token, _external=True)

      
        msg = MailMessage(
            "Potwierdź swoje konto",
            sender="no-replay@gmail.com",
            recipients=[new_user.email],
        )
        msg.body = "Kliknij w link aby potwierdzić swoje konto: {}".format(confirm_url)
        mail.send(msg)

        return render_template("success.html")

    return render_template("register.html", form=form)


@app.route("/confirm_email/<token>")
def confirm_email(token):
    try:
        email = s.loads(token, max_age=3600)
    except SignatureExpired:
        flash("Link potwierdzający wygasł.")
        return redirect(url_for("resend_confirmation"))

    user = User.query.filter_by(email=email).first()
    if user.email_confirmed:
        flash("Konto zostało już potwierdzone. Proszę zalogować się.")
    else:
        user.email_confirmed = True
        db.session.add(user)
        db.session.commit()
        flash(
            "Dziękujemy za potwierdzenie adresu e-mail! Teraz musisz poczekać na potwierdzenie przez administratora.",
            "success",
        )

        admin_msg = MailMessage(
            "Nowy potwierdzony użytkownik",
            sender="no-reply@gmail.com",
            recipients=[moj_mail],
        )
        admin_msg.body = f"Użytkownik {user.name} {user.surname} ({user.email}) potwierdził swój adres e-mail."
        mail.send(admin_msg)
    return redirect(url_for("login"))


from itsdangerous import URLSafeTimedSerializer, SignatureExpired


@app.route("/resend_confirmation", methods=["GET", "POST"])
def resend_confirmation():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Nie ma takiego użytkownika. Spróbuj ponownie.")
            return redirect(url_for("resend_confirmation"))

      
        token = s.dumps(user.email)
        confirm_url = url_for("confirm_email", token=token, _external=True)

   
        user_msg = MailMessage(
            "Potwierdzenie rejestracji",
            sender="no-reply@gmail.com",
            recipients=[user.email],
        )
        user_msg.body = (
            f"Kliknij link poniżej, aby potwierdzić swoje konto:\n{confirm_url}"
        )
        mail.send(user_msg)

        flash("Nowy link potwierdzający został wysłany. Sprawdź swoją skrzynkę e-mail.")
        return redirect(url_for("login"))

    return render_template("resend_confirmation.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(
            (User.username == form.email_or_username.data)
            | (User.email == form.email_or_username.data)
        ).first()
        if user and check_password_hash(user.password, form.password.data):
            if not user.confirmed and not user.admin:
                flash(
                    "Twoje konto musi zostać najpierw potwierdzone przez admina.",
                    "info",
                )
                return redirect(url_for("login"))
            login_user(user)
            if user.admin and user.first_login:
                flash(
                    "Zalogowano pomyślnie jako administrator. Prosimy o zmianę domyślnych danych uwierzytelniających.",
                    "info",
                )
                return redirect(url_for("change_admin_credentials"))
            flash(f"Zalogowano pomyślnie, {user.name}!", "success")
            if user.admin:
                return redirect("/admin")
            return redirect("/")
        else:
            flash("Nieprawidłowa nazwa użytkownika lub hasło.", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/admin/confirmed")
@login_required
def confirmed():
    if not current_user.admin:
        return redirect(url_for("home"))
    users = User.query.filter_by(email_confirmed=True, confirmed=False).all()
    num_unconfirmed = len(users)
    return render_template(
        "confirmed.html", users=users, num_unconfirmed=num_unconfirmed
    )


@app.route("/admin/delete_unconfirmed/<int:user_id>", methods=["POST"])
@login_required
def delete_unconfirmed(user_id):
    if not current_user.admin:
        return redirect(url_for("home"))
    user = User.query.filter_by(
        id=user_id, email_confirmed=True, confirmed=False
    ).first()
    if user:
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for("confirmed"))


@app.context_processor
def include_num_unconfirmed():
    if not current_user.is_authenticated or not current_user.admin:
        return {}
    num_unconfirmed = User.query.filter_by(
        email_confirmed=True, confirmed=False
    ).count()
    return dict(num_unconfirmed=num_unconfirmed)


@app.route("/confirm/<int:user_id>")
@login_required
def confirm(user_id):
    if not current_user.admin:
        return redirect(url_for("home"))
    user = User.query.get(user_id)
    if user:
        user.confirmed = True
        db.session.commit()

        msg = MailMessage(
            "Rejestracja potwierdzona",
            sender="wiktor.szczurek1@gmail.com",
            recipients=[user.email],
        )
        msg.body = "Twoje konto zostało potwierdzone na silafizjo.pl."
        mail.send(msg)

    return redirect(url_for("confirmed"))


@app.route("/admin/user/<int:user_id>/add_plan", methods=["GET", "POST"])
@login_required
def add_plan(user_id):
    user = User.query.get_or_404(user_id)
    form = TrainingPlanForm()
    if form.validate_on_submit():
        filename = secure_filename(form.file.data.filename)
        existing_plan = TrainingPlan.query.filter_by(
            filename=filename, user_id=user_id
        ).first()
        if existing_plan:
            flash("Ten plan treningowy już został dodany.", "error")
        else:
            form.file.data.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            training_plan = TrainingPlan(filename=filename, user_id=user_id)
            db.session.add(training_plan)
            db.session.commit()
            flash("Plan treningowy został dodany.", "success")

    
    exercises = sorted(Exercise.query.all(), key=lambda e: e.name)
    user_plans = TrainingPlan.query.filter_by(user_id=user_id).all()
    photos = sorted(Photo.query.all(), key=lambda p: p.name)

    return render_template(
        "plans.html",
        form=form,
        user=user,
        training_plans=user_plans,
        exercises=exercises,
        photos=photos,
    )


from flask import abort


@app.route(
    "/admin/user/<int:user_id>/delete_training_plan/<int:plan_id>", methods=["POST"]
)
@login_required
def admin_delete_training_plan(user_id, plan_id):
    user = User.query.get_or_404(user_id)
    if not current_user.admin:
        abort(403)
    training_plan = TrainingPlan.query.get_or_404(plan_id)
    if training_plan.user_id != user.id:
        abort(403)
    db.session.delete(training_plan)
    db.session.commit()
    flash("Plan treningowy został usunięty.", "success")
    return redirect(url_for("add_plan", user_id=user_id))


@app.route("/download_training_plan/<int:plan_id>")
@login_required
def download_training_plan(plan_id):
    plan = TrainingPlan.query.get_or_404(plan_id)
    return send_file(plan.filepath, as_attachment=True)


@app.route("/training_plans")
@login_required
def training_plans():
    if current_user.admin:
        return redirect(url_for("admin"))
    user_plans = TrainingPlan.query.filter_by(user_id=current_user.id).all()

    plans_and_contents = []
    for plan in user_plans:
        with open(plan.filepath, "r", encoding="utf-8") as file:
            try:
                content = file.read()
            except UnicodeDecodeError:
                
                file.seek(0)
                content = file.read(encoding="latin-1")
        if hasattr(plan, "photo"):  
            photo = Photo.query.filter_by(name=plan.photo).first()
        else:
            photo = None  
        plans_and_contents.append({"plan": plan, "content": content, "photo": photo})

    photos = current_user.photos  
    return render_template(
        "training_plans.html",
        plans_and_contents=plans_and_contents,
        exercises=current_user.exercises,
        photos=photos,
    )


@app.route("/exercises_user")
@login_required
def excercises_user():
    if current_user.admin:
        return redirect(url_for("admin"))

    photos = current_user.photos
    exercises = current_user.exercises

    return render_template(
        "excercises_user.html",
        exercises=exercises,
        photos=photos,
    )


@app.route("/admin/add_exercise", methods=["GET", "POST"])
@login_required
def add_exercise():
    if not current_user.admin:
        return redirect(url_for("home"))
    form = AddExerciseForm()
    if form.validate_on_submit():
        exercise = Exercise(name=form.name.data, youtube_link=form.youtube_link.data)
        db.session.add(exercise)
        db.session.commit()
        flash("Ćwiczenie zostało dodane!", "success")
        return redirect(url_for("add_exercise"))
    exercises = Exercise.query.all()
    return render_template("add_exercise.html", form=form, exercises=exercises)


@app.route("/admin/delete_exercise/<int:id>", methods=["POST"])
@login_required
def delete_exercise(id):
    if not current_user.admin:
        return redirect(url_for("home"))

    exercise = Exercise.query.get(id)
    if exercise:
        db.session.delete(exercise)
        db.session.commit()
        flash("Ćwiczenie zostało usunięte!", "success")

    return redirect(url_for("add_exercise"))


@app.route("/admin_add_exercise_to_user/<int:user_id>", methods=["POST"])
@login_required
def admin_add_exercise_to_user(user_id):
    exercise_id = request.form.get("exercise_id")
    user = User.query.get(user_id)
    exercise = Exercise.query.get(exercise_id)
    if user and exercise:
        if exercise in user.exercises:
            flash("To ćwiczenie zostało już dodane.", "error")
        else:
            user.exercises.append(exercise)
            db.session.commit()
            flash("Ćwiczenie zostało dodane.", "success")
    else:
        flash("Błąd - użytkownik lub ćwiczenie nie istnieje.", "error")

    return redirect(url_for("add_plan", user_id=user.id))


@app.route(
    "/admin_delete_exercise_from_user/<int:user_id>/<int:exercise_id>", methods=["POST"]
)
@login_required
def admin_delete_exercise_from_user(user_id, exercise_id):
    user = User.query.get(user_id)
    exercise = Exercise.query.get(exercise_id)
    if user and exercise:
        user.exercises.remove(exercise)
        db.session.commit()
        return redirect(url_for("add_plan", user_id=user.id))
    return "Błąd - użytkownik lub ćwiczenie nie istnieje."


@app.route("/add_photo", methods=["GET", "POST"])
def add_photo():
    if request.method == "POST":
        photo = request.files["photo"]
        name = request.form["name"]
        note = request.form.get("note") 

        
        filename = secure_filename(photo.filename)
     
        photo_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
      
        photo.save(photo_path)

       
        new_photo = Photo(name=name, data=filename, note=note)
        db.session.add(new_photo)
        db.session.commit()

        return redirect(url_for("add_photo"))

    
    photos = Photo.query.all()
    return render_template("add_photo.html", photos=photos)


@app.route("/delete_photo/<int:id>", methods=["POST"])
def delete_photo(id):
    photo = Photo.query.get(id)
    if photo:
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], photo.data)
        if os.path.isfile(file_path):  
            os.remove(file_path)  
            db.session.delete(photo)  
            db.session.commit()

    return redirect(url_for("add_photo"))


@app.route("/admin_add_photo_to_user/<int:user_id>", methods=["POST"])
@login_required
def admin_add_photo_to_user(user_id):
    photo_id = request.form.get("photo_id")
    user = User.query.get(user_id)
    photo = Photo.query.get(photo_id)
    if user and photo:
        if photo in user.photos:
            flash("To zdjęcie zostało już dodane.", "error")
        else:
            user.photos.append(photo)
            db.session.commit()
            flash("Zdjęcie zostało dodane.", "success")
    else:
        flash("Błąd - użytkownik lub zdjęcie nie istnieje.", "error")

    return redirect(url_for("add_plan", user_id=user.id))


@app.route(
    "/admin_delete_photo_from_user/<int:user_id>/<int:photo_id>", methods=["POST"]
)
@login_required
def admin_delete_photo_from_user(user_id, photo_id):
    user = User.query.get(user_id)
    photo = Photo.query.get(photo_id)
    if user and photo:
        user.photos.remove(photo)
        db.session.commit()
        return redirect(url_for("add_plan", user_id=user.id))
    return "Błąd - użytkownik lub zdjęcie nie istnieje."


from flask_mail import Message as MailMessage


@app.route("/admin/send_message/<int:user_id>", methods=["GET", "POST"])
@login_required
def send_message(user_id):
    if not current_user.admin:
        return redirect(url_for("home"))

    user = User.query.get(user_id)
    if user is None:
        flash("Użytkownik nie istnieje.", "error")
        return redirect(url_for("home"))

    if request.method == "POST":
        content = request.form.get("content")
        if not content:
            flash("Wiadomość nie może być pusta.", "error")
        else:
            message = Message(content=content, user_id=user.id)
            db.session.add(message)
            db.session.commit()

           
            mail_message = MailMessage(
                "Nowa informacja na twoim koncie",
                sender="wiktor.szczurek1@gmail.com",  
                recipients=[user.email],
                body=f"Informacja ze strony silafizjo.pl: {content}",
            )
            mail.send(mail_message)

            flash("Wiadomość została wysłana.", "success")
            return redirect(url_for("send_message", user_id=user.id))

    messages = (
        Message.query.filter_by(user_id=user.id)
        .order_by(Message.timestamp.desc())
        .all()
    )
    return render_template("admin_message.html", user=user, messages=messages)


@app.route("/admin/delete_message/<int:message_id>", methods=["POST"])
@login_required
def delete_message(message_id):
    if not current_user.admin:
        return redirect(url_for("home"))

    message = Message.query.get(message_id)
    if message is None:
        flash("Wiadomość nie istnieje.", "error")
        return redirect(url_for("home"))

    user_id = (
        message.user_id
    )  

    db.session.delete(message)
    db.session.commit()

    flash("Wiadomość została usunięta.", "success")
    return redirect(
        url_for("send_message", user_id=user_id)
    )  


@app.route("/messages")
@login_required
def messages():
    messages = (
        Message.query.filter_by(user_id=current_user.id)
        .order_by(Message.timestamp.desc())
        .all()
    )

   
    Message.query.filter_by(user_id=current_user.id).update({Message.is_read: True})
    db.session.commit()

    return render_template("messages.html", messages=messages)


@app.context_processor
def include_num_unread_messages():
    if not current_user.is_authenticated:
        return {}
    num_unread_messages = Message.query.filter_by(
        user_id=current_user.id, is_read=False
    ).count()
    return dict(num_unread_messages=num_unread_messages)


from flask import request, flash


@app.route("/admin/chat/<int:user_id>", methods=["GET", "POST"])
@login_required
def admin_chat(user_id):
    if not current_user.admin:
        flash("Brak uprawnień administratora.", "error")
        return redirect(url_for("home"))

    user = User.query.get(user_id)
    if user is None:
        flash("Użytkownik nie istnieje.", "error")
        return redirect(url_for("home"))

    if request.method == "POST":
        content = request.form.get("content")
        if not content:
            flash("Wiadomość nie może być pusta.", "error")
        else:
            message = ChatMessage(
                content=content, sender_id=current_user.id, recipient_id=user.id
            )
            db.session.add(message)
            db.session.commit()

           
            ChatMessage.query.filter_by(
                sender_id=user.id, recipient_id=current_user.id
            ).update({ChatMessage.is_read: True})
            db.session.commit()

            msg = MailMessage(
                "Nowa wiadomość od Krystian Szczurek",
                sender="your-email@example.com",
                recipients=[user.email],
            )
            msg.body = f"Wiadomość od: {current_user.name} {current_user.surname}\n\nTreść wiadomości:\n{content}"
            mail.send(msg)

            return redirect(url_for("admin_chat", user_id=user.id))

    messages = (
        ChatMessage.query.filter(
            (
                (ChatMessage.sender_id == current_user.id)
                & (ChatMessage.recipient_id == user.id)
            )
            | (
                (ChatMessage.sender_id == user.id)
                & (ChatMessage.recipient_id == current_user.id)
            )
        )
        .order_by(ChatMessage.timestamp.asc())
        .all()
    )

 
    ChatMessage.query.filter_by(sender_id=user.id, recipient_id=current_user.id).update(
        {ChatMessage.is_read: True}
    )
    db.session.commit()

    return render_template("chat.html", user=user, messages=messages)


@app.context_processor
def include_unread_messages_count():
    if not current_user.is_authenticated or not current_user.admin:
        return {}
    unread_messages_count = {}
    users = User.query.filter(User.username != "admin", User.admin != True).all()
    for user in users:
        unread_messages_count[user.id] = ChatMessage.query.filter_by(
            sender_id=user.id, recipient_id=current_user.id, is_read=False
        ).count()
    return dict(unread_messages_count=unread_messages_count)


@app.context_processor
def include_user_unread_messages_count():
    if not current_user.is_authenticated:
        return {}
    user_unread_messages_count = ChatMessage.query.filter_by(
        recipient_id=current_user.id, is_read=False
    ).count()
    return dict(user_unread_messages_count=user_unread_messages_count)


@app.route("/user_chat", methods=["GET", "POST"])
@login_required
def user_chat():
    admin = User.query.filter_by(admin=True).first()
    if admin is None:
        flash("Administrator nie istnieje.", "error")
        return redirect(url_for("home"))

    if request.method == "POST":
        content = request.form.get("content")
        if not content:
            flash("Wiadomość nie może być pusta.", "error")
        else:
            message = ChatMessage(
                content=content, sender_id=current_user.id, recipient_id=admin.id
            )
            db.session.add(message)
            db.session.commit()

            msg = MailMessage(
                "Nowa wiadomość od użytkownika",
                sender="your-email@example.com",
                recipients=[admin.email],
            )
            msg.body = f"Użytkownik: {current_user.name} {current_user.surname}\n\nTreść wiadomości:\n{content}"
            mail.send(msg)

            return redirect(url_for("user_chat"))

    if request.method == "GET":
        messages = ChatMessage.query.filter(
            (ChatMessage.sender_id == current_user.id)
            & (ChatMessage.recipient_id == admin.id)
            | (ChatMessage.sender_id == admin.id)
            & (ChatMessage.recipient_id == current_user.id)
        ).all()
        for message in messages:
            if message.recipient_id == current_user.id:
                message.is_read = True
        db.session.commit()

    messages = (
        ChatMessage.query.filter(
            (ChatMessage.sender_id == current_user.id)
            & (ChatMessage.recipient_id == admin.id)
            | (ChatMessage.sender_id == admin.id)
            & (ChatMessage.recipient_id == current_user.id)
        )
        .order_by(ChatMessage.timestamp.asc())
        .all()
    )

    return render_template("chat.html", messages=messages, user=admin)


@app.route("/support", methods=["GET", "POST"])
def support():
    if request.method == "POST":
        email = request.form.get("email")
        category = request.form.get("category")
        problem = request.form.get("problem")

        
        if category == "logowanie":
            subject = "Problem z logowaniem zgłoszony przez użytkownika"
        elif category == "rejestracja":
            subject = "Problem z rejestracją zgłoszony przez użytkownika"
        elif category == "aplikacja":
            subject = "Problem z aplikacją zgłoszony przez użytkownika"
        else:
            subject = "Inny problem zgłoszony przez użytkownika"

       
        msg = MailMessage(subject, sender=email, recipients=[moj_mail])
        msg.body = f"Adres e-mail: {email}\nKategoria problemu: {category}\n\nOpis problemu:\n{problem}"
        mail.send(msg)

        flash("Wiadomość została wysłana. Dziękujemy za kontakt!")
        return redirect(url_for("support"))

    return render_template("support.html")


@app.route("/articles")
def articles():
    articles = Article.query.order_by(Article.timestamp.desc()).all()
    return render_template("articles.html", articles=articles)


@app.route("/article/<int:article_id>")
def article(article_id):
    article = Article.query.get_or_404(article_id)
    return render_template("article.html", article=article)


@app.route("/add_article", methods=["GET", "POST"])
@login_required
def add_article():
    if not current_user.admin:
        abort(403)  

    form = AddArticleForm()
    if form.validate_on_submit():
        new_article = Article(
            title=form.title.data, content=form.content.data, author_id=current_user.id
        )
        db.session.add(new_article)
        db.session.commit()
        flash("Artykuł został dodany.", "success")
        return redirect(url_for("articles"))
    return render_template("add_article.html", form=form)


@app.route("/delete_article/<int:article_id>", methods=["POST"])
@login_required
def delete_article(article_id):
    if not current_user.admin:
        abort(403)

    article = Article.query.get_or_404(article_id)
    db.session.delete(article)
    db.session.commit()
    flash("Artykuł został usunięty.", "success")
    return redirect(url_for("articles"))


@app.route("/admin/send_message_to_all", methods=["GET", "POST"])
@login_required
def send_message_to_all():
    if not current_user.admin:
        return redirect(url_for("home"))

    if request.method == "POST":
        email_subject = request.form.get("email_subject")
        content = request.form.get("content")
        if not content:
            flash("Wiadomość nie może być pusta.", "error")
        else:
            users = User.query.all()
            admin_email = "wiktor.szczurek1@gmail.com"

            for user in users:
                if user.email != admin_email:
                    mail_message = MailMessage(
                        email_subject,
                        sender="wiktor.szczurek1@gmail.com",
                        recipients=[user.email],
                        body=f"Wiadomość dla wszystkich użytkowników siłafizjo.pl: {content}",
                    )
                    mail.send(mail_message)

            flash("Wiadomość została wysłana do użytkowników.", "success")
            return redirect(url_for("send_message_to_all"))

    return render_template(
        "admin_message_all.html", page_title="Send Email to All Users"
    )


from flask_login import current_user


@app.route("/profile")
@login_required
def profile():
    user = current_user
    return render_template("profile.html", user=user)


from wtforms import PasswordField


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        validators=[DataRequired()],
        render_kw={"placeholder": "Obecne hasło"},
    )
    new_password = PasswordField(
        validators=[DataRequired()],
        render_kw={"placeholder": "Nowe hasło"},
    )
    confirm_new_password = PasswordField(
        validators=[
            DataRequired(),
            EqualTo("new_password", message="Hasła muszą być takie same"),
        ],
        render_kw={"placeholder": "Potwierdź nowe hasło"},
    )
    submit = SubmitField("Zmień hasło")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if form.new_password.data != form.confirm_new_password.data:
            flash("Nowe hasła nie są zgodne.", "danger")

        elif check_password_hash(current_user.password, form.current_password.data):
            new_hashed_password = generate_password_hash(
                form.new_password.data, method="sha256"
            )
            current_user.password = new_hashed_password
            db.session.commit()
            flash("Hasło zostało zmienione!", "success")
            return redirect(url_for("profile"))
        else:
            flash("Obecne hasło jest niepoprawne.", "danger")
    return render_template("change_password.html", form=form)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            existing_email_user = User.query.filter_by(
                email="wiktor.szczurek1@gmail.com"
            ).first()
            if not existing_email_user:
                admin = User(
                    name="Krystian",
                    surname="Szczurek",
                    username="admin",
                    email="wiktor.szczurek1@gmail.com",
                    password=generate_password_hash("admin", method="sha256"),
                    confirmed=True,
                    admin=True,
                    first_login=True,
                )
                db.session.add(admin)
                db.session.commit()
    app.run(debug=True)
