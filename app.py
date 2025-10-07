from datetime import timedelta, datetime
import os

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuración base ---
app = Flask(__name__)

# Base de datos (PostgreSQL en Render o SQLite localmente)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///kitchenmaster.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "change-me-in-production")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)


# --- Modelos ---
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")

    def to_dict(self):
        return {"id": self.id, "username": self.username, "role": self.role}


class Recipe(db.Model):
    __tablename__ = "recipes"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    ingredients = db.Column(db.Text, default="")
    steps = db.Column(db.Text, default="")
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "ingredients": self.ingredients,
            "steps": self.steps,
            "owner_id": self.owner_id,
            "created_at": self.created_at.isoformat() + "Z",
        }


class Suggestion(db.Model):
    __tablename__ = "suggestions"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    ingredients = db.Column(db.Text, default="")
    steps = db.Column(db.Text, default="")
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "ingredients": self.ingredients,
            "steps": self.steps,
            "owner_id": self.owner_id,
            "created_at": self.created_at.isoformat() + "Z",
        }


# --- Funciones auxiliares ---
def ensure_admin_exists():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                password_hash=generate_password_hash("admin123"),
                role="admin"
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin creado: usuario=admin / contraseña=admin123")


# --- Rutas de autenticación ---
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "username y password requeridos"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "El usuario ya existe"}), 400

    user = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Usuario registrado correctamente"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Credenciales incorrectas"}), 401

    token = create_access_token(
        identity=user.id,
        additional_claims={
            "role": user.role,
            "username": user.username
        }
    )

    return jsonify({"access_token": token, "user": user.to_dict()})


# --- Rutas para recetas ---
@app.route("/items", methods=["GET"])
@jwt_required()
def get_recipes():
    recipes = Recipe.query.order_by(Recipe.created_at.desc()).all()
    return jsonify([r.to_dict() for r in recipes])


@app.route("/items", methods=["POST"])
@jwt_required()
def create_recipe():
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")

    if role != "admin":
        return jsonify({"error": "Solo los admin pueden crear recetas"}), 403

    data = request.get_json() or {}
    title = data.get("title", "").strip()

    if not title:
        return jsonify({"error": "El título es obligatorio"}), 400

    recipe = Recipe(
        title=title,
        description=data.get("description", ""),
        ingredients=data.get("ingredients", ""),
        steps=data.get("steps", ""),
        owner_id=current_user_id
    )

    db.session.add(recipe)
    db.session.commit()
    return jsonify(recipe.to_dict()), 201


# --- Rutas para sugerencias ---
@app.route("/suggestions", methods=["POST"])
@jwt_required()
def create_suggestion():
    current_user_id = get_jwt_identity()
    data = request.get_json() or {}
    title = data.get("title", "").strip()

    if not title:
        return jsonify({"error": "El título es obligatorio"}), 400

    suggestion = Suggestion(
        title=title,
        description=data.get("description", ""),
        ingredients=data.get("ingredients", ""),
        steps=data.get("steps", ""),
        owner_id=current_user_id
    )

    db.session.add(suggestion)
    db.session.commit()
    return jsonify(suggestion.to_dict()), 201


@app.route("/suggestions", methods=["GET"])
@jwt_required()
def get_suggestions():
    claims = get_jwt()
    role = claims.get("role")

    if role != "admin":
        return jsonify({"error": "Solo los admin pueden ver sugerencias"}), 403

    suggestions = Suggestion.query.order_by(Suggestion.created_at.desc()).all()
    return jsonify([s.to_dict() for s in suggestions])


@app.route("/suggestions/<int:sid>/approve", methods=["POST"])
@jwt_required()
def approve_suggestion(sid):
    claims = get_jwt()
    role = claims.get("role")

    if role != "admin":
        return jsonify({"error": "Solo los admin pueden aprobar sugerencias"}), 403

    s = Suggestion.query.get_or_404(sid)
    recipe = Recipe(
        title=s.title,
        description=s.description,
        ingredients=s.ingredients,
        steps=s.steps,
        owner_id=s.owner_id
    )
    db.session.add(recipe)
    db.session.delete(s)
    db.session.commit()

    return jsonify({"message": "Sugerencia aprobada", "recipe": recipe.to_dict()})


@app.route("/suggestions/<int:sid>", methods=["DELETE"])
@jwt_required()
def delete_suggestion(sid):
    claims = get_jwt()
    role = claims.get("role")

    if role != "admin":
        return jsonify({"error": "Solo los admin pueden eliminar sugerencias"}), 403

    s = Suggestion.query.get_or_404(sid)
    db.session.delete(s)
    db.session.commit()
    return jsonify({"message": "Sugerencia eliminada"})


# --- Ruta raíz ---
@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "ok", "api": "KitchenMaster API"}), 200


if __name__ == "__main__":
    ensure_admin_exists()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
