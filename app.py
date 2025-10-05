from datetime import timedelta, datetime
import os

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

# --- App Config ---
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///kitchenmaster.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "change-me-in-production")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- Models ---
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")  # 'admin' or 'user'

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
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)  # the user who suggested
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

# --- Helpers ---
def ensure_db_seed_admin():
    db.create_all()
    # Create a default admin if none exists (for first-time testing)
    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            password_hash=generate_password_hash("admin123"),
            role="admin",
        )
        db.session.add(admin)
        db.session.commit()

def require_admin(user_id):
    user = User.query.get(user_id)
    return user and user.role == "admin"

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username","").strip()
    password = data.get("password","").strip()
    role = data.get("role", "user")
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if role not in ("user", "admin"):
        role = "user"
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "username already exists"}), 400
    user = User(username=username, password_hash=generate_password_hash(password), role=role)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "user created", "user": user.to_dict()}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username","").strip()
    password = data.get("password","").strip()
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "invalid credentials"}), 401
    token = create_access_token(identity={"id": user.id, "role": user.role, "username": user.username})
    return jsonify({"access_token": token, "user": user.to_dict()})

# --- Recipes ---
@app.route("/items", methods=["GET"])
@jwt_required()
def list_recipes():
    # Everyone logged-in can see approved recipes
    recipes = Recipe.query.order_by(Recipe.created_at.desc()).all()
    return jsonify([r.to_dict() for r in recipes])

@app.route("/items", methods=["POST"])
@jwt_required()
def create_recipe():
    current_user = get_jwt_identity()
    if not require_admin(current_user["id"]):
        return jsonify({"error": "admin only"}), 403
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "title is required"}), 400
    recipe = Recipe(
        title=title,
        description=data.get("description",""),
        ingredients=data.get("ingredients",""),
        steps=data.get("steps",""),
        owner_id=current_user["id"]
    )
    db.session.add(recipe)
    db.session.commit()
    return jsonify(recipe.to_dict()), 201

@app.route("/items/<int:rid>", methods=["PUT"])
@jwt_required()
def update_recipe(rid):
    current_user = get_jwt_identity()
    if not require_admin(current_user["id"]):
        return jsonify({"error": "admin only"}), 403
    recipe = Recipe.query.get_or_404(rid)
    data = request.get_json(silent=True) or {}
    for field in ["title", "description", "ingredients", "steps"]:
        if field in data and isinstance(data[field], str):
            setattr(recipe, field, data[field])
    db.session.commit()
    return jsonify(recipe.to_dict())

@app.route("/items/<int:rid>", methods=["DELETE"])
@jwt_required()
def delete_recipe(rid):
    current_user = get_jwt_identity()
    if not require_admin(current_user["id"]):
        return jsonify({"error": "admin only"}), 403
    recipe = Recipe.query.get_or_404(rid)
    db.session.delete(recipe)
    db.session.commit()
    return jsonify({"message": "deleted"})

# --- Suggestions Flow ---
@app.route("/suggestions", methods=["POST"])
@jwt_required()
def create_suggestion():
    current_user = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "title is required"}), 400
    s = Suggestion(
        title=title,
        description=data.get("description",""),
        ingredients=data.get("ingredients",""),
        steps=data.get("steps",""),
        owner_id=current_user["id"]
    )
    db.session.add(s)
    db.session.commit()
    return jsonify(s.to_dict()), 201

@app.route("/suggestions", methods=["GET"])
@jwt_required()
def list_suggestions():
    current_user = get_jwt_identity()
    if not require_admin(current_user["id"]):
        return jsonify({"error": "admin only"}), 403
    suggestions = Suggestion.query.order_by(Suggestion.created_at.desc()).all()
    return jsonify([s.to_dict() for s in suggestions])

@app.route("/suggestions/<int:sid>/approve", methods=["POST"])
@jwt_required()
def approve_suggestion(sid):
    current_user = get_jwt_identity()
    if not require_admin(current_user["id"]):
        return jsonify({"error": "admin only"}), 403
    s = Suggestion.query.get_or_404(sid)
    # Create a recipe from suggestion
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
    return jsonify({"message": "approved", "recipe": recipe.to_dict()})

@app.route("/suggestions/<int:sid>", methods=["DELETE"])
@jwt_required()
def reject_suggestion(sid):
    current_user = get_jwt_identity()
    if not require_admin(current_user["id"]):
        return jsonify({"error": "admin only"}), 403
    s = Suggestion.query.get_or_404(sid)
    db.session.delete(s)
    db.session.commit()
    return jsonify({"message": "rejected"})

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "name": "KitchenMaster API"}), 200

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


