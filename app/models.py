from flask import current_app, request, url_for
from flask_login import UserMixin, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.jose import jwt
from time import time
from datetime import datetime
from markdown import markdown
import bleach
import hashlib
import os

from . import db, login_manager
from app.exceptions import ValidationError


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16


class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship("User", backref="role", lazy="dynamic")

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    @staticmethod
    def insert_roles():
        roles = {
            "User": [
                Permission.FOLLOW,
                Permission.COMMENT,
                Permission.WRITE,
            ],
            "Moderator": [
                Permission.FOLLOW,
                Permission.COMMENT,
                Permission.WRITE,
                Permission.MODERATE,
            ],
            "Administrator": [
                Permission.FOLLOW,
                Permission.COMMENT,
                Permission.WRITE,
                Permission.MODERATE,
                Permission.ADMIN,
            ],
        }
        default_role = "User"
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = True if role.name == default_role else False
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return f"<Role {self.name!r}>"


class Follow(db.Model):
    __tablename__ = "follows"
    follower_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Follower {self.follower!r}> <Followed {self.followed!r}>"


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"))
    # role = db.relationship("Role", backref="users")
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))
    posts = db.relationship("Post", backref="author", lazy="dynamic")
    followed = db.relationship(
        "Follow",
        foreign_keys=[Follow.follower_id],
        backref=db.backref("follower", lazy="joined"),
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    followers = db.relationship(
        "Follow",
        foreign_keys=[Follow.followed_id],
        backref=db.backref("followed", lazy="joined"),
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    comments = db.relationship("Comment", backref="author", lazy="dynamic")

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == os.getenv("ADMIN_EMAIL"):
                self.role = Role.query.filter_by(name="Administrator").first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = self.gravatar_hash()
        self.follow(self)

    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    @staticmethod
    def add_admin():
        admin = User(
            username=os.getenv("ADMIN_USER", "admin"),
            email=os.getenv("ADMIN_EMAIL", current_app.config["FLASKY_ADMIN"]),
            password=os.getenv("ADMIN_PWD", "password"),
            role=Role.query.filter_by(name="Administrator").first(),
            confirmed=True,
        )
        db.session.add(admin)
        db.session.commit()

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expires_in=3600):
        """生成用于验证的JWT(json web token)"""
        now = int(time())
        # 签名算法
        header = {"alg": "HS256"}
        # 用于签名的密钥
        key = current_app.config["SECRET_KEY"]
        # 待签名的数据负载
        data = {"id": self.id, "iat": now, "exp": now + expires_in}

        return jwt.encode(header=header, payload=data, key=key).decode("utf-8")

    def validate_token(self, token):
        key = current_app.config["SECRET_KEY"]
        now = int(time())
        try:
            data = jwt.decode(token, key)
            expiration = int(data.get("exp"))
        except:
            return False
        if data.get("id") != self.id or now > expiration:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    @staticmethod
    def reset_password(token, new_password):
        key = current_app.config["SECRET_KEY"]
        now = int(time())
        try:
            data = jwt.decode(token, key)
            expiration = int(data.get("exp"))
            user = User.query.get(data.get("id"))
        except:
            return False
        if user is None or now > expiration:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def generate_email_change_token(self, new_email, expires_in=3600):
        now = int(time())
        # 签名算法
        header = {"alg": "HS256"}
        # 用于签名的密钥
        key = current_app.config["SECRET_KEY"]
        # 待签名的数据负载
        data = {
            "id": self.id,
            "new_email": new_email,
            "iat": now,
            "exp": now + expires_in,
        }

        return jwt.encode(header=header, payload=data, key=key).decode("utf-8")

    def change_email(self, token):
        key = current_app.config["SECRET_KEY"]
        now = int(time())
        try:
            data = jwt.decode(token, key)
            expiration = int(data.get("exp"))
            new_email = data.get("new_email")
        except:
            return False
        if (
            data.get("id") != self.id
            or now > expiration
            or not new_email
            or self.query.filter_by(email=new_email).first()
        ):
            return False
        self.email = new_email
        self.avatar_hash = self.gravatar_hash()
        db.session.add(self)
        return True

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()

    def gravatar_hash(self):
        return hashlib.md5(self.email.lower().encode("utf-8")).hexdigest()

    def gravatar(self, size=100, default="identicon", rating="g"):
        # url = "https://gravatar.zeruns.tech/avatar"
        url = "https://gravatar.loli.net/avatar"
        hash = self.avatar_hash or self.gravatar_hash()
        return f"{url}/{hash}?s={size}&d={default}&r={rating}"

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        if user.id is None:
            return False
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        if user.id is None:
            return False
        return self.followers.filter_by(follower_id=user.id).first() is not None

    @property
    def followed_posts(self):
        return Post.query.join(Follow, Follow.followed_id == Post.author_id).filter(
            Follow.follower_id == self.id
        )

    def to_json(self):
        json_user = {
            "url": url_for("api.get_user", id=self.id),
            "username": self.username,
            "member_since": self.member_since,
            "last_seen": self.last_seen,
            "posts_url": url_for("api.get_user_posts", id=self.id),
            "followed_posts_url": url_for("api.get_user_followed_posts", id=self.id),
            "post_count": self.posts.count(),
        }
        return json_user

    def generate_auth_token(self, expires_in=3600):
        """生成用于验证的JWT(json web token)"""
        now = int(time())
        # 签名算法
        header = {"alg": "HS256"}
        # 用于签名的密钥
        key = current_app.config["SECRET_KEY"]
        # 待签名的数据负载
        data = {"id": self.id, "iat": now, "exp": now + expires_in}

        return jwt.encode(header=header, payload=data, key=key).decode("utf-8")

    @staticmethod
    def verify_auth_token(token):
        key = current_app.config["SECRET_KEY"]
        now = int(time())
        try:
            data = jwt.decode(token, key)
            id = data.get("id")
            expiration = int(data.get("exp"))
        except:
            return None
        if now > expiration or id is None:
            return None
        return User.query.get(id)

    def __repr__(self):
        return f"<User {self.username!r}>"


class AnonymousUser(AnonymousUserMixin):
    def can(self, perm):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser


class Post(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comments = db.relationship("Comment", backref="post", lazy="dynamic")

    def to_json(self):
        json_post = {
            "url": url_for("api.get_post", id=self.id),
            "body": self.body,
            "body_html": self.body_html,
            "timestamp": self.timestamp,
            "author_url": url_for("api.get_user", id=self.author_id),
            "comments_url": url_for("api.get_post_comments", id=self.id),
            "comment_count": self.comments.count(),
        }
        return json_post

    @staticmethod
    def from_json(json_post):
        body = json_post.get("body")
        if body is None or body == "":
            raise ValidationError("post does not have a body")
        return Post(body=body)

    @staticmethod
    def on_change_body(target, value, oldvalue, initiator):
        allowed_tags = [
            "a",
            "abbr",
            "acronym",
            "b",
            "blockquote",
            "code",
            "em",
            "i",
            "li",
            "ol",
            "pre",
            "strong",
            "ul",
            "h1",
            "h2",
            "h3",
            "p",
        ]
        target.body_html = bleach.linkify(
            bleach.clean(
                markdown(value, output_format="html"), tags=allowed_tags, strip=True
            )
        )


db.event.listen(Post.body, "set", Post.on_change_body)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"))

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = [
            "a",
            "abbr",
            "acronym",
            "b",
            "code",
            "em",
            "i",
            "strong",
            "mark",
        ]
        target.body_html = bleach.linkify(
            bleach.clean(
                markdown(value, output_format="html"), tags=allowed_tags, strip=True
            )
        )

    def to_json(self):
        json_comment = {
            "url": url_for("api.get_comment", id=self.id, _external=True),
            "post_url": url_for("api.get_post", id=self.post_id, _external=True),
            "body": self.body,
            "body_html": self.body_html,
            "timestamp": self.timestamp,
            "author_url": url_for("api.get_user", id=self.author_id, _external=True),
        }
        return json_comment

    @staticmethod
    def from_json(json_comment):
        body = json_comment.get("body")
        if body is None or body == "":
            raise ValidationError("comment does not have a body")
        return Comment(body=body)


db.event.listen(Comment.body, "set", Comment.on_changed_body)
