import os


basedir = os.path.dirname(os.path.abspath(__file__))


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "hard to guess")

    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.qq.com")

    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))

    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() in ("true", "on", "1")

    MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "true").lower() in ("true", "on", "1")

    MAIL_USERNAME = os.getenv("MAIL_USERNAME")

    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

    FLASKY_MAIL_SUBJECT_PREFIX = "[FLASKY]"

    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER")

    FLASKY_ADMIN = os.getenv("FLASKY_ADMIN")

    FLASKY_POSTS_PER_PAGE = 15

    FLASKY_FOLLOWERS_PER_PAGE = 15

    FLASKY_COMMENTS_PER_PAGE = 15

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DEV_DATABASE_URL", "sqlite:///" + os.path.join(basedir, "db-dev.sqlite")
    )


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.getenv("TEST_DATABASE_URL", "sqlite://")
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", "sqlite:///" + os.path.join(basedir, "db.sqlite")
    )


config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
