from app import db
from peewee import Model, CharField


class User(Model):
    username = CharField(unique=True)
    email = CharField(unique=True)
    password = CharField()

    class Meta:
        database = db

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email
        }
