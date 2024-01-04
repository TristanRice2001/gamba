from peewee import Model, CharField, BooleanField


class UserModel(Model):
    username = CharField(unique=True)
    email = CharField(unique=True)
    is_admin = BooleanField(default=False) 
    password = CharField()

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email
        }

def create_user_model(db):
    class UserWithMeta(UserModel):

        class Meta:
            database = db

    return UserWithMeta