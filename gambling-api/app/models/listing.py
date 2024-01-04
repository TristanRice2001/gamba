from peewee import Model, CharField

class ListingModel(Model):
    name = CharField()

def create_listing_model(db):
    class Listing(ListingModel):
        class Meta:
            database = db

    return Listing