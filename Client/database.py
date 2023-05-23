from flask_sqlalchemy import SQLAlchemy


""" INITIAL SETUP """

sqlite_db = SQLAlchemy()

""" MODELS SECTION """

class Ais_Packet(sqlite_db.Model):
    log_id = sqlite_db.Column(sqlite_db.Integer, primary_key=True)
    messages = sqlite_db.Column(sqlite_db.String(250), unique=False, nullable=False)
    authed = sqlite_db.Column(sqlite_db.Integer, unique=False, nullable=False )

class Vessel(sqlite_db.Model):
    vessel_id = sqlite_db.Column(sqlite_db.Integer, primary_key=True)
    mmsi = sqlite_db.Column(sqlite_db.Integer, unique=True, nullable=False)
    public_key = sqlite_db.Column(sqlite_db.String(300), unique=False, nullable=False)






def Register_Database(app):
    sqlite_db.init_app(app)




    return sqlite_db










