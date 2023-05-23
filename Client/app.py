""" Imports """
import crypt
from flask import Flask, render_template, request, json
import socketio as sio
from flask_socketio import SocketIO, emit, send
import socket as sock
import utils as utils
from classes import APConfig,  Logger
from flask_apscheduler import APScheduler
import json as jsonLib
from config import config as personal_conf
import crypt as crypt_module
from pyais.encode import encode_dict
from pyais import decode
from flask_sqlalchemy import SQLAlchemy
import os
import datetime
from database import Register_Database, Ais_Packet, Vessel

sqlite_db = SQLAlchemy()
app = Flask(__name__) # Initializing Flask Application

app.config['SECRET_KEY'] = 'TheSecretKeyOfAwesomeness' #TODO: Change this to an ENV variable for production.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(personal_conf['basedir'],'ship_logs.db') # Location to store the SQLite DB.


sqlite_db = Register_Database(app) # Create DB Class.



def from_packet_to_db(messages, authed, sig):
    """
    Converts from received object to db object.
    :param packet: Transmission packet
    :return: Ais_Packet DB object
    """

    ais_packet = Ais_Packet(
        messages = messages,
        authed = authed,
    )
    return ais_packet


with app.app_context():
    """ Checks to see if tables already exist based upon supplied classes, if not the tables are created. """
    sqlite_db.create_all()


""" Sheduling """
scheduler = APScheduler() # Sheduling Object.
scheduler.init_app(app) # Initialising Sheduler
scheduler.start() # Starting the sheduler.


""" Initialising Socket.IO """
socketio = SocketIO(app)



""" Defining Globals """
global ships # Creating global variable for ships.
global keys # Creating global variable for keys.
global ship_logs # Creating global variable for ship logs.


ships = {} # Setting ships as a dictionary.
ship_logs = [] # Setting ship logs as a literal list.
self_ship = utils.Generate_self_packet() # Generating intial self packet.
private_pem, public_pem = crypt_module.load_keys(self_ship['mmsi']) # Requesting and loading RSA keys. See crypt.py for more info.
keys = crypt_module.retrive_public_keys() # Requesting public keys from distribution server.



@app.route('/', methods=["GET", "POST"])
def Index():
    """
    Main Page / Index.

    Returns the index page, self ship data, ship logs,
    Configuration values for showing authed ships / transmission enabled.
    :return: Index.html, lat, lon, ship logs,configuration information.
    """
    if request.method == "GET": # Visitting the page
        lat, lon = utils.GetLocation() # Gathers ships current location.
        global ships # Inits global variable
        global ship_logs # See above
        logs = Ais_Packet.query.all()
        packets = []
        for log in logs: # Iterates through logs and builds json packet to return to user.
            messages = utils.messages_from_string(log.messages)
            decoded, sig = utils.messages_to_packet(messages, log.authed)
            packet= {"data": decoded, "sig": sig, "messages": messages}
            packets.append(packet)
        return render_template("index.html", lat=self_ship['lat'],lon=self_ship['lon'], ships=packets, show_authorised_ships_only=personal_conf['show_authorised_ships_only'], enable_transmission=personal_conf['enable_transmission'], show_lines=personal_conf['show_lines'])


@app.route('/settings/', methods=['GET', 'POST'])
def Settings():
    """
    Handler for the settings page request, exports the configuration to the website.
    :return: Settings.html, Configuration Data
    """
    if request.method == "GET":
        return render_template('settings.html', config=personal_conf)


@app.route('/logs/', methods=['GET'])
def ViewLogs():
    """
    Handler for the logs page request, exports the ship logs to the website.
    :return: Logs.html alongside ship logs.
    """
    if request.method == "GET":
        logs = Ais_Packet.query.all()
        packets = []
        for log in logs:
            messages = utils.messages_from_string(log.messages)
            decoded, sig = utils.messages_to_packet(messages, log.authed)
            packet= {"data": decoded, "sig": sig, "messages": messages, "id": log.log_id}
            packets.append(packet)
        return render_template('logs.html', ship_logs=packets)


@app.route('/view_log/<log>')
def ViewLog(log=False):
    """
    Route to view individual log. Log ID is passed. If log ID is found, log view page with data packet.
    :param log: Log ID to be found.
    :return: View_Log.html, encoded and decoded packet.
    """
    if not log == False:
        pack = Ais_Packet.query.get(int(log))
        messages = utils.messages_from_string(pack.messages)
        decodeed = decode(*messages)
        print(decodeed)
        decoded, sig = utils.messages_to_packet(messages, pack.authed)
        packet = {"data": decoded, "sig": sig, "messages": messages, "id": pack.log_id}
        return render_template('view_log.html', log=packet, extra=decodeed)
    else:
        return "no logs found"



""" SOCKET.IO FUNCTIONALITY """

@socketio.on('inital_connection')
def SocketIO_Initial_Connection(json):
    print(f"Received Data: {str(json)} ")

@socketio.on('message')
def handle_message(data):
    print(f'received message: {data} ')

@socketio.on('update_subscribe')
def handle_event(data):
    print(f'received data: {data}')

@socketio.on('ship_ping')
def handle_ping(data):

    """
    Used to handle the incoming data from the socket.io connections.
    Takes the incoming AIS encoded packet, rebuilds the signed string,
    Checks the signed string against list of existing RSA public keys,
    Emits AIS MessageType1 with authentication state.
    :param data: Incoming Data from socket.io
    :return: Nothing
    """


    ship_ping_logger = Logger("ship_ping") # Creating Logger
    ship_ping_logger.Log(f'Received Ping from Boat: {data}')


    try:
        messages = data['messages']
        utils.messages_to_string(messages)
        decoded = decode(*messages)

        ship_ping_logger.Log(f"---- DECODED ----\n {decoded}\n \n")

        ais_sig = decoded.sig
        ais_mmsi = str(decoded.mmsi)
        ais_packet = {
            "id": "AIVDM",
            "type": 1,
            "mmsi": ais_mmsi,
            "lat": decoded.lat,
            "lon": decoded.lon,
            "course": decoded.course,
            "authed": 1,
        }

        ship_ping_logger.Log(f"----AIS SIG---\n {ais_sig}\n \n")
        ship_ping_logger.Log(f"----AIS PACKET----\n {ais_packet}\n \n")
        sig = ais_sig

    except:
        raise ValueError("Incorrect Data has been sent.")

    json_packet = ais_packet

    global keys
    global ships
    global ship_logs

    if not json_packet['mmsi'] in keys: # Checking MMSI against available keys.

        if not sig == None: # Mark packet as signature attached but no key found.
            try:
                keys = crypt_module.retrive_public_keys() # Refresh key listing if possible.
            except:
                raise ValueError("Key Server cannot be reached")


            ship_ping_logger.Log(f"SIG-ATTACHED {type(json_packet)} {json_packet}")

            json_packet['authed'] = 2

            pack = {'data': json_packet, 'sig': sig}

            ship_logs.append(pack)
            ais_packet = from_packet_to_db((utils.messages_to_string(messages)), 2, sig)
            sqlite_db.session.add(ais_packet)
            sqlite_db.session.commit()
            pack['log_id'] = ais_packet.log_id
            emit('ship_ping_update', pack, broadcast=True)

    else: # Key has been found in data, attempt to verify signature.

        ship_ping_logger.Log(f"MMSI: {json_packet['mmsi']} found in key data.")
        ship_public_pem = crypt_module.load_public_key(keys[json_packet['mmsi']])

        if crypt.verify_data_sig(ship_public_pem, json_packet, sig): # Signature verified, emit authed ship.
            ship_ping_logger.Log(f"AUTHED {type(json_packet)}, {json_packet}")
            # json_packet = json.loads(json_packet)
            ships[json_packet["mmsi"]] = json_packet
            pack = {'data': json_packet, 'sig': sig, "messages": messages}
            ship_logs.append(pack)
            ais_packet = from_packet_to_db((utils.messages_to_string(messages)), 1, sig)
            sqlite_db.session.add(ais_packet)
            sqlite_db.session.commit()
            print(datetime.datetime.now())
            pack['log_id'] = ais_packet.log_id
            emit('ship_ping_update', pack, broadcast=True)

        else: # Signature not verified. Emit Unauthed Ship ping.
            ship_ping_logger.Log("UNAUTHED" , f"{type(json_packet)} {json_packet}")
            # json_packet = json.loads(json_packet)
            json_packet['authed'] = 0
            pack = {'data': json_packet, 'sig': sig, "messages": messages}
            ais_packet = from_packet_to_db((utils.messages_to_string(messages)), 0, sig)
            sqlite_db.session.add(ais_packet)
            sqlite_db.session.commit()
            pack['log_id'] = ais_packet.log_id
            ship_logs.append(pack)

            emit('ship_ping_update', pack, broadcast=True)

@socketio.on('request_listings')
def handle_request_listings(data):
    """
    Used to handle the request for ship logs / listings.
    :param data: Incoming Socket.IO data.
    :return: Nothing
    """
    print(f'Received Listing Request')
    emit('ship_listing_update', ships)


# Updating the config.
@socketio.on('update_config')
def handle_update_config(data):
    """
    Used to handle the incoming update for configuration data.
    This does not update the config file.

    Some Input Validation on the boolean variables.

    :param data: Incoming Socket.IO Config Data
    :return: Nothing
    """
    print(data)
    if not type(data['show_authorised_ships_only'])==bool:
        print("Show Authed Ships is not boolean.")

        raise ValueError("Show Authed Ships update is not boolean.")

    if not type(data['enable_transmission']) == bool:
        raise ValueError("Enable Transmission is not boolean.")

    for update in data:
        personal_conf[update] = data[update]

@socketio.on('clear_logs')
def handle_clear_logs(data):
    """
    Used to handle the request to clear ship logs.
    :param data: Socket.IO data, this should be empty / nill.
    :return:  Nothing
    """
    print("--CLEARING LOGS--")
    global ship_logs
    ship_logs = []
first_time_transmit = True


@scheduler.task('interval', id="transmit_location", seconds=personal_conf['interval'], misfire_grace_time=900)
def transmit_location():
    """
    Sheduled task to broadcast AIS MessageType1 with signature embedded in.
    Builds MessageType1 Packet, converts to string, signs the string.
    Adds the signature to the packet, encodes in AIS MessageType1 Communication.
    Emits the packet to designated host.

    The designated host is used for demonstration purposes, in a deployed situation
    a serial broadcast would be made into VHF equipment.
    :return: Nothing
    """

    global first_time_transmit
    transmission_logger = Logger("Transmission")

    if personal_conf['enable_transmission'] == True:

        sio_client = sio.Client()
        sio_client.connect(f"http://{personal_conf['connect_to']}/")

        if first_time_transmit:
            transmission_logger.Log(f"connected to {personal_conf['connect_to']}/")
            packet = utils.Generate_self_packet()
            self_ship['lat'], self_ship['lon'] = packet['lat'], packet['lon']
            pack_to_string = json.dumps(self_ship)
            first_time_transmit = False
        else:
            transmission_logger.Log(f"connected to {personal_conf['connect_to']}/")
            packet = utils.Generate_self_packet(pre_lat = self_ship['lat'], pre_lon = self_ship['lon'])
            self_ship['lat'], self_ship['lon'] = packet['lat'], packet['lon']
            pack_to_string = json.dumps(self_ship)


        data, sig = crypt_module.sign_string(private_pem, pack_to_string)
        packet = json.loads(data)
        if personal_conf['use_correct_sig'] == False:
            packet['sig'] = b'as.a.s,as.,.as.,d.a'
        else:
            packet['sig'] = sig
        transmission_logger.Log(sig)


        encoded = encode_dict(packet, radio_channel="A", talker_id="AIVDM")
        transmission_logger.Log(f"----ENCODED PACKET---- \n {encoded}")
        decoded = decode(*encoded)
        transmission_logger.Log(f"----DECODED PACKET---- \n {decoded}")
        transmission_logger.Log(f"----COMPARING PACKET----\n {packet}")


        pack = {"messages": encoded}
        sio_client.emit("ship_ping", pack)
        sio_client.disconnect()
        transmission_logger.Log(f"Transmitted Packet with signature {sig}")
    else:
        transmission_logger.Log("Enable Transmission is false, not sending.")



# Main Run
if __name__ == '__main__':
    """
    Main Thread, runs the application.
    """
    socketio.run(app,host="0.0.0.0",port=80, debug=True)

