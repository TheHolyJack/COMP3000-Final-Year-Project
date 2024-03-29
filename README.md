
# COMP3000 Final Year Project  - Secure AIS

## Supervisor: Dr Hafizul Asad

## Description
The Automatic Identification System (A.I.S) is an internationally agreed upon requirement for maritime vessels that exceed 300 GT (Gross Tonnage). This system is used to broadcast and receive a maritime vessel’s information, primarily the location, speed, course and heading. Each broadcast is identified by the vessels registered MMSI (Maritime Mobile Service Identity).

This final year project aims to create, model and implement an authentication method into the A.I.S. encoded messages through using RSA Digital Signatures.

Key Size Used: 1024-Bit.

Signature Hash: SHA256

## Implementation

- Public & Private keys are generated and distributed through server package. 
- Data is signed with RSA private key, encoded with signature into NMEA 0183 message. 
- Data is then broadcasted to defined host also running the application. 
- Data is received, decoded, verified against list of public keys. 
- Data is then allocated an authentication status, stored into the database and distributed to any clients connected to the web service. 

This implementation is designed to model an A.I.S, this package is not designed to broadcast over V.H.F.
## Installation

### Requirements
- Windows / Linux Systems are supported. Developed on both Windows and Raspberry Pi machines.
- Python 3.9.2.
- Git.
- Network Connectivity.

#### Clone the repository.
Upon cloning the repository, you will find two folders. One being the client application and one being the key-distribution server. 
```bash
  git clone https://github.com/TheHolyJack/COMP3000-Final-Year-Project
  cd COMP3000-Final-Year-Project/

```
#### Create a virtual environment
```bash
    sudo pip3 install virtualenv
    sudo python3 -m venv Server/env/
    sudo python3 -m venv Client/env/
```
#### Activate Virtual Environment & Install Requirements
At this stage, two terminals will be required. One to run the server package, and one to run the client package. Only one device needs to run the server package.

Terminal 1: Client
```bash
    source /venv/bin/activate 
    pip3 install -r requirements.txt
```

Terminal 2: Server
```bash
cd Server
source env/bin/activate
sudo pip3 install cryptography==36.0.0
sudo pip3 install flask
```

#### Configuring Application 
Changes will need to be made to the configuration file, you will need to know your devices I.P. address, the I.P. of the device hosting the server package and the I.P. of the device you are broadcasting too. 

Example: 
```python3
config['connect_to'] = "192.168.0.47" # Client to broadcast to
config['key_server'] = "192.168.0.37:8080" # Key distribution server, don't forget :8080!
```
If you only have one device, you can use the same devices I.P. address if you really have too, you will just be sending yourself the same positional data you are already seeing. You will however still be able to see the signatures, encoded messages and message information. 

#### Installing PyAIS Modification 
Modification to the PyAIS messages.py file has been made in order to account for the 1600-bit maximum signature size. 

If you have used a virtual environment, the PyAIS library will be installed too env/Lib/pyais/. To overwrite the file simply use:
```bash
cp ../pyAIS/messages.py env/Lib/pyais
```

#### Launching Application
Once configured, they server needs to be launched first. The client application cannot run without obtaining the key pairing from the server.

Terminal 2: Server 
```bash
python3 main.py
```
This will then start the application on port 8080 of the hosting device. 

Terminal 1: Client 

You may not initialise the client application.
```bash
python3 app.py
```

The client application will then retrieve keys from the server, load them and begin the web-service.

This web-service will be accessible from your devices local network I.P. E.G. 192.168.0.5

#### Installation Complete 
Congratulations, the installation is now complete! If you have followed both steps on two devices connected to the same network, your devices should now be generating, encoding and broadcasting authenticated A.I.S. messages between each other!
## Acknowledgements & Licenses
I would like to give acknowledgements to the creators of these libraries, without these this project would not have been possible.
 - [Flask](https://flask.palletsprojects.com/en/2.3.x/license/)
 - [SocketIO](https://github.com/IBM/socket-io/blob/master/LICENSE)
 - [Leaflet.js](https://github.com/Leaflet/Leaflet/blob/main/LICENSE)
  - [APScheduler](https://github.com/agronholm/apscheduler/blob/master/LICENSE.txt)
 - [PyAIS](https://github.com/M0r13n/pyais/blob/master/LICENSE)
 - [Gevent](https://github.com/gevent/gevent/blob/master/LICENSE)

 - [Bootstrap](https://themes.getbootstrap.com/licenses/)
 - [jQuery](https://jquery.org/license/)
 - [OpenStreetMap](https://www.openstreetmap.org/copyright)


## License

[Creative Commons Zero v1.0 Universal](https://github.com/TheHolyJack/COMP3000-Final-Year-Project/blob/main/LICENSE)

