
"""
Configuration file, each configuration is explained to the right of the variable.
"""
import os


config = {}
config['basedir'] = os.path.abspath(os.path.dirname(__file__))
config['show_authorised_ships_only'] = True # Only show authed ships on the map.
config['interval'] = 5 # Interval to ping location.
config['enable_transmission'] = True
config['connect_to'] = "192.168.0.37"
config['key_server'] = "192.168.0.37:8080"
config['show_sig_attached'] = True # Show ships that are not authenticated, but have a signature attached.
config['ship_name'] = "Ocean Blue"
config['show_lines'] = True
config['show_trails'] = True
config['debug'] = True
config['use_correct_sig'] = True
config['use_encryption'] = False