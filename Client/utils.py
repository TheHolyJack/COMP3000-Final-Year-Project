import random
import socket as sock
import numpy as np
import time
from shapely.geometry import Polygon, Point
from config import config as personal_conf
from pyais import decode
"""
Utilities file.

These are stored here as to not clutter up the main file.

"""


"""
The following points are used to designate the zone in which random generation of
location will be generated.
"""
poly = Polygon([
    (49.89932938611323, -5.21158609797218),
    (49.754039862648185, -6.92270670344093),
    (49.56034464924948, -8.410725961691401),
    (48.526610885170776, -7.009437994145387),
    (47.89701117190479, -5.965736822270387),
    (49.170033437817494, -4.449623541020387),
    (49.49935138968446, -3.6586079160203866),
    (49.819380158601845, -3.2850727597703866),
    (49.98213812023041, -3.5597309628953866),
    (50.080939459473804, -3.8563618222703866)])


def random_points_generation(poly, num_points):
    """
    Used to generate random points within the boundries of the poly list.
    :param poly: Polygon in which to generate point within.
    :param num_points: Number of points to generate
    :return: Generated Points
    """
    min_x, min_y, max_x, max_y = poly.bounds

    points = []

    while len(points) < num_points:
        random_point = Point([random.uniform(min_x, max_x),
        random.uniform(min_y, max_y)])
        if (random_point.within(poly)):
            points.append(random_point)
    return points

def random_singular_point(poly):
    """
    Generates one singular random location within the given polygon.
    :param poly: Polygon in which to generate point within.
    :return: Generated Point
    """
    points = random_points_generation(poly, 1)

    return points[0]

def generate_packet():
    """
    Used to generate a random ship packet, this is used for demonstration purposes.
    :return: Random Ship Packet.
    """
    point = random_singular_point(poly)
    packet = {"id": "AIVDM",
              "course": (random.randint(1,360)),
              "status": 0,
              "lat": point.x,
              "lon": point.y,
              "mmsi": str(random.randint(1000, 99999999)),
              "type": 1,
              }
    return packet



def GetLocation():
    """
    Generates random location within polygon.
    :return: x, y coords.
    """
    point = random_singular_point(poly)

    return point.x , point.y


def Generate_self_packet(pre_lat=False,pre_lon=False):
    """
    Combines all of the generation utilities to generate a random ship packet
    :return: Randomly Generated Ship Packet.
    """
    if pre_lat == False or pre_lon == False:
        lat, lon = GetLocation()
    else:

        print(pre_lat, pre_lon)
        pick = random.randint(1,4)
        if pick == 1:
            pre_lat = pre_lat + 0.006
            pre_lon = pre_lon - 0.006

        elif pick == 2:
            pre_lat = pre_lat - 0.006
            pre_lon = pre_lon + 0.006

        elif pick == 3:
            pre_lat = pre_lat - 0.006
            pre_lon = pre_lon - 0.006

        elif pick == 4:
            pre_lat= pre_lat + 0.006
            pre_lon = pre_lon + 0.006

        lat, lon = pre_lat, pre_lon
        print(lat,lon)


    course = (round(random.uniform(1,360), 1))
    packet = {
        "id": "AIVDM",
        "type": 1,
        "mmsi": str(random.randint(000000000, 999999999)),
        # "status": 0,
        # "turn": (random.randint(1, 20)),
        # "speed": 300,
        "lat": round(lat, 4),
        "lon": round(lon, 4),
        "course": course,
        # "heading": course,
        # "raim": 0,
        "authed": 1,
    }
    print(packet['lat'], packet['lon'])
    return packet

def messages_to_packet(messages, authed):
    decoded = decode(*messages)

    ais_sig = decoded.sig

    ais_mmsi = str(decoded.mmsi)

    ais_packet = {
        "id": "AIVDM",
        "type": 1,
        "mmsi": ais_mmsi,
        # "status": decoded.status,
        # "turn": decoded.turn,
        # "speed": decoded.speed,
        "lat": decoded.lat,
        "lon": decoded.lon,
        "course": decoded.course,
        # "heading": decoded.heading,
        # "raim": decoded.raim,
        "authed": authed,
    }

    return ais_packet, ais_sig

def messages_to_string(messages):
    messages_in_string = " ".join(messages)
    return messages_in_string

def messages_from_string(message_string):
    messages = message_string.split(" ")
    return messages