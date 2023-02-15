import os
import geopy

def long_lat_calc(address):
    geocoder = geopy.Nominatim(user_agent = os.environ["NOMINATIM_USER"])
    address_data = geocoder.geocode(address)
    lat = address_data.latitude
    long = address_data.longitude
    return(long, lat)