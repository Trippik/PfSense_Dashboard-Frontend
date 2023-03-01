import requests
import json
import folium

def get_ip_details(ip: str):
    resp = requests.get(f"https://ipwho.is/{ip}?security=1")
    return resp.json()

def show_ip_map(ip_details):
    folium_map = folium.Map(location=(ip_details["latitude"], ip_details["longitude"]), zoom_start=6)
    folium.Marker(
        [float(ip_details["latitude"]), float(ip_details["longitude"])],
        popup = ip_details["ip"] + "\n" + ip_details["connection"]["isp"],
        icon=folium.Icon(color="blue", icon="sitemap", prefix="fa")
        ).add_to(folium_map)
    return folium_map