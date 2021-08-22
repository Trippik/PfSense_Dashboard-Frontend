# PfSense_Dashboard-Frontend
The WebGUI/Web App frontend for the PfSense Dashboard system, providing admin access, GUI configuration, and data retrieval for the whole system.
  
## ENV Variables  
DB_IP = IP that MySQL is accessible on  
DB_USER = User credential for DB access  
DB_PASS = Password for DB access  
DB_SCHEMA = Name of target Schema in DB  
DB_PORT = Port that DB is accessible on  
NOMINATIM_USER = Email to be affiliated to geocode requests to OpenStreetMap when addresses are ammended or added to system
THREADS = The number of threads assigned to the serving of the web app
  
## Network Requirements
A port will need to be forwarded to port 8080 of the container that will be used for HTTP access to the WebGUI.
