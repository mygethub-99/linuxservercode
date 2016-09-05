# FSND Linux Server

This FSND project requires the configuration of a Linux server VM that will be used to host a catalog application. The catalog web project that is hosted on this server project is a web site that highlights a few of the Dallas Texas area restaurants.
The host server is reachable at http://ec2-52-41-58-45.us-west-2.compute.amazonaws.com
****
Main Project Milestones
Server Access
Server Security
Server Configuration/Applications
****
#Server Access
IP address: 52.41.58.46

SSH Incoming PORT: 2200

TCP Incoming port 80 opened

UDP Incoming port 123

Web Application URL: http://52.41.58.45

*AWS-Server:http://ec2-52-41-58-45.us-west-2.compute.amazonaws.com
Server access has been setup for user grader with sudo access

*ssh -i ~/.ssh/grader -p 2200 grader@52.41.58.45
*password phrase is: grader12

#Security
Server firewall has been activated
Port 2200 has been opened for ssh access
ssh keys have been installed for user "grader"

#Server Configuration/Applications

Server time has been set to UTC

Installed Applications

* Apache2

* Python-setuptools

* libapache2-mod-wsgi

* Git Application

* libapache2-mod-wsgi python-dev
* python-pip
* virtualenv
Flask
httplib2
requests
flask-seasurf
oauth2client
python-psycopg2
sqlalchemy
flask_excel
postgesql
postgresql-contrib











## Name of Project: Dallas Texas Restaurant app.

### Description: The Dallas Texas Restaurant Application provides a list of restaurants along with particulars such as location, map, type of cuisine, and menu items of restaurants in Dallas Texas. Web App incorporates user registration, and oauth authentication along with the ability to post, edit and delete new restaurants, and menu items. Site allows the user to filter for particular cuisine types to narrow the list of restaurants to view.
***

### Required Files and software.

Python: feb32015.py (Creates db, and tables), dbpopfeb3.py (Populates the DB with items for restaurant), dropallfeb32015.py (Drops all table data in the db), master.py (contains the main server code)

json: FB_client_secrets.json, and client_secrets.json provide the needed code to allow for oauth authentication to take palce.

restaurantmapped.db: This is a sqlite db where all the apps data is stored and managed.

README.md: You are looking at it.

static folder: Contains the styles.css files that allows for some customized formatting of the web site. All othe files in the static folder are jpg and png files that are used by the web site application.

js: Contains the bootstrap.js file and bootstrap.min.js file used to create cool functions like carousel, drop down menus in a web site. jquery-2.1.4.js provides additional js for the web app.

templates folder: Contain all the .html templates used by the application. flask, jinja are used to render templates from python and to script python within html.
***
## Web Application Setup
 1. Install Vagrant. Follow these instructions. [vagrant] (https://www.udacity.com/wiki/ud197/install-vagrant)
 2. Clone this project from Github. [project] (https://github.com/mygethub-99/proj3fullstack) into the vagrant directory. 
 3. Open Git Bash and navigate to the vagrant folder with the proj3fullstack master.py file. The execute vagrant up.
    Once vagrant vm is loaded execute the vagrant ssh command. 
 4. Once in vagrant shell (see step 1 for more details) Type in "python dropallfeb32015.py" this command will drop all tables in the      db. Very important step!
 5. Type in "python dbpopfeb3.py" to load the database with app data.
 6. Type in "python master.py" to launch the web server application.
 7. Now open a chrome web browser and type in http://localhost:5000/restaurant/ to display the restaurant application.
 8. You may explore the web application as a visitor, or login using facebaook or your google account login.
 9. Once you are logged in you may add new restaurants to edit and display in the web server application.
 10. To add pictures of your restaurant you will need to to use the edit restaurant menu page. Remember, you can only edit restaurants   that you have created or have been made the owner of.
 11. User will need to pip install Flask-Excel and plug in, pyexcel-xls, for the excel export feature to work.
 12. Link to [Flask Excel] (http://flask-excel.readthedocs.org/en/latest/)

***
### List of master.py module functions.
Functions login, fbconnect, fbdisconnect, gconnect, creatUser, getUserInfo, getUserID, gdisconnect, and disconnect are used for logging in or out of the application using oauth function via facebook and google.

login_required decorator used to redirect a user to the login page.

restaurantMenuJSON, menuItemJSON, restaurantJSON, and showRestaurantJSON are used to create output to mobile devices.

showRestaurant displays a list of the restaurants.

newRestaurant builds a new restaurant in the database using sqlachemy.

editRestaurant allows the user to values held in the restaurant db table.

deleteRestaurant allows the user to delete a restaurant from the database.

showMenu will query and display the restaurant menu.

showRestCuisine will query on a particular type of cuisine.

newMenuItem will allow the user to build a new menu item that.

editMenuItem will allow the user to edit a menuitem that they are a owner of.

deleteMenuItem allows the user to delete a menu item.

notallowed notifies the user of when they have attempted to edit or delete a web page they do not have rights to access.

exportRest will allow the user to export the Restaurant table to excel from the sqlalchemy db.

customExport gives the coder the option to control the scope of the export.



