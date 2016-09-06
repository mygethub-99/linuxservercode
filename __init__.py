from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash
from functools import wraps
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
# Changed the name of database builder and added user and other new.
from feb32015db import Base, Restaurant, MenuItem, User
from flask import session as login_session
import flask_excel as excel
import pyexcel
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
# Added logging for debug.
import logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger('sqlalchemy.engine.base').setLevel(logging.DEBUG)
echo = False

app = Flask(__name__)

CLIENT_ID = json.loads(
    open(r'/var/www/Catalog/catalog/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"


# Connect to Database and create database session.
#engine = create_engine('sqlite:///restaurantmapped.db')
engine = create_engine('postgresql://catalog:mydata@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token.
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# Facebook oauth.
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open(r'/var/www/Catalog/catalog/fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open(r'/var/www/Catalog/catalog/fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Use token to get user info from API.
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # Strip expire tag from access token.
    token = result.split("&")[0]
    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Print "url sent for API access:%s"% url
    # Print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]
    # The token must be stored in the login_session in order to logout.
    # Let's strip out the information before the equal sign in our token.
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token
    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data["data"]["url"]
    # See if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;- \
    webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("Now logged in as %s" % login_session['username'])
    return output


# Disconnect a FB user.
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Gmail oauth funtion.
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('/var/www/Catalog/catalog/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already \
            connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info.
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # Add Provider to the login session.
    login_session['provider'] = 'google'
    # See if a user already exist, if so don't make a new one.
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: \
    150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User login code to define users that can access the database.
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Wrap function for login_session argument.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        else:
            return f(*args, **kwargs)
    return decorated_function


# Disconnect a gmail user.
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Restaurant Information.
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])
    
    
# Excel Export APIs to view Restaurant Information.
@app.route("/export/restaurant/xls", methods=['GET'])
def exportRest():
    return excel.make_response_from_tables(session, [Restaurant], "xls")
    

@app.route("/export/custom_export", methods=['GET'])
def customExport():
    get_list = session.query(Restaurant).order_by(Restaurant.name)
    column_names = ['name', 'address', 'phone', 'health_rating']
    return excel.make_response_from_query_sets(get_list, column_names, "xls")


# Show all restaurants.
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
    cuisine = session.query(Restaurant).order_by(asc(Restaurant.cuisine_cat))
    food = ['Asian', 'Italian', 'American', 'Greek', 'Vegetarian', 'Mexican', \
     'All']
    return render_template('restaurantlarge.html', restaurants=restaurants, \
        food=food)
    

# Create a new restaurant.
@app.route('/restaurant/new/', methods=['GET', 'POST'])
@login_required
def newRestaurant():
    if request.method == 'POST':
        newRestaurant = Restaurant(name=request.form['name'], address= \
            request.form['address'], phone=request.form['phone'], \
            health_rating=request.form['rating'], cuisine_cat= \
            request.form['cuisine'], picture=request.form['picture'], \
            user_id=login_session['user_id'])
        session.add(newRestaurant)
        flash('New Restaurant %s Successfully Created' % newRestaurant.name)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newRestaurant.html')


# Edit a restaurant.
@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
@login_required
def editRestaurant(restaurant_id):
    editRest = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if editRest.user_id != login_session['user_id']:
        return noWay()
    if request.method == 'POST':
        if request.form['name']:
            editRest.name = request.form['name']
        if request.form['address']:
            editRest.address = request.form['address']
        if request.form['phone']:
            editRest.phone = request.form['phone']
        if request.form['rating']:
            editRest.health_rating = request.form['rating']
        if request.form['picture']:
            editRest.picture = request.form['picture']
        if request.form['cuisine']:
            editRest.cuisine_cat = request.form['cuisine']
        session.add(editRest)
        session.commit()
        flash('Restaurant Successfully Edited')
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('editRestExpand.html', restaurant=editRest)


# Delete a restaurant.
@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteRestaurant(restaurant_id):
    restaurantToDelete = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if restaurantToDelete.user_id != login_session['user_id']:
        return noWay()
    if request.method == 'POST':
        session.delete(restaurantToDelete)
        flash('%s Successfully Deleted' % restaurantToDelete.name)
        session.commit()
        return redirect(url_for('showRestaurants', restaurant_id=restaurant_id))
    else:
        return render_template('deleteRestaurant.html', \
            restaurant=restaurantToDelete)


# Redirect user if not allowed access.
@app.route('/restaurant/notallowed')
def noWay():
    return render_template('notallowed.html')


# Show a restaurant menu.
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    creator = getUserInfo(restaurant.user_id)
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    # I am doing the login or not check in the menu.html.
    return render_template('menu.html', items=items, restaurant=restaurant, \
        creator=creator)
    

#Filter on a single type of cuisine category.
@app.route('/restaurant/cuisine/<string:cuisine>/')
def showRestCuisine(cuisine):
    food = ['Asian', 'Italian', 'American', 'Greek', 'Vegetarian', 'Mexican', \
    'All']      
    catCuisine = session.query(Restaurant).filter_by(cuisine_cat= cuisine).all()
    return render_template('restaurantlarge.html', restaurants=catCuisine, \
        food=food)
    

# Create a new menu item.
@app.route('/restaurant/<int:restaurant_id>/menu/new/', methods=['GET', 'POST'])
@login_required
def newMenuItem(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if restaurant.user_id != login_session['user_id']:
        return noWay()
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'], description=request.form[
                           'description'], price=request.form['price'], course=\
                           request.form['course'], restaurant_id=restaurant_id)
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id=restaurant_id,\
         restaurant = restaurant)


# Edit a menu item.
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=\
    ['GET', 'POST'])
@login_required
def editMenuItem(restaurant_id, menu_id):
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    # Adding protection to the data.
    if login_session['user_id'] != restaurant.user_id:
        return noWay()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id=\
            restaurant_id, menu_id=menu_id, item=editedItem, \
            restaurant=restaurant)


# Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', \
    methods=['GET', 'POST'])
@login_required
def deleteMenuItem(restaurant_id, menu_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if login_session['user_id'] != restaurant.user_id:
        return noWay()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item=itemToDelete, \
            restaurant=restaurant)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            # Changed from credentials to access_token.
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showRestaurants'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showRestaurants'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

