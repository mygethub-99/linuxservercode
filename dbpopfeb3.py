from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from feb32015db import Restaurant, Base, MenuItem, User

#engine = create_engine('sqlite:///restaurantmapped.db')
engine = create_engine('postgresql://catalog:mydata@localhost/catalog')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Owen Workman", email="tomakeitcount@gmail.com",
             picture='/static/healthdepart.png')
session.add(User1)
session.commit()


# Menu for UrbanBurger
restaurant1 = Restaurant(user_id=1, name="Urban Burger", address="1321 \
  Commerce St, The Adolphus Hotel, Dallas, TX 75202", phone="989-234-6070", \
  cuisine_cat="American", health_rating= "Poor", picture \
  ='/static/urbanburger.png')

session.add(restaurant1)
session.commit()

menuItem2 = MenuItem(user_id=1, name="Veggie Burger", description="Juicy \
  grilled veggie patty with tomato mayo and lettuce",
                     price="$7.50", course="Entree", restaurant=restaurant1)

session.add(menuItem2)
session.commit()


menuItem1 = MenuItem(user_id=1, name="French Fries", description="with garlic \
  and parmesan",
                     price="$2.99", course="Appetizer", restaurant=restaurant1)

session.add(menuItem1)
session.commit()

menuItem2 = MenuItem(user_id=1, name="Chicken Burger", description="Juicy \
  grilled chicken patty with tomato mayo and lettuce",
                     price="$5.50", course="Entree", restaurant=restaurant1)

session.add(menuItem2)
session.commit()

menuItem3 = MenuItem(user_id=1, name="Chocolate Cake", description="fresh \
  baked and served with ice cream",
                     price="$3.99", course="Dessert", restaurant=restaurant1)

session.add(menuItem3)
session.commit()

menuItem4 = MenuItem(user_id=1, name="Sirloin Burger", description="Made with \
  grade A beef",
                     price="$7.99", course="Entree", restaurant=restaurant1)

session.add(menuItem4)
session.commit()

menuItem5 = MenuItem(user_id=1, name="Root Beer", description="16oz of \
  refreshing goodness",
                     price="$1.99", course="Beverage", restaurant=restaurant1)

session.add(menuItem5)
session.commit()

menuItem6 = MenuItem(user_id=1, name="Iced Tea", description="with Lemon",
                     price="$.99", course="Beverage", restaurant=restaurant1)

session.add(menuItem6)
session.commit()

menuItem7 = MenuItem(user_id=1, name="Grilled Cheese Sandwich",
                     description="On texas toast with American Cheese", \
                     price="$3.49", course="Entree", restaurant=restaurant1)

session.add(menuItem7)
session.commit()

menuItem8 = MenuItem(user_id=1, name="Veggie Burger", description="Made with \
  freshest of ingredients and home grown spices",
                     price="$5.99", course="Entree", restaurant=restaurant1)

session.add(menuItem8)
session.commit()


# Menu for Super Stir Fry
restaurant2 = Restaurant(user_id=1, name="Super Stir Fry", address="5500 \
  Greenville Ave, Dallas, TX 75206", phone="989-245-6071", cuisine_cat="Asian",\
   health_rating= "Poor", picture= '/static/chinese.jpg')

session.add(restaurant2)
session.commit()


menuItem1 = MenuItem(user_id=1, name="Chicken Stir Fry", description="With \
  your choice of noodles vegetables and sauces", price="$7.99", \
  course="Entree", restaurant=restaurant2)

session.add(menuItem1)
session.commit()

menuItem2 = MenuItem(user_id=1, name="Peking Duck",
       description=" A famous duck dish from Beijing[1] that has been prepared \
       since the imperial era. The meat is prized for its thin, crisp skin, \
       with authentic versions of the dish serving mostly the skin and little \
       meat, sliced in front of the diners by the cook", price="$25", \
       course="Entree", restaurant=restaurant2)

session.add(menuItem2)
session.commit()

menuItem3 = MenuItem(user_id=1, name="Spicy Tuna Roll", description="Seared \
  rare ahi, avocado, edamame, cucumber with wasabi soy sauce ",
       price="15", course="Entree", restaurant=restaurant2)

session.add(menuItem3)
session.commit()

menuItem4 = MenuItem(user_id=1, name="Nepali Momo ", description="Steamed \
  dumplings made with vegetables, spices and meat. ",
       price="12", course="Entree", restaurant=restaurant2)

session.add(menuItem4)
session.commit()

menuItem5 = MenuItem(user_id=1, name="Beef Noodle Soup", description="A \
  Chinese noodle soup made of stewed or red braised beef, beef broth, \
  vegetables and Chinese noodles.", price="14", course="Entree", \
  restaurant=restaurant2)

session.add(menuItem5)
session.commit()

menuItem6 = MenuItem(user_id=1, name="Ramen", description="a Japanese noodle \
  soup dish. It consists of Chinese-style wheat noodles served in a meat- or \
  (occasionally) fish-based broth, often flavored with soy sauce or miso, and \
  uses toppings such as sliced pork, dried seaweed, kamaboko, and green \
  onions.", price="12", course="Entree", restaurant=restaurant2)

session.add(menuItem6)
session.commit()


menuItem7 = MenuItem(user_id=1, name="Jello Fruity", description="Jello with \
  local fresh fruit", price="$4.50", course="Dessert", restaurant=restaurant2)

session.add(menuItem7)
session.commit()


menuItem10 = MenuItem(user_id=1, name="Hot Tea", description="Famous Asian \
  Tea", price="$4.50", course="Beverage", restaurant=restaurant2)

session.add(menuItem10)
session.commit()


# Menu for Panda Garden
restaurant1 = Restaurant(user_id=1, name="Panda Garden",address="3511 Oak Lawn \
  Ave, Dallas, TX 75219", phone="989-865-7530", cuisine_cat="Asian", \
  health_rating= "Good", picture= '/static/stirfry.jpg')

session.add(restaurant1)
session.commit()


menuItem1 = MenuItem(user_id=1, name="Pho", description="a Vietnamese noodle \
  soup consisting of broth, linguine-shaped rice noodles called banh pho, a \
  few herbs, and meat.", price="$8.99", course="Entree", restaurant=restaurant1)

session.add(menuItem1)
session.commit()

menuItem2 = MenuItem(user_id=1, name="Chinese Dumplings", description="a \
  common Chinese dumpling which generally consists of minced meat and finely \
  chopped vegetables wrapped into a piece of dough skin. The skin can be \
  either thin and elastic or thicker.", price="$6.99", course="Appetizer", \
  restaurant=restaurant1)

session.add(menuItem2)
session.commit()

menuItem3 = MenuItem(user_id=1, name="Gyoza", description="light seasoning \
  of Japanese gyoza with salt and soy sauce, and in a thin gyoza wrapper", \
  price="$9.95", course="Entree", restaurant=restaurant1)

session.add(menuItem3)
session.commit()

menuItem4 = MenuItem(user_id=1, name="Stinky Tofu", description="Taiwanese \
  dish, deep fried fermented tofu served with pickled cabbage.", \
  price="$6.99", course="Entree", restaurant=restaurant1)

session.add(menuItem4)
session.commit()

menuItem2 = MenuItem(user_id=1, name="Veggie Burger", description="Juicy \
  grilled veggie patty with tomato mayo and lettuce", price="$9.50", \
  course="Entree", restaurant=restaurant1)

session.add(menuItem2)
session.commit()


menuItem3 = MenuItem(user_id=1, name="Jello Fruity", description="Jello \
  with local fresh fruit", price="$4.50", course="Dessert", \
  restaurant=restaurant1)

session.add(menuItem3)
session.commit()


menuItem4 = MenuItem(user_id=1, name="Hot Tea", description="Famous Asian Tea",\
 price="$4.50", course="Beverage", restaurant=restaurant1)

session.add(menuItem4)
session.commit()


# Menu for Thyme for that
restaurant1 = Restaurant(user_id=1, name="Thyme for That Vegetarian Cuisine", \
  address="4901 Bryan St, Dallas, TX 75206-7613", phone="128-234-5550", \
  cuisine_cat="Vegetarian", health_rating= "Excellent", picture= \
  '/static/veg.jpg')

session.add(restaurant1)
session.commit()


menuItem1 = MenuItem(user_id=1, name="Tres Leches Cake", description="Rich, \
  luscious sponge cake soaked in sweet milk and topped with vanilla bean \
  whipped cream and strawberries.", price="$2.99", course="Dessert", \
  restaurant=restaurant1)

session.add(menuItem1)
session.commit()

menuItem2 = MenuItem(user_id=1, name="Mushroom risotto", description=\
  "Portabello mushrooms in a creamy risotto",
                     price="$5.99", course="Entree", restaurant=restaurant1)

session.add(menuItem2)
session.commit()

menuItem3 = MenuItem(user_id=1, name="Honey Boba Shaved Snow",
       description="Milk snow layered with honey boba, jasmine tea jelly, \
       grass jelly, caramel, cream, and freshly made mochi", price="$4.50", \
       course="Dessert", restaurant=restaurant1)

session.add(menuItem3)
session.commit()

menuItem4 = MenuItem(user_id=1, name="Cauliflower Manchurian", description=\
  "Golden fried cauliflower florets in a midly spiced soya,garlic sauce cooked \
  with fresh cilantro, celery, chilies,ginger & green onions",
       price="$6.95", course="Appetizer", restaurant=restaurant1)

session.add(menuItem4)
session.commit()

menuItem5 = MenuItem(user_id=1, name="Aloo Gobi Burrito", description="Vegan \
  goodness. Burrito filled with rice, garbanzo beans, curry sauce, potatoes \
  (aloo), fried cauliflower (gobi) and chutney. Nom Nom", price="$7.95", \
  course="Entree", restaurant=restaurant1)

session.add(menuItem5)
session.commit()

menuItem2 = MenuItem(user_id=1, name="Veggie Burger", description="Juicy \
  grilled veggie patty with tomato mayo and lettuce", price="$6.80", \
  course="Entree", restaurant=restaurant1)

session.add(menuItem2)
session.commit()


menuItem8 = MenuItem(user_id=1, name="Juice and Smoothy Bar", description=\
  "Pick of any Jice of Smoothy drink", price="$5.95", course="Beverage",\
  restaurant=restaurant1)

session.add(menuItem8)
session.commit()


# Menu for Tony's Bistro
restaurant1 = Restaurant(user_id=1, name="Tony's Bistro", address="1322 \
  Commerce St, The Adolphus Hotel, Dallas, TX 75202", phone="946-430-6070", \
  cuisine_cat="Italian", health_rating= "Excellent", picture= \
  '/static/tonysbistro.png')

session.add(restaurant1)
session.commit()


menuItem1 = MenuItem(user_id=1, name="Shellfish Tower", description=\
  "Lobster, shrimp, sea snails, crawfish, stacked into a delicious tower", \
  price="$13.95", course="Entree", restaurant=restaurant1)

session.add(menuItem1)
session.commit()

menuItem2 = MenuItem(user_id=1, name="Chicken and Rice", description=\
  "Chicken... and rice", price="$4.95", course="Entree", restaurant=restaurant1)

session.add(menuItem2)
session.commit()

menuItem3 = MenuItem(user_id=1, name="Mom's Spaghetti", description=\
  "Spaghetti with some incredible tomato sauce made by mom", price="$6.95", \
  course="Entree", restaurant=restaurant1)

session.add(menuItem3)
session.commit()

menuItem4 = MenuItem(user_id=1, name="Choc Full O\' Mint (Smitten\'s \
  Fresh Mint Chip ice cream)",
       description="Milk, cream, salt, ..., Liquid nitrogen magic. \
       Signed waver required.", price="$3.95", course="Dessert", \
       restaurant=restaurant1)

session.add(menuItem4)
session.commit()

menuItem5 = MenuItem(user_id=1, name="Tonkatsu Ramen", description=\
  "Noodles in a delicious pork-based broth with a soft-boiled egg", \
  price="$7.95", course="Entree",restaurant=restaurant1)

session.add(menuItem5)
session.commit()


menuItem6 = MenuItem(user_id=1, name="Noodle Bowl", description="Noodles in \
  a delicious pork juice", price="$3.95", course="Appetizer",\
  restaurant=restaurant1)

session.add(menuItem6)
session.commit()


menuItem7 = MenuItem(user_id=1, name="Carmel Cake", description=\
  "Hot fresh cake with warm carmel", price="$4.95", course="Dessert",\
  restaurant=restaurant1)

session.add(menuItem7)
session.commit()


menuItem8 = MenuItem(user_id=1, name="Coke Fountain", description=\
  "All famous Coke products", price="$2.95", course="Beverage",\
  restaurant=restaurant1)

session.add(menuItem8)
session.commit()


menuItem9 = MenuItem(user_id=1, name="Wine List", description="We have red \
  and white wine", price="$4.95", course="Beverage",restaurant=restaurant1)

session.add(menuItem9)
session.commit()


# Menu for Andala's
restaurant1 = Restaurant(user_id=1, name="Andala's", address="10477 Lombardy \
  Ln, Dallas, TX 75220-4349", phone="989-234-6070", cuisine_cat="Italian", \
  health_rating= "Good", picture= '/static/andala.png')

session.add(restaurant1)
session.commit()


menuItem1 = MenuItem(user_id=1, name="Lamb Curry", description="Slow cook \
  that thang in a pool of tomatoes, onions and alllll those tasty Indian \
  spices. Mmmm.",price="$9.95", course="Entree", restaurant=restaurant1)

session.add(menuItem1)
session.commit()

menuItem2 = MenuItem(user_id=1, name="Chicken Marsala", description="Chicken \
  cooked in Marsala wine sauce with mushrooms", price="$7.95", course="Entree",\
   restaurant=restaurant1)

session.add(menuItem2)
session.commit()

menuItem3 = MenuItem(user_id=1, name="Potstickers", description="Delicious \
  chicken and veggies encapsulated in fried dough.", price="$6.50", course=\
  "Appetizer", restaurant=restaurant1)

session.add(menuItem3)
session.commit()

menuItem4 = MenuItem(user_id=1, name="Nigiri Sampler", description="Maguro, \
  Sake, Hamachi, Unagi, Uni, TORO!", price="$6.75", course="Appetizer", \
  restaurant=restaurant1)

session.add(menuItem4)
session.commit()

menuItem5 = MenuItem(user_id=1, name="Veggie Burger", description="Juicy \
  grilled veggie patty with tomato mayo and lettuce", price="$7.00", \
  course="Entree", restaurant=restaurant1)

session.add(menuItem5)
session.commit()


menuItem6 = MenuItem(user_id=1, name="Cake of the Day", description=\
  "Daily pick of Chocolate, Carmel, Strawberry or Vanilla homemade \
  cake", price="$3.50", course="Dessert", restaurant=restaurant1)

session.add(menuItem6)
session.commit()


menuItem7 = MenuItem(user_id=1, name="Soft Drink Bar", description=\
  "Pick from large selection of soft drinks.", price="$2.75", course=\
  "Beverage", restaurant=restaurant1)

session.add(menuItem7)
session.commit()


menuItem8 = MenuItem(user_id=1, name="Desert Bar", description="Pick from \
  large selection of cakes, cookies, and ice cream.", price="$4.75", course=\
  "Dessert", restaurant=restaurant1)

session.add(menuItem8)
session.commit()


# Menu for Auntie Ann's
restaurant1 = Restaurant(user_id=1, name="Auntie Ann\'s Diner' ", address=\
  "8300 Preston Road, Dallas, TX 75225", phone="989-504-6045", cuisine_cat=\
  "American", health_rating= "Fair", picture = '/static/auntannies.jpg')

session.add(restaurant1)
session.commit()

menuItem9 = MenuItem(user_id=1, name="Chicken Fried Steak",
       description="Fresh battered sirloin steak fried and smothered with \
       cream gravy", price="$8.99", course="Entree", restaurant=restaurant1)

session.add(menuItem9)
session.commit()


menuItem1 = MenuItem(user_id=1, name="Boysenberry Sorbet", description="An \
  unsettlingly huge amount of ripe berries turned into frozen (and seedless) \
  awesomeness", price="$2.99", course="Dessert", restaurant=restaurant1)

session.add(menuItem1)
session.commit()

menuItem2 = MenuItem(user_id=1, name="Broiled salmon", description="Salmon \
  fillet marinated with fresh herbs and broiled hot & fast", price="$10.95", \
  course="Entree", restaurant=restaurant1)

session.add(menuItem2)
session.commit()

menuItem3 = MenuItem(user_id=1, name="Morels on toast (seasonal)", \
  description="Wild morel mushrooms fried in butter, served on herbed \
  toast slices", price="$7.50", course="Appetizer", restaurant=restaurant1)

session.add(menuItem3)
session.commit()

menuItem4 = MenuItem(user_id=1, name="Tandoori Chicken", description="Chicken \
  marinated in yoghurt and seasoned with a spicy mix(chilli, tamarind among \
    others) and slow cooked in a cylindrical clay or metal oven which gets \
its heat from burning charcoal.", price="$8.95", course="Entree", \
restaurant=restaurant1)

session.add(menuItem4)
session.commit()

menuItem2 = MenuItem(user_id=1, name="Veggie Burger", description="Juicy \
  grilled veggie patty with tomato mayo and lettuce", price="$9.50", \
  course="Entree", restaurant=restaurant1)

session.add(menuItem2)
session.commit()

menuItem10 = MenuItem(user_id=1, name="Spinach Ice Cream", description=\
  "vanilla ice cream made with organic spinach leaves", price="$1.99", \
  course="Dessert", restaurant=restaurant1)

session.add(menuItem10)
session.commit()


menuItem11 = MenuItem(user_id=1, name="Soft Drink Bar", description=\
  "Variety of cold soft drinks", price="$1.99", course="Beverage", \
  restaurant=restaurant1)

session.add(menuItem11)
session.commit()


# Menu for Cocina Y Amor
restaurant1 = Restaurant(user_id=1, name="Cocina Y Amor ", address=\
  "2401 McKinney Ave, Dallas, TX 75201", phone="981-232-6570", cuisine_cat=\
  "Mexican", health_rating= "Poor", picture= '/static/Mexican.png')

session.add(restaurant1)
session.commit()


menuItem1 = MenuItem(user_id=1, name="Super Burrito Al Pastor",
       description="Marinated Pork, Rice, Beans, Avocado,Cilantro, Salsa, \
       Tortilla", price="$5.95", course="Entree", restaurant=restaurant1)

session.add(menuItem1)
session.commit()

menuItem2 = MenuItem(user_id=1, name="Cachapa", description="Golden brown, \
  corn-based Venezuelan pancake; usually stuffed with queso telita or queso \
  de mano, and possibly lechon. ", price="$7.99", course="Entree", \
  restaurant=restaurant1)

session.add(menuItem2)
session.commit()


menuItem3 = MenuItem(user_id=1, name="Taco Max", description="Big soft taco \
  shell covered with Beef, cheese, and sides. ", price="$7.99", course=\
  "Entree", restaurant=restaurant1)

session.add(menuItem3)
session.commit()


menuItem4 = MenuItem(user_id=1, name="Chips and Salsa", description="Chips \
  and local made salsa. ", price="$3.99", course="Appetizer", restaurant=\
  restaurant1)

session.add(menuItem4)
session.commit()


menuItem5 = MenuItem(user_id=1, name="Fried Ice Cream", description="Balls of \
  Ice Cream battered and fried. ", price="$3.99", course="Dessert", \
  restaurant=restaurant1)

session.add(menuItem5)
session.commit()


menuItem6 = MenuItem(user_id=1, name="Soft Drink Bar", description="Variety of \
  soft drinks ", price="$2.75", course="Beverage", restaurant=restaurant1)

session.add(menuItem6)
session.commit()

restaurant1 = Restaurant(user_id=1, name="Stratos", address="2907 W Northwest \
  Hwy, Dallas, TX", phone="857-234-1270", cuisine_cat="Greek", health_rating= \
  "Good", picture = '/static/stratos.png')
session.add(restaurant1)
session.commit()

menuItem1 = MenuItem(user_id=1, name="Nick's Gyros", description="classic gyro \
  freshly sliced off the rotisserie stuffed in a grilled Pita with homemade \
  Tzatziki sauce, tomatoes and red onions, served with fries", price="$10.95", \
  course="Entree", restaurant=restaurant1)

session.add(menuItem1)
session.commit

menuItem2 = MenuItem(user_id=1, name="Meat lovers Gyro Plate",
       description="Double gyro meat atop a toasted Pita open-face with \
       tomatoes, red onions, homemade Tzatziki sauce, sided with Feta cheese \
       and Kalamata olives.", price="$13.95", course="Entree", \
       restaurant=restaurant1)

session.add(menuItem2)
session.commit()


menuItem3 = MenuItem(user_id=1, name="Rack of Lamb",
       description="Tender Australian lamb chops with oregano and grilled to \
       savory perfection, seved with rice, fresh sauteed garden vegetables \
       with pitta bread.", price="$13.95", course="Entree", \
       restaurant=restaurant1)

session.add(menuItem3)
session.commit()


menuItem4 = MenuItem(user_id=1, name="Stratos",
       description="beer battered and deep fried, sided with marinara and \
       ranch", price="$6.25", course="Appetizer", restaurant=restaurant1)

session.add(menuItem4)
session.commit()

menuItem5 = MenuItem(user_id=1, name="Spanakopita",
       description="Spinach, Feta cheese and onions baked in layers of flaky \
       phyllo", price="$6.50", course="Appetizer", restaurant=restaurant1)

session.add(menuItem5)
session.commit()


menuItem6 = MenuItem(user_id=1, name="Aphrodite's Chocolate Passion", \
  description="a sex bomb of a dessert -Dallas Morning News. A brownie crust \
  filled with chocolate mousse cake with chunks of New York cheesecake and \
  caramel erupting from the center crowned with almond slivers and chocolate \
  curls, sided with a scoop of vanilla ice cream", price="$8.50", course=\
  "Dessert", restaurant=restaurant1)

session.add(menuItem6)
session.commit()


menuItem7 = MenuItem(user_id=1, name="Fried Cheesecake",
       description="New York cheesecake wrapped in flaky phyllo dough sheets \
       and deep fried, rolled in sugar and cinnamo", price="$7.50", course=\
       "Dessert", restaurant=restaurant1)

session.add(menuItem7)
session.commit()


menuItem8 = MenuItem(user_id=1, name="Red & White Wine List",
       description="Large selection of wines for your drinking pleasure", \
       price="$7.50", course="Beverage", restaurant=restaurant1)

session.add(menuItem8)
session.commit()

print "added menu items!"

