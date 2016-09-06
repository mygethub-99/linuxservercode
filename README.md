# FSND Linux Server

This FSND project requires the configuration of a Linux server VM that will be used to host a catalog application. The catalog web project that is hosted on this server project is a web site that highlights a few of the Dallas Texas area restaurants.
The host server is reachable at http://ec2-52-41-58-45.us-west-2.compute.amazonaws.com
****
#Main Project Milestones

* Server Access

* Server Security

* Server Applications

* Server Configuration
****
#Server Access

IP address: 52.41.58.46

SSH Incoming PORT: 2200

TCP Incoming port 80 opened

UDP Incoming port 123

Web Application URL: http://52.41.58.45

AWS-Server:http://ec2-52-41-58-45.us-west-2.compute.amazonaws.com
Server access has been setup for user grader with sudo access

ssh -i ~/.ssh/linuxNew -p 2200 grader@52.41.58.45

--password phrase is: grader12

****

#Server Security

* Server firewall has been activated

* Port 2200 has been opened for ssh access

* ssh keys have been installed for user "grader"

****

#Server Applications

Server time has been set to UTC

Installed Applications

* Apache2

* Python-setuptools

* libapache2-mod-wsgi

* Git Application

* libapache2-mod-wsgi python-dev

* python-pip

* virtualenv

* Flask

* httplib2

* requests

* flask-seasurf

* oauth2client

* python-psycopg2

* sqlalchemy

* flask_excel

* postgesql

* postgresql-contrib
****
# Server Configuration

* [.bash_log] (https://github.com/mygethub-99/linuxservercode/blob/master/.bash_log)
* Setup ~/.ssh folder on local machine with udacity-key.rsa with read-write access level
* Utilized ssh protocal to login into server, setup new user called grader and a user called builder with sudo rights
* Setup ssh port to use port 2200
* Created new key pairs for user builder and grader using ssh_keygen, setting correct access rights for new keys (644)
* Configured /sshd_config file, changing PasswordAuthentication yes to no for each new user
* Configured /etc/hosts file with hostname ip address
* Configured firewall and enabled firewall
* Setup server on UTC time. [Ubuntu doc] (https://help.ubuntu.com/community/UbuntuTime#Using_the_Command_Line_.28terminal.29)
* Installed Configured Apache to serve Python mod_wsgi application. See Server Application section for list of applications loaded.
* Created /var/www/Catalog & var/www/Catalog/catalog & static & templates directories to place web application files in.
* Installed and enabled a virtual environment(virtualenv)
  * [How to deploy Flask and virtual environment] (https://www.digitalocean.com/community/tutorials/how-to-deploy-a-flask-application-on-an-ubuntu-vps)
* Configured the virtual host by creating and configuring catalog.conf file.
* Created the catalog.wsgi file with needed web application code.
* Added a git repository called gitrepo under the /catalog/gitrepo directory to push/pull the linux server web application.
  * [git-explained] (http://juristr.com/blog/2013/04/git-explained/)
* Added FSND Calalog project by using git to pull the repository from github.com
* Setup .htaccess to limit repository access. [How to setup mod_rewrite for Apache Ubuntu 14.04] (https://www.digitalocean.com/community/tutorials/how-to-set-up-mod_rewrite-for-apache-on-ubuntu-14-04)
* Setup PostgreSQL. [Link to help] (https://www.digitalocean.com/community/tutorials/how-to-secure-postgresql-on-an-ubuntu-vps)
* Created a Postgres user called catalog 
* Corrected the G and FB Oauth-logins by correction the directory link to the client_secret.json files.
* Added Amazon host server link to the FB and G developers console credentials.

****

#Database Setup

The catalog database has been setup to use Postgresql

Access and ownership of the catalog database has been given to user "catalog"

* catalog db password is "mydata"

The catalog db tables have been setup by [Link to db setup] (https://github.com/mygethub-99/linuxservercode/blob/master/feb32015db.py)

Catalog db has been populated using [Link to db setup] (https://github.com/mygethub-99/linuxservercode/blob/master/dbpopfeb3.py)













