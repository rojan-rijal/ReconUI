echo "Starting installation. Please hold on. This will take time"
echo "Starting with good old system update"
sudo apt-get -y update
echo "Install pip"
sudo apt-get install -y python-pip ruby apache2 python-dev supervisor libapache2-mod-wsgi curl rabbitmq-server libcurl4-openssl-dev libssl-dev
sudo apt-get update
sudo pip install --upgrade pip
echo "Time to install pip modules"
sudo pip install psutil validators dnspython bs4 boto flask flask-wtf flask-bootstrap Celery tld python-Wappalyzer wfuzz
sudo a2enmod wsgi
sudo a2dissite 000-default.conf
sudo cp www/App.conf /etc/apache2/sites-available/App.conf
sudo a2ensite App.conf
sudo rm www/App.conf
sudo rm www.zip
zip -r www.zip www
sudo rm -r /var/www
sudo mv www.zip /var/www.zip
sudo unzip /var/www.zip -d /var
private_key=$(uuidgen)
sudo sed  -i -e "s/PRIVATE_KEY/$private_key/g" /var/www/ManualScanner/app/home/views.py
echo "Your private key is $private_key make sure to save it because you will need this to run the scan."
