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
echo "Now it is time for some custom setups"
echo "Please copy & paste your Censys API ID. You can get this from: https://www.censys.io/account/api"
read censys_app_id
sudo sed  -i -e "s/CENSYS_UUID/$censys_app_id/g" /var/www/ManualScanner/app/home/helpers.py
echo "Thank you. Now please copy paste your API KEY/Secret from the same link"
read censys_secret
sudo sed  -i -e "s/CENSYS_SECRET/$censys_secret/g" /var/www/ManualScanner/app/home/helpers.py
echo "If you have setup your Heroku app to make it able to takeover domains, enter the app name below"
read heroku_app_name
sudo sed  -i -e "s/APP_NAME/$heroku_app_name/g" /var/www/ManualScanner/app/home/helpers.py
echo "This app allows you take screenshot of each retrieved subdomains. However, to prevent massive server usage it uses URLScan.io. If you already requested an API key from them and have received one, paste it below"
read urlscan_api_key
sudo sed -i -e "s/URLSCAN_API/$urlscan_api_key/g" /var/www/ManualScanner/app/home/helpers.py
