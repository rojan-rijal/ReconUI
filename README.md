# ReconUI
Alpha version code of ReconUI


# Installation
**Automated Setups**
*Before running this check the custom/required setup section below*
1. To setup basically everything, simply run installer.sh as sudo. 

**Custom/Required Setup**

There are some setups that you need to do manually.

*Heroku*

1. Install and setup Heroku CLI: https://devcenter.heroku.com/articles/heroku-cli
2. Make sure you have a valid Heroku account when you set this up. In Heroku to add custom domains, you need a credit/debit card in your account. 
3. Create an app that will be used for takeovers. Heroku allows adding multiple custom domains so one app is suffice. Once you add the app, make sure it has some code. 
4. Easiest way to deploy the app is through Dropbox. Simply link your dropbox, upload your code and make sure your Heroku app has the buildback ready. For PHP, simply create a index.php (or any php file name) and also a composer.json file (this can be empty like this `{}`). Then put that in dropbox and added a PHP buildback and deploy it. 

*AWS*

1. Make sure you have a valid AWS account. Once that is there, use AWS CLI to configure your account. 
2. To configure simply do `aws configure` and paste in your keys as requested. 

*URLScan.io API* 

For the screenshot feature, instead of using custom code and manually taking picture, the tool will send an external request to generate a private report in URLScan. To do so you need an API key. For that you will have to email the URLScan.io personnels. 

*Censys*
Make sure you signup on Censys to get the API Key Id and Secret. 

# Current Features
1. Subdomain bruteforcing
2. Directory bruteforce for each subdomains. 
3. Basic CORS vulnerability check. 
4. Auto subdomain takeover for AWS S3 Bucket and Heroku
5. Censys IPv4 lookups. 
6. Public XSS search from open bug bounty. 
7. Screenshot grab of each subdomains. 

# Videos:
1. Showcasing the tool: https://www.youtube.com/watch?v=4XGsRhZ70BQ
2. Installer script: https://www.youtube.com/watch?v=gUFlj-JHpbc


# Error debugging
If one or more of the services do not work and you keep getting 500 Internal server error: 
1. Make sure the API keys are valid. 
2. Make sure that you have OpenSSL installed. If OpenSSL and its dependencies are not installed, a SSL Handshake Failure will likely happen when connecting to external site. 
