from time import sleep
from tld import get_tld
import subprocess, os, requests, psutil, dns.resolver, json, urllib2, requests, uuid, urllib, json
from flask import render_template, flash, redirect, url_for, session
import boto
from boto.s3.connection import S3Connection
from boto.s3.key import Key
from Wappalyzer import Wappalyzer, WebPage
import celery
from bs4 import BeautifulSoup

emails = [[],[]]
breaches = []
f_uuid = ""
taskapp = celery.Celery('app.home.helpers.subdomain', backend='amqp://', broker='amqp://')
API_URL = "https://censys.io/api/v1/search/ipv4"
UID = "CENSYS_UUID"
SECRET = "CENSYS_SECRET"

def dnsrecord(domain, type):
	record=[]
	output = ""
	try:
		answers = dns.resolver.query(domain, type)
		for data in answers:
			record.append(data)
		return record
	except:
		record.insert(0, "No record found")
		return record


@taskapp.task(name='app.home.helpers.subdomain')
def subdomain(domain):
	final_output = '{"result":"true", "Outputs":[]}'
	final_output = json.loads(final_output)
	f_uuid = str(uuid.uuid4())
	run_scan = "ruby /var/www/manual/hostile/sub_brute.rb "+domain+" "+f_uuid
	subprocess.call(run_scan, shell=True)
	subDomains = [[],[]]
	with open("/var/www/manual/hostile/output-"+f_uuid+".txt","r") as ins:
		for line in ins:
			subDomains[0].append(line.split(" ")[0])
			subDomains[1].append(line.split(" ")[1])
	remove_output = "rm /var/www/manual/hostile/output-"+f_uuid+".txt"
	subprocess.call(remove_output, shell=True)
	return subDomains

@taskapp.task(name='app.home.helpers.s3takeover')
def s3takeover(domain_takeover, file_uuid):
	bucket_name = ""
	conn = S3Connection(is_secure=False)
	try:
		bucket_name = domain_takeover
		conn.create_bucket(bucket_name)
		bucketobj = conn.get_bucket(bucket_name)
		file = Key(bucketobj)
		file.key = 'reports-'+file_uuid+'.txt'
		file.set_contents_from_filename('/var/www/reports/sample.txt', policy='public-read')
		for_file = "http://"+domain_takeover
		res = get_tld(for_file)
		f = open('/var/www/reports/report-'+file_uuid+'.md', 'w+')
		reports_template = ""
		reports_template += "#Summary \r\n"
		reports_template += "During the recon process of scanning "+res+" for possible subdomain takeovers, a specific subdomain was identified to be vulnerable for this issue. With this takeover, I am able to publish my own content on behalf of "+res+". Technical description regarding this is below. \r\n"
		reports_template += "\r\n"
		reports_template += "#Description \r\n"
		reports_template += domain_takeover +" was poiniting to AWS s3 bucket. However, this domain has not been claimed in AWS side. Each bucket in AWS acts like a domain. If it was already claimed, it should have either displayed a content or display the message AccessDenied based on the ACL. However, for this domain, it displayed **NoSuchBucket**. This means that "+domain_takeover+" does not exist as an AWS bucket. Because of this, anyone can create a bucket with name "+domain_takeover+" and be able to display their content.\r\n"
		reports_template += "Continuing, I decided to go to my aws console and then create a bucket with this name. Currently, because I do not have any files hosted on it, "+domain_takeover+" now displays AccessDenied.\r\n"
		reports_template += "\r\n"
		reports_template += "#Reproduction \r\n"
		reports_template += "You can see PoC of this takeover at "+for_file+"/reports-"+file_uuid+".txt \r\n"
		reports_template += "#Impact\r\n"
		reports_template += "Depending on how the system is setup, this can be used for more serious attacks. For example if cookies on "+res+" is shared meaning the domain for cookies is: ."+res+", then I can use this domain and make it pull sensitive cookies if they do not have additional protection. In addition, CORS attack is also possible with this because most of the times website tend to allow Origin to be any subdomains of a domain they operate.\r\n"
		reports_template += "\r\n"
		reports_template += "#Fix\r\n"
		reports_template += "If the domain is no longer used, it is best recommended that its DNS record are removed. That way, this takeover will not happen again. In addition, it is also recommended to check other subdomains for possible vulnerabilities similar to this one.\r\n"
		f.write(reports_template)
		f.close()
		return True
	except:
		return False


@taskapp.task(name='app.home.helpers.censysassets')
def censysassets(domain):
    sleep(2)
    payload = json.dumps({'query':'443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names:"%s"' % domain, 'fields':['ip','protocols']})
    try:
    	res = requests.post(API_URL, payload, auth=(UID, SECRET))
    	if res.json()['metadata']['count'] == 0:
        	assets = [[],[]]
        	assets[0].append("No Asset Found")
        	assets[1].append("Null")
    	else:
		assets = [[],[]]
        	for result in res.json()['results']:
            		assets[0].append(result['ip'])
            		ports_data = ""
            		for ports in result['protocols']:
                		ports_data += ports + " "
            		assets[1].append(ports_data)
    	return assets
    except:
	assets = [[],[]]
	assets[0].append("No asset found")
	assets[1].append("Null")
	return assets

@taskapp.task(name='app.users.helpers.corsscan')
def corsscan(subdomains):
	output_result = []
	for subdomain in subdomains[0]:
		target_url = "https://"+subdomain
		cors_headers = {'Origin': 'https://bugbounty.site'}
		try:
			cors_request = requests.get(target_url, headers = cors_headers, timeout = 5.00)
			if cors_request.headers['Access-Control-Allow-Origin'] == "https://bugbounty.site":
				output_result.append(['Vulnerable to CORS'])
			else:
				output_result.append(['Not Vulnerable to CORS'])
		except:
			output_result.append(['Not Vulnerable to CORS'])
	return output_result

#not sure if it should have a s3 bucket scanner because AWS might get mad.
@taskapp.task(name='app.home.helpers.s3bucketscanner')
def s3bucketscanner(domain):
	try:
		buckets = [[],[]]
		domain_tld = get_tld(domain, as_object=True)
		target = domain_tld.domain
		random_uuid = str(uuid.uuid4())
		command = "bash /var/www/manual/s3/brute.sh "+target+" " + random_uuid
		subprocess.call(command, shell=True)
		with open("/var/www/manual/s3/results/results-"+random_uuid+".txt", "r") as ins:
			for datas in ins:
				bucket = datas.strip()
				buckets[0].append(datas.split(" ")[0])
				buckets[1].append(datas.split(" ")[1])
		return buckets
	except:
		buckets = [['No bucket found'],['Null']]
		return buckets

# runs a small python version of wappalyzer to identify some services
@taskapp.task(name='app.home.helpers.services')
def services(subdomain):
	found_services = []
	# celery will feed result from subdomains scan to this.
	for subDomain in subdomain[0]:
		wappalyzer = Wappalyzer.latest()
		try:
			webpage = WebPage.new_from_url('http://'+subDomain)
			found_services.append(list(wappalyzer.analyze(webpage)))
		except:
			error_array = ['No Service Detected - Error']
			found_services.append(error_array)
	return found_services


@taskapp.task(name='app.home.helpers.herokutakeover')
def herokutakeover(domain):
	try:
		herokutakeover = 'heroku domains:add '+urllib.quote(domain)+' --app APP_NAME'
		subprocess.call(herokutakeover, shell=True)
		return True
	except:
		return False


@taskapp.task(name='app.home.helpers.openbbp')
def openbbp(domain):
	headers = {'User-Agent': 'Mozilla/5.0',}
	total_report = [[],[]]
	html = requests.get("https://www.openbugbounty.org/search/?search=."+domain,headers=headers).text
        response = BeautifulSoup(html, 'html.parser')
        try:
            response = response('body')[0]
            tag = response.find_all("h3")
            noReports = tag[0]
            if noReports.next_sibling == '0 vulnerability mirror(s) match your request':
                total_report[0].append("No XSS found")
		total_report[1].append("Null")
            else:
                divs = response.findAll("h3", {"class": "reportertxt"})
                table = response.findAll('table')[2]
                divs = table.find_all('div', {'class': 'cell1'})
                for vuln in divs:
                    vuln = vuln.find_all('a')
                    href = vuln[0]["href"]
                    name = vuln[0].getText()
                    total_report[0].append(name)
		    total_report[1].append('https://www.openbugbounty.org'+href)
            return total_report
        except KeyError:
            total_report[0].append("Error")
	    return total_report

# runs wfuzz to bruteforce directories
@taskapp.task(name='app.home.helpers.dirsearch')
def dirsearch(subdomains):
	total_dir = []
	for subdomain in subdomains[0]:
		try:
			filename = "/var/www/manual/hostile/dir-"+str(uuid.uuid4()) + ".json"
			command2 = "wfuzz -w /var/www/manual/common.txt -o json --sc 200,403 --follow http://"+urllib.quote(subdomain)+"/FUZZ/ >> "+filename
			subprocess.call(command2, shell=True)

			with open(filename, 'r') as f:
				datastore = json.load(f)
			found_dirs = []

			for data in datastore:
				if data['code'] == 200 or data['code'] == 403:
					found_dirs.append(data['location'])
			remove_command = "rm "+filename
			subprocess.call(remove_command, shell=True)
			if len(filter(None, found_dirs)) == 0:
				found_dirs=['None found']
			total_dir.append(found_dirs)
		except:
			found_dirs = ['None found']
			total_dir.append(found_dirs)
	return total_dir


#urlscan api to take image
@taskapp.task(name='app.home.helpers.screenshot')
def screenshot(subdomains):
	images = []
	headers = {'Content-Type': 'application/json', 'API-Key':'URLSCAN_API'}
	url = 'https://urlscan.io/api/v1/scan'
	for subdomain in subdomains[0]:
		subdomain = "https://"+subdomain
		payload = '{"url":"%s"}' %  subdomain
		send_scan = requests.post(url, data=payload, headers=headers)
		result_json = json.loads(send_scan.text)
		image_uuid = result_json['uuid']
		images.append(image_uuid)
		sleep(5.00)
	return images
