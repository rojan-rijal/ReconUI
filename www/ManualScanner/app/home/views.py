import threading, urllib, uuid, json, validators
from tld import get_tld
from time import sleep
from flask import render_template, flash, redirect, url_for, session, send_file
from helpers import dnsrecord, subdomain, s3takeover, censysassets, herokutakeover, s3bucketscanner, openbbp, dirsearch, services, corsscan
from forms import ManualForm
from celery.result import AsyncResult
from . import home
import celery.states


@home.route('/')
def homepage():
    """
    Render the homepage template on the / route
    """
    test_array = ['hi','ok']
    return render_template('home/index.html', test_array=test_array)
	
@home.route('/scanner', methods=['GET', 'POST'])
def manual_recon():
    """
    Manual recon Hack All the things
    """
    session["user_uuid"] = str(uuid.uuid4())
    dnsdata = []
    form = ManualForm()
    user_uuid = session["user_uuid"]
    if form.validate_on_submit():
    	check_tld = get_tld(form.url.data, as_object=True)
    	if "gov" in check_tld.suffix:
		flash(".gov domains are not allowed")
		return render_template('home/manual/manual.html', form = form, title="Manual Scanning")
	else:
		if form.beta_key.data == '398311c2-c521-42fa-9be7-6923cbe30028':
			domain = form.url.data
			domain_target_tld = get_tld(domain, as_object=True)
			domain_target = domain_target_tld.domain + "." + domain_target_tld.suffix
        		a = dnsrecord(domain_target, 'A')
			ns = dnsrecord(domain_target, 'NS')
			mx = dnsrecord(domain_target, 'MX')
			subdomains = subdomain.apply_async(args=[urllib.quote(domain_target),], link=[services.s(),corsscan.s(),dirsearch.s()])
			assets = censysassets.delay(urllib.quote(domain_target))
			public_xss = openbbp.delay(urllib.quote(domain_target))
			#s3buckets = s3bucketscanner.delay(domain)
			company = form.company.data
			if not subdomains.ready() or not assets.ready() or not s3buckets.ready() or not public_xss.ready():
				return render_template('home/manual/scanning.html', domain = urllib.quote(domain_target),
							subdomains = subdomains, a=a, ns=ns, mx=mx, uuid=user_uuid, assets = assets, public_xss = public_xss)
			return render_template('home/manual/scanning.html', length = length, 
						subdomains=subdomains, a = a, ns = ns,
						mx = mx, domain = domain_target, uuid=user_uuid)
		else:
			flash('Sorry, the key you added was invalid')
			return render_template('home/manual/manual.html',
					       form = form, title="Manual Scanning")
    return render_template('home/manual/manual.html',
                           form=form, uuid=user_uuid,
			   title="Manual Scanning")




@home.route('/api/task/<string:id>', methods=['GET'])
def check_task(id):
   res = subdomain.AsyncResult(id)
   if res.ready():
	output = "true"
	static_domain = '{"result":"true","results":[],"subtasks":[], "stats":[]}'
        load_static = json.loads(static_domain)
	for domain in res.result[0]:
		load_static['results'].append(domain)
	for stats in res.result[1]:
		load_static['stats'].append(stats)
	try:
		if len(res.children[0]) > 0:
			for children in res.children[0]:
				load_static['subtasks'].append(children.id)
		datas = ""
		datas = json.dumps(load_static)
		return datas
	except:
		datas = ""
		datas = json.dumps(load_static)
		return datas
   else: 
	static_domain = '{"result":"false","domains":[],"stats":[]}'
	return static_domain



@home.route('/api/subtask/<string:id>', methods=['GET'])
def subdtask_task(id):
   res = subdomain.AsyncResult(id)
   if res.ready():
        output = "true"
        static_domain = '{"result":"true","results":[],"subtasks":[]}'
        load_static = json.loads(static_domain)
	for domain in res.result:
		load_static['results'].append(domain)
	datas = ""
	datas = json.dumps(load_static)
	return datas
   else:
	static_domain = '{"result":"false","domains":[],"stats":[]}'
        return static_domain


@home.route('/takeover/<string:domain>/<string:temp_id>', methods=['GET'])
def takeover_domain(domain, temp_id):
	try:
		if temp_id == session["user_uuid"]:
			bool_value = s3takeover.delay(domain, temp_id)
			bool_value.wait()
			file = "report-"+temp_id+".md"
			flash(domain)
			return render_template('home/takeover.html', bool_value=bool_value, file=file, domain=domain, temp_id=temp_id)
		else:
			flash(domain)
			return render_template('error.html', domain=domain)
	except:
		return redirect(url_for('home.manual_recon'))


@home.route('/htakeover/<string:domain>/<string:temp_id>', methods=['GET'])
def htakeover(domain, temp_id):
	try:
		if temp_id == session["user_uuid"]:
			if not validators.url("http://"+domain):
				return render_template('error.html')
			else:
				h_value = herokutakeover.delay(domain)
				h_value.wait()
				return render_template('home/htakeover.html', bool_value = h_value, domain = domain)
		else:
			return render_template('error.html')
	except:
		return redirect(url_for('home.manual_recon'))



@home.route('/download/<string:filename>', methods=['GET'])
def download_report(filename):
   try:
	fileLoc = '/var/www/reports/'+filename
   	return send_file(fileLoc, attachment_filename=filename)
   except:
   	return render_template('error.html')

@home.route('/github/', methods=['GET'])
def github_search():
	return render_template('home/github.html')
