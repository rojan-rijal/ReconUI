#!/usr/bin/expect -f
set domain [lindex $argv 0]
spawn ruby /var/www/manual/hostile/sub_brute.rb
expect "domain"
sleep 1
send "$domain\r"
interact
