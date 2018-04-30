# ZzufでFuzzing

## 1.複数のバージョンのApacheを一気に建てる
```bash
root@ubuntu:~$ for i in {0..34}; do wget http://archive.apache.org/dist/httpd/httpd-2.2.${i}.tar.gz;tar xf httpd-2.2.${i}.tar.gz; pushd httpd-2.2.${i}; ./configure --prefix=/opt/httpd/2.2.${i};make;make install;sed -i "s/Listen 80/Listen $((2000+${i}))/" /opt/httpd/2.2.${i}/conf/httpd.conf; echo "TraceEnable Off" >> /opt/httpd/2.2.${i}/conf/httpd.conf; /opt/httpd/2.2.${i}/bin/apachectl start; popd; done
```

```
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0000040s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 986 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
2000/tcp open  http    Apache httpd 2.2.0 ((Unix))
2002/tcp open  http    Apache httpd 2.2.2 ((Unix))
2003/tcp open  http    Apache httpd 2.2.3 ((Unix))
2004/tcp open  http    Apache httpd 2.2.4 ((Unix))
2006/tcp open  http    Apache httpd 2.2.6 ((Unix))
2008/tcp open  http    Apache httpd 2.2.8 ((Unix))
2009/tcp open  http    Apache httpd 2.2.9 ((Unix))
2010/tcp open  http    Apache httpd 2.2.10 ((Unix))
2013/tcp open  http    Apache httpd 2.2.13 ((Unix))
2020/tcp open  http    Apache httpd 2.2.20 ((Unix))
2021/tcp open  http    Apache httpd 2.2.21 ((Unix))
2022/tcp open  http    Apache httpd 2.2.22 ((Unix))
2034/tcp open  http    Apache httpd 2.2.34 ((Unix))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.11 seconds
```


## 2.WikipediaのHTTPheaderからHTTPヘッダーのリストをコピペして、貼り付ける
```bash
root@ubuntu:~$ cat << EOF > wiki-http-headers
```

## 3.要らない解説とかを消す
```bash
root@ubuntu:~$ cat wiki-http-headers | cut -f3 | grep ":" | sed "s#Example....##g" | sort -u
```
## 4.ヘッダー一覧から、実際に動くHTTPリクエストを組み立てる
```bash
root@ubuntu:~$ a=0 && IFS=$'\n' && for header in $(cat wiki-http-headers | cut -f3 | grep ":" | sort -u); do echo -e "GET / HTTP/1.0\r\n$header\r\n\r\n" > "testcase$a.req";a=$(($a+1)); done && unset IFS
```
## 5.生成したリクエストをランダムに変化させる
```bash
root@ubuntu:~$ for i in {0..89}; do for f in testcase.*; do zzuf -r 0.01 -s $i < "$f" > "$i-$f"; done; done
```
## 6.[1.]で構築したApacheに対して、ランダムに変化させたHTTPリクエストをNcatで送信する。
```bash
root@ubuntu:~$ for v in {0..89}; do for p in {2000,2002,2003,2004,2006,2008,2009,2010,2013,2020,2021,2022,2034};do nc -nv 192.168.204.80 ${p} < ${v}-testcase${v}.req; done; done  > `date +%Y%m%d%H%M%S.log` | less
```