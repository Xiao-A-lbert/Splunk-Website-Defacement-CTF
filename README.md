# Splunk: Website Defacement CTF

<h2>Description</h2>
In this SIEM task, I use Splunk to investigate a website defacement for imnotreallybatman.com. 

<h2>Languages and Utilities Used</h2>

- n/a

<h2>Environments Used </h2>

- <b>Splunk</b> 

<br />
<br />
Splunk Boss of the SOC challenge.

![1) selecting v1](https://github.com/user-attachments/assets/4d849016-70eb-4c13-8e74-2a0ccdb1a483)

<br />
<br />
Selecting website defacement ctf. 

![2) website defacement](https://github.com/user-attachments/assets/188c97dc-7d88-4bf3-8d08-12045b7c93c5)

<br />
<br />  
Challenge prompt.

![3) challenge prompt](https://github.com/user-attachments/assets/ca8fe5d5-cd93-480f-9e1b-d8be82784944)

<br />
<br />
| eventcount summarize=false index=* to list all available indexes with events showing botsv1 as the index of interested.  

![4) filtering count per index to show botsv1](https://github.com/user-attachments/assets/daf9a36d-b0c9-4440-8dea-15377489f322)

<br />
<br />
| metadata type=sourcetypes | fields sourcetype enumerates the different fields within the index. An interesting field is the fgt_utm firewall log.

![5) website defacement filter for sourcetypes](https://github.com/user-attachments/assets/fd6995b0-7093-47c0-b134-6311c55798e4)

<br />
<br />
Scanning website means attacker is mainly using network tools (suricata, firewall, http logs). index-botsv1 "imreallynotbatman.com" sourcetype=fgt* : shows srcip and actions if things were blocked or allowed, and url page being accessed through the firewall. Looks at top values for srcip (40.80.148.42). Actions field, investigate some blocked packets. actions="blocked" only showing 40.80.148.12 only being blocked. The attack field shows blocked due to acunetix.web.vulnerability.scanner. ( probably attacker scanning the website). Google attackid: 39769. Investigation shows attacker ip: 40.80.148.42 and victim ip as 192.168.250.70 Using sourcetype=suricata > alert.signature field> XSS CVE numbers, srcipt.

![6) q1 ipv4 of attacker scan index, domain, src shows 1 ip addr](https://github.com/user-attachments/assets/317c318c-fbdd-45e7-9e41-66fc44c4c03d)

<br />
<br />  
We know that ip 40.80.148.42 was correlated with using XSS through suricata and is related to acunetix vulnerability scanner.

![7) q2 acunetix ](https://github.com/user-attachments/assets/6a205d48-6e1f-47b5-a373-7810d9b66544)

<br />
<br />  
Index, notbatman, sourcetype=fgt* > look at vendor_url > shows a lot of /joomla.
    Change sourcetype=stream:http > uri & uri path> more references to joomla.
    
    
![8) q3 content mangement system ](https://github.com/user-attachments/assets/d057a476-6cec-4f6a-959e-9ae22743e376)

<br />
<br />
Index, not batman, sourcetype=fgt* | stats count by srcip to show 2 results interacting with the domain's firewall.
    Searching for "23.22.63.114" and changing sourcetype=* > uri shows /joomla/administrator/index.php adding to search.
    Form data shows username and passwords (100+) within the post data.
    | stats count by form_data shows a clear brute force attack.
    
![9) q8 brute force attack](https://github.com/user-attachments/assets/0408d464-d4e2-42fa-8b9d-fb74b1203c65)

<br />
<br />  
Index, all sourcetype, notbatman domain, AND "*.exe" shows 86 events.
    Logs show a filename = 3791.exe.
    Adding http+method=POST shows 7 events> filename shows 2 results > add 3791.exe to search.
    Opening up the log shows a suricata alert from the attacker ip 40.80.148.42.
    Running index, notbatman, sourcetype=* "3791.exe" > fgt_utm sourcetype log>.
    Log file fomr fgt_utm shows critical severity, dtype virus, msg: file is infected, filehash VT scan shows 66.
    
![10) q9 ](https://github.com/user-attachments/assets/11393ab9-ce93-4403-8b49-8de89c5d5ebb)

<br />
<br />  
It's either a post request or get request. index, all sourcetype, dest_ip="192.168.250.70" AND src_ip="40.80.148.42" OR src_ip="23.22.63.114" since we know the 40 ip is for scanning and 23 ip is brute force.
    Adding http_method=GET to narrow results.
    Adding Event_type shows 1 result for fileinfo from suricata.
    Examining the one event for fileinfo shows a get request from 23.22.63.114:1337 to dest 192.168.250.70:51573.
    
![11) q4](https://github.com/user-attachments/assets/445ea7ab-01a6-4122-935a-7ee77c978c5a)

<br />
<br />
From q4 http.hostname shows prankglassinebracket.jumpingcrab.com,
    cisco talos shows it as a malware site and untrusted,
    googling "jumpingcrab.com" shows open threat exchange verdict as dynamic dns service.
    
![12) Q5](https://github.com/user-attachments/assets/4233f461-3380-41c5-a187-9b1912e1a571)

<br />
<br />  
Malicious ips already identified: 40.80 malicious scanning and 23.22 brute force and uploaded 3791.exe. Using open threat exchange again to search in the malicious ips shows 23.22 with passive DNS typesquatting domain names to mimic waynecorpinc.com

![13) Q6 typosquatting](https://github.com/user-attachments/assets/e3d8bcc8-86ef-4ba0-9007-26f4a1a0fde0)

<br />
<br />
Index="botsv1" imreallynotbatman.com sourcetype=* uri_path="/joomla/administrator/index.php" form_data="*&passwd*"
| rex field=form_data "passwd=(?<Password>\w+)" to extract passwords into their own column.

![13) Q14 1st password used](https://github.com/user-attachments/assets/90ea793a-e159-46ea-9c10-4bc80d9ef67c)

<br />
<br />
index="botsv1" imreallynotbatman.com sourcetype=* uri_path="/joomla/administrator/index.php" form_data="*&passwd*"
| rex field=form_data "passwd=(?<Password>\w+)"
| rex field=form_data "username=(?<Username>\w+)"
| eval Length=len(Password)
| search Length=6
| table _time, Username, Password, Length

Added eval to count the length of each password

![13) Q15](https://github.com/user-attachments/assets/ccee99ee-a5af-42f3-a88a-b567e6b9ba1f)

<br />
<br />
going back to
index="botsv1" imreallynotbatman.com sourcetype=* uri_path="/joomla/administrator/index.php" form_data="*&passwd*"
| rex field=form_data "passwd=(?<Password>\w+)"
| rex field=form_data "username=(?<Username>\w+)"
| table _time, Username, Password

and putting the time into the most recent will show the latest password used.

![14) Q16](https://github.com/user-attachments/assets/227a5533-21d6-4d90-95f6-fc17a840e7d3)

<br />
<br />  
index="botsv1" imreallynotbatman.com sourcetype=* uri_path="/joomla/administrator/index.php" form_data="*&passwd*"
| rex field=form_data "passwd=(?<Password>\w+)"
| rex field=form_data "username=(?<Username>\w+)"
| eval Length=len(Password)
| table _time, Username, Password, Length
| stats avg(Length)

piping length to average will show average length
c
![15) Q17](https://github.com/user-attachments/assets/7beb39b5-1148-47be-b951-6cad943cd2fa)

<br />
<br />  
index="botsv1" imreallynotbatman.com sourcetype=* uri_path="/joomla/administrator/index.php" form_data="*&passwd*"
| rex field=form_data "passwd=(?<Password>\w+)"
| rex field=form_data "username=(?<Username>\w+)"
| eval Length=len(Password)
| search Password="batman"
| table _time, Username, Password, Length
| transaction Password

transaction shows the duration ebtween the two batman password uses

![16) Q18](https://github.com/user-attachments/assets/5f17a841-2228-43ba-a158-3016899f1d61)

<br />
<br />
index="botsv1" imreallynotbatman.com sourcetype=* uri_path="/joomla/administrator/index.php" form_data="*&passwd*"
| rex field=form_data "passwd=(?<Password>\w+)"
| rex field=form_data "username=(?<Username>\w+)"
| table _time, Username, Password
| dedup Password
| stats count by Password
| stats sum(count) as count

to show 412 unique passwords

![17) Q19](https://github.com/user-attachments/assets/192aeb57-5371-4f33-a8a8-640cab9af5f0)

<br />
<br />  
