# Splunk: Website Defacement CTF

<h2>Description</h2>
In this SIEM task, I use Splunk to investigate a website defacement for imnotreallybatman.com. 

<h2>Languages and Utilities Used</h2>

- <b>linux CLI</b>

<h2>Environments Used </h2>

- <b>Splunk</b>
- <b>Unbuntu</b> 

<br />
<br />
In Splunk, go to settings>forwarding and receiving. 

![1) selecting v1](https://github.com/user-attachments/assets/4d849016-70eb-4c13-8e74-2a0ccdb1a483)

<br />
<br />
Enter the port for reciving logs, default 9997.

![2) website defacement](https://github.com/user-attachments/assets/188c97dc-7d88-4bf3-8d08-12045b7c93c5)

<br />
<br />  
On my windows vm install the windows 64bit splunk forwarder.

![3) challenge prompt](https://github.com/user-attachments/assets/ca8fe5d5-cd93-480f-9e1b-d8be82784944)

<br />
<br />
Created an outbound and inboudn firewall rule to allow for tcp port 8089, and 9997 called Splunk Forwarder.

![4) filtering count per index to show botsv1](https://github.com/user-attachments/assets/daf9a36d-b0c9-4440-8dea-15377489f322)

<br />
<br />
Running and installing the Splunk Forwarder setting default ports of 8089 and 9997. 

![5) website defacement filter for sourcetypes](https://github.com/user-attachments/assets/fd6995b0-7093-47c0-b134-6311c55798e4)

<br />
<br />
Confirmed that the windows vm is connected with 2 sources, windows security and system logs. 

![6) q1 ipv4 of attacker scan index, domain, src shows 1 ip addr](https://github.com/user-attachments/assets/317c318c-fbdd-45e7-9e41-66fc44c4c03d)

<br />
<br />  
Searching for all indexes with and event code of 4624 plls up 59 windows events. 

![7) q2 acunetix ](https://github.com/user-attachments/assets/6a205d48-6e1f-47b5-a373-7810d9b66544)

<br />
<br />  
Searching for event code 1102 under windwos security logs and saving it as an alert will trigger an alert for cleared security logs. 

![8) q3 content mangement system ](https://github.com/user-attachments/assets/d057a476-6cec-4f6a-959e-9ae22743e376)

<br />
<br />
Clearing the windows vm security logs through the command line "wevtutil cl Security".

![9) q8 brute force attack](https://github.com/user-attachments/assets/0408d464-d4e2-42fa-8b9d-fb74b1203c65)

<br />
<br />  
In Activity>triggered alerts> an alert was generated. 

![10) q9 ](https://github.com/user-attachments/assets/11393ab9-ce93-4403-8b49-8de89c5d5ebb)

<br />
<br />  
In Splunk, go to settings>forwarding and receiving. 

![11) q4](https://github.com/user-attachments/assets/445ea7ab-01a6-4122-935a-7ee77c978c5a)

<br />
<br />
Enter the port for reciving logs, default 9997.

![12) Q5](https://github.com/user-attachments/assets/4233f461-3380-41c5-a187-9b1912e1a571)

<br />
<br />  
On my windows vm install the windows 64bit splunk forwarder.

![13) Q6 typosquatting](https://github.com/user-attachments/assets/e3d8bcc8-86ef-4ba0-9007-26f4a1a0fde0)

<br />
<br />
Created an outbound and inboudn firewall rule to allow for tcp port 8089, and 9997 called Splunk Forwarder.

![13) Q14 1st password used](https://github.com/user-attachments/assets/90ea793a-e159-46ea-9c10-4bc80d9ef67c)

<br />
<br />
Running and installing the Splunk Forwarder setting default ports of 8089 and 9997. 

![13) Q15](https://github.com/user-attachments/assets/ccee99ee-a5af-42f3-a88a-b567e6b9ba1f)

<br />
<br />
Confirmed that the windows vm is connected with 2 sources, windows security and system logs. 

![14) Q16](https://github.com/user-attachments/assets/227a5533-21d6-4d90-95f6-fc17a840e7d3)

<br />
<br />  
Searching for all indexes with and event code of 4624 plls up 59 windows events. 

![15) Q17](https://github.com/user-attachments/assets/7beb39b5-1148-47be-b951-6cad943cd2fa)

<br />
<br />  
Searching for event code 1102 under windwos security logs and saving it as an alert will trigger an alert for cleared security logs. 

![16) Q18](https://github.com/user-attachments/assets/5f17a841-2228-43ba-a158-3016899f1d61)

<br />
<br />
Clearing the windows vm security logs through the command line "wevtutil cl Security".

![17) Q19](https://github.com/user-attachments/assets/192aeb57-5371-4f33-a8a8-640cab9af5f0)

<br />
<br />  
