# ADVenturer

```
  ___ ______ _   _            _                       
 / _ \|  _  \ | | |          | |                      
/ /_\ \ | | | | | | ___ _ __ | |_ _   _ _ __ ___ _ __ 
|  _  | | | | | | |/ _ \ '_ \| __| | | | '__/ _ \ '__|
| | | | |/ /\ \_/ /  __/ | | | |_| |_| | | |  __/ |   
\_| |_/___/  \___/ \___|_| |_|\__|\__,_|_|  \___|_|   
                                                      
```                                                 

ADVenturer is a tool focused on automating enumeration for lateral movement vectors in an Active Directory domain. It can be ran as any user but naturally will provide most value once you have escalated privileges to a local Administrator. 

👁ADVenturer will perform enumeration via: <br>
  o Extracting hashes/passwords from SAM, SECURITY, & SYSTEM registry keys <br>
  o Identify all user's powershell logging locations and search for key words <br>
  o Identify all non-standard user directories <br>
  o Identify all text files in any user-owned directories <br>
  o Identify other user sessions for Mimikatz Pass the Ticket (PtT) attack <br>
  o Additional features TBD <br>

🐱‍💻Usage and Setup Instructions: <br>
  o Clone this repository: <br>
    `git clone https://` <br>

  o Run as python script: <br> 
    `python3 adventurer.py`

⚠️ Disclaimer: This project is for educational purposes only. It is designed to help individuals in educational penetration testing situations (ie: HackTheBox), and it is not intended for real-life use...
