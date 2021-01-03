with open('/home/kali/OSCP_Prep/wordlists/oracle_default_userpass.txt', 'r') as f:
    for i in f:
        s=i.replace(' ', '/')
        with open('credential_oracle.txt', 'a') as f:
            f.write(s)
