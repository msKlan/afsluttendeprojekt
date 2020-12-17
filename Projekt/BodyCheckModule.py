import sys
import pandas as pd
import whois #maybe pip installed? in which case: pythonwhois
w = whois.whois("pythonforbeginners.com")
import socket, ssl
import OpenSSL
import re
import urllib
import requests
from datetime import date, datetime
from googlesearch import search #pip installed
from bs4 import BeautifulSoup, SoupStrainer #pip installed
import bs4
# from urllib2 import

realURL = "dr.dk"
fakeURL = "https://www.fakewebsite.org/should_not_be_suspicious"
fakePhishing = "http://www.gimmeyourinfo.ru.dk.com/@/add_something_suspicious//as_i_go_along.dk"


def CheckURLforPhishing(p_url):
    # test_url=p_url
    today = date.today()
    url = p_url.lower()
    


    #url = fakePhishing
    res = [0]*31

# having_IP_Address  { -1,1 }
    #fjern https, http, etc og www og check om det indeholder tal med punktummer
    res[0] = 1
# URL_Length   { 1,0,-1 }
    if (len(url)<54):
        res[1] = -1
    elif (len(url)>54 and len(url)<75):
        res[1] = 0
    else: 
        res[1] = 1
# Shortining_Service { 1,-1 }
    if (url.count("bitly" or "tinyurl" or "ow.ly" or "rebrandly" or "t2m" or "clickmeter")>0):
        res[2] = 1
    else:
        res[2] = 0
# having_At_Symbol   { 1,-1 }
    if (url.count("@") > 0):
        res[3] = 1
    else:
        res[3] = 0
# double_slash_redirecting { -1,1 }
    doubleslash = url
    doubleslash.replace("https://", "")
    doubleslash.replace("http://", "")
    if (doubleslash.count("//")>0):
        res[4] = 1
    else:
        res[4] = 0
# Prefix_Suffix  { -1,1 }
    if (url.count("-") > 0):
          res[5] = 1
    else:

        res[5] = 0
# having_Sub_Domain  { -1,0,1 }
    if (url.count(".") >= 1):
        res[6] = -1
    elif (url.count(".") == 2):
        res[6] = 0
    else: 
        res[6] = 1
# SSLfinal_State  { -1,1,0 }
        res[7] = 0
# Domain_registeration_length { -1,1 }
    # print(w.updated_date[0].strftime("%Y-%m-%d"))
  #  print(w.updated_date[0])
    # print("crackhead")
    # print(today.strftime("%Y-%m-%d"))
    # print((w.updated_date[0] - w.creation_date[0]).days)
    
    #registrar, updated_url, creation_date, expiration_date, name servers
    res[8] = 0
# Favicon { 1,-1 }
    f1 = '<html><head><link rel="shortcut icon" href="https://xx.dk/favicon.ico" /></head><body>Test</body></html>'
    f2 = '<link rel="shortcut icon" href="favicon.ico" /><link rel="stylesheet" href="x.css" />'
    f3 = '<link rel="shortcut icon" href="./favicon.ico" />'
    f3 = '<link rel="shortcut icon" href="./img/favicon.ico" />'

    soup = BeautifulSoup(f1, 'html.parser')
    # soup = BeautifulSoup(f2, 'html.parser')
    # soup = BeautifulSoup(f3, 'html.parser')
    # soup = BeautifulSoup(f4, 'html.parser')
    host = "xx1.dk"
    faviconreturn = 0
    
    for a in soup.find_all('link', href=True):
        if ("favicon" in str(a)):
            first_split = a['href'].split("//")
            # print(1, first_split)
            faviconreturn = 1
            if ("http" in first_split[0]):
                # print(2, 'has http', first_split[1])
                second_split = first_split[1].split("/")
                # print("3 host=", second_split[0])
                faviconreturn = 0
                if (host == second_split[0]):
                    # print(4, "local on host", -1)
                    faviconreturn = -1
                else:
                    # print(5, "external host", 1, ("gottem"))
                    faviconreturn = 1
            elif (first_split[0][0] == "."):
                # print(6, "local on host", -1)
                faviconreturn = -1
            else:
                # print(7, "local on host", -1)
                faviconreturn = -1
    res[9] = faviconreturn
# port { 1,-1 }
    res[10] = 0
# HTTPS_token { -1,1 }
    nohttpstoken = url.split("//", 1)[1]
    if (nohttpstoken.count("https")>0):
        res[11] = 1
    else:
        res[11] = 0
# Request_URL  { 1,-1 }
    r_url = "http://stackoverflow.com/"
    # r_url = "https://dr.dk/"

    page = requests.get(r_url)
    data = page.text
    soup = BeautifulSoup(data, features="lxml")

    successrate = 0
    j = 0
    domain = 'cdn.sstatic.net'
    print("https://" + domain)
    for img in soup.find_all('img', src=True):
        print(img["src"], "https://" + domain in img['src'])
        if ("https://" + domain in img['src'] or "http://" + domain in img['src']):
            successrate += 1
            # print(successrate)
        j += 1
    for audio in soup.find_all('audio', src=True):
        print(img["src"], "https://" + domain in img['src'])
        if ("https://" + domain in audio['src'] or "http://" + domain in audio['src']):
            successrate += 1
            # print(successrate)
        j += 1
    for embed in soup.find_all('embed', src=True):
        print(img["src"], "https://" + domain in img['src'])
        if ("https://" + domain in embed['src'] or "http://" + domain in embed['src']):
            successrate += 1
            # print(successrate)
        j += 1
    
    print(successrate)
    print(j)
    
    
    
    try:
        percentage = successrate / float(j) * 100
        print(percentage)
    except:
        return 1

    if percentage < 22.0:
        res[12] = 1
    elif 22.0 <= percentage < 61.0:
        res[12] = 0
    else:
        res[12] = -1
    print(res[12])
# URL_of_Anchor { -1,0,1 }
    res[13] = 0
# Links_in_tags { 1,-1,0 }
    succesrate = 0
    j = 0
    domain = 'cdn.sstatic.net'
    for link in soup.find_all('link', href=True):
        print(link["href"], "https://" + domain in link['href'])
        if ("https://" + domain in link['href'] or "http://" + domain in link['href']):
            successrate += 1
            print(successrate)
        j += 1
        print(j)
    try:
        percentage = successrate / float(j) * 100
    except:
        res[14] = 1

    if percentage < 17.0:
        res[14] = 1
    elif 17.0 <= percentage < 81.0:
        res[14] = 0
    else:
        res[14] = -1
# SFH  { -1,1,0 }
    for form in soup.find_all('form', action=True):
        if form['action'] == "" or form['action'] == "about:blank":
            res[15] = -1
        elif url not in form['action'] and domain not in form['action']:
            res[15] = 0
        else:
            res[15] = 1
   # res[15] = 1
    
# Submitting_to_email { -1,1 }
    res[16] = 0
# Abnormal_URL { -1,1 }
    if (url == w.domain_name):
        res[17] = 0
    else:
        res[17] = 1
# Redirect  { 0,1 }
    res[18] = 0
# on_mouseover  { 1,-1 }
    res[19] = 0
# RightClick  { 1,-1 }
    res[20] = 0
# popUpWindow  { 1,-1 }
    res[21] = 0
# Iframe { 1,-1 }
    res[22] = 0
# age_of_domain  { -1,1 }
    hostname='online.carnegie.dk'
    #whois
    port=443

    cert = ssl.get_server_certificate((hostname, port))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    pk = x509.get_pubkey()

    # print("Issuer:", x509.get_issuer())
    # print("Subject:", x509.get_subject())
    # print("Cert valid from:", datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'))
    # print("Cert valid to:", datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'))
    res[23] = 0
# DNSRecord   { -1,1 }
    try:
        print(socket.getaddrinfo(url,80) + " dnsrecord")
    except:
        print("dnsrecord failed")
        res[24] = 1
        
    # print("lookie here"),
    # print(url)
    # res[24] = 0
# web_traffic  { -1,0,1 }
    res[25] = 0
# Page_Rank { -1,1 }
    res[26] = 0
# Google_Index { 1,-1 }
    site = search(url,5)
    if(site):
        res[27] = 1
    else: res[27] = -1
# Links_pointing_to_page { 1,0,-1 }
    res[28] = 0
# Statistical_report { -1,1 }
    res[29] = 0
# Result  { -1,1 }
    res[30] = 0
    return res
    
print(CheckURLforPhishing(fakePhishing))


#husk ved externe kald, brug "try catch"