import sys
import pandas as pd
import whois
import socket, ssl
import OpenSSL
from datetime import date, datetime
from googlesearch import search
from bs4 import BeautifulSoup
import bs4

today = date.today()

fakeURL = "https://www.fakewebsite.org/should_not_be_suspicious"
fakePhishing = "http://www.gimmeyourinfo.ru.dk.com/@/add_something_suspicious//as_i_go_along.dk"

#url = fakePhishing

def Check_having_IP_Address(url):
    #fjern https, http, etc og www og check om det indeholder tal med punktummer
    return 1

def Check_URL_Length(url):
    if (len(url)<54):
        return -1
    elif (len(url)>54 and len(url)<75):
        return 0
    else: 
        return 1
    
def Check_Shortining_Service(url):
    lowercase = url
    if (lowercase.count("bitly" or "tinyurl" or "ow.ly" or "rebrandly" or "t2m" or "clickmeter")>0):
        return 1
    else:
        return 0

def Check_Having_At_symbol(url):
    if (url.count("@") > 0):
        return 1
    else:
        return 0
    
def Check_double_slash_redirecting(url):
    doubleslash = url
    doubleslash.replace("https://", "")
    doubleslash.replace("http://", "")
    if (doubleslash.count("//")>0):
        return 1
    else:
        return 0
    
def Check_Prefix_Suffix(url):
    if (url.count("-") > 0):
          return 1
    else:

        return 0

def Check_having_Sub_Domain(url):
    if (url.count(".") >= 1):
        return -1
    elif (url.count(".") == 2):
        return 0
    else: 
        return 1
    
def Check_SSLfinal_State(url):
        return 0
    
def Check_Domain_registeration_length(url):
    w = whois.whois("pythonforbeginners.com")
    print(w.updated_date[0].strftime("%Y-%m-%d"))
  #  print(w.updated_date[0])
    print("crackhead")
    print(today.strftime("%Y-%m-%d"))
    print((w.updated_date[0] - w.creation_date[0]).days)
    
    #registrar, updated_url, creation_date, expiration_date, name servers
    return 0
    
def Check_Favicon(url):

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
            print(1, first_split)
            faviconreturn = 1
            if ("http" in first_split[0]):
                print(2, 'has http', first_split[1])
                second_split = first_split[1].split("/")
                print("3 host=", second_split[0])
                faviconreturn = 0
                if (host == second_split[0]):
                    print(4, "local on host", -1)
                    faviconreturn = -1
                else:
                    print(5, "external host", 1, ("gottem"))
                    faviconreturn = 1
            elif (first_split[0][0] == "."):
                print(6, "local on host", -1)
                faviconreturn = -1
            else:
                print(7, "local on host", -1)
    return faviconreturn
            
    
def Check_port(url):
        return 0
    
def Check_HTTPS_token(url):
    nohttpstoken = url.split("//", 1)[1]
    if (nohttpstoken.count("https")>0):
        return 1
    else:
        return 0
    
def Check_Request_URL(url):
        return 0
    
def Check_URL_of_Anchor(url):
        return 0
    
def Check_Links_in_tags(url):
        return 0
    
def Check_SFH(url):
        return 0
    
def Check_Submitting_to_email(url):
        return 0
    
def Check_Abnormal_URL(url):
        
        return 0
    
def Check_Redirect(url):
        return 0
    
def Check_on_mouseover(url):
        return 0
    
def Check_RightClick(url):
        return 0
    
    
    #their spelling error, not mine
def Check_popUpWindow(url):
        return 0
    
def Check_Iframe(url):
        return 0
    
def Check_age_of_domain(url):
    hostname='online.carnegie.dk'
    #whois
    port=443

    cert = ssl.get_server_certificate((hostname, port))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    pk = x509.get_pubkey()

    print("Issuer:", x509.get_issuer())
    print("Subject:", x509.get_subject())
    print("Cert valid from:", datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'))
    print("Cert valid to:", datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'))
    return 0
    
def Check_DNSRecord(url):
        return 0
    
def Check_web_traffic(url):
        return 0
    
def Check_Page_Rank(url):
        return 0
    
def Check_Google_Index(url):
        site = search(url,5)
        return 1 if site else -1
    
def Check_Links_pointing_to_page(url):
        return 0
    
def Check_Statistical_report(url):
        return 0
    
def Check_Result(url):
        return 0








def UrlData(url):
    r = [-1, 1, 1, 1, -1, -1, -1, -1, -1, 1, 1, -1, 1, -1, 1, -
         1, -1, -1, 0, 1, 1, 1, 1, -1, -1, -1, -1, 1, 1, -1, -1]
    return r


if __name__ == "__main__":
    #print(Check_having_IP_Adress("dr.dk"))
    #print(Check_having_IP_Adress("192.168.40.11"))

#    print(Check_having_IP_Address(fakeURL))
#    print(Check_having_IP_Address(fakePhishing))
#    print(Check_URL_Length(fakeURL))
#    print(Check_URL_Length(fakePhishing))
#    print(Check_Shortining_Service(fakeURL))
#    print(Check_Shortining_Service(fakePhishing))
#    print(Check_Having_At_symbol(fakeURL))
#    print(Check_Having_At_symbol(fakePhishing))
#    print(Check_double_slash_redirecting(fakeURL))
#    print(Check_double_slash_redirecting(fakePhishing))
#    print(Check_Prefix_Suffix(fakeURL))
#    print(Check_Prefix_Suffix(fakePhishing))
#    print(Check_having_Sub_Domain(fakeURL))
#    print(Check_having_Sub_Domain(fakePhishing))
#    print(Check_SSLfinal_State(fakeURL))
#    print(Check_SSLfinal_State(fakePhishing))
    print(Check_Domain_registeration_length(fakeURL))
    print(Check_Domain_registeration_length(fakePhishing))
#    print(Check_Favicon(fakeURL))
#    print(Check_Favicon(fakePhishing))
#    print(Check_port(fakeURL))
#    print(Check_port(fakePhishing))
#    print(Check_HTTPS_token(fakeURL))
#    print(Check_HTTPS_token(fakePhishing))
#    print(Check_Request_URL(fakeURL))
#    print(Check_Request_URL(fakePhishing))
#    print(Check_URL_of_Anchor(fakeURL))
#    print(Check_URL_of_Anchor(fakePhishing))
#    print(Check_Links_in_tags(fakeURL))
#    print(Check_Links_in_tags(fakePhishing))
#    print(Check_SFH(fakeURL))
#    print(Check_SFH(fakePhishing))
#    print(Check_Submitting_to_email(fakeURL))
#    print(Check_Submitting_to_email(fakePhishing))
#    print(Check_Abnormal_URL(fakeURL))
#    print(Check_Abnormal_URL(fakePhishing))
#    print(Check_Redirect(fakeURL))
#    print(Check_Redirect(fakePhishing))
#    print(Check_on_mouseover(fakeURL))
#    print(Check_on_mouseover(fakePhishing))
#    print(Check_RightClick(fakeURL))
#    print(Check_RightClick(fakePhishing))
#    print(Check_popUpWindow(fakeURL))
#    print(Check_popUpWindow(fakePhishing))
#    print(Check_Iframe(fakeURL))
#    print(Check_Iframe(fakePhishing))
#    print(Check_age_of_domain(fakeURL))
#    print(Check_age_of_domain(fakePhishing))
#    print(Check_DNSRecord(fakeURL))
#    print(Check_DNSRecord(fakePhishing))
#    print(Check_web_traffic(fakeURL))
#    print(Check_web_traffic(fakePhishing))
#    print(Check_Page_Rank(fakeURL))
#    print(Check_Page_Rank(fakePhishing))
#    print(Check_Google_Index(fakeURL))
#    print(Check_Google_Index(fakePhishing))
#    print(Check_Links_pointing_to_page(fakeURL))
#    print(Check_Links_pointing_to_page(fakePhishing))
#    print(Check_Statistical_report(fakeURL))
#    print(Check_Statistical_report(fakePhishing))
#    print(Check_Result(fakeURL))
#    print(Check_Result(fakePhishing))