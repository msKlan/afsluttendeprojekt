from bs4 import BeautifulSoup, SoupStrainer
from googlesearch import search
import ssl
import socket
import bs4
from datetime import date, datetime
import requests
import argparse
import re
import OpenSSL
import sys
import pandas as pd
import whois
import time


def GetPhishingFeatures(p_url, p_verdict):
    # Desiker url og find metadata og andet som skal bruges i efterfølgende målepunkter
    today = date.today()
    url = p_url.lower()                   # Se bort fra versaler
    if (url.startswith("https://")):    # Find url uden http/https i starten
        strip_hdr = url[8:]
    elif (url.startswith("http://")):
        strip_hdr = url[7:]
    else:
        strip_hdr = url

    domain = re.findall(
        r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)", url)[0]  # Find domænenavn

    try:
        whois_domain = whois.whois(domain)  # Slå op i whois
    except:
        whois_domain = -1

    try:            # Hent siden og kør gennem BeautifulSoup
        page = requests.get(url)
        soup = BeautifulSoup(page.text, features="lxml")
    except:
        soup = -1
        page = -1

    # Initialiser de pt. 30 målepunkter (features) og 1 resultat
    # Generelt for alle målepunkter: 1 phishing, 0 mistænkelig og -1 ikke phishing
    res = [0]*31

# Indeholder en IP adresse { 1,-1 }
    if (re.findall(r'[0-9]+(?:\.[0-9]+){3}', url)):
        res[0] = -1
    else:
        res[0] = 1

# Længden af URL'en { 1,0,-1 }
    if (len(url) < 54):
        res[1] = -1
    elif (len(url) > 54 and len(url) < 75):
        res[1] = 0
    else:
        res[1] = 1

# Benyttes Shortening Services { 1,-1 }
    ss_match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|rb\.gy|clickmeter|'
                         r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                         r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                         r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                         r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                         r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                         r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)
    if (ss_match):
        res[2] = -1
    else:
        res[2] = 1

# Indeholder @ symbolet { 1,-1 }
    if (url.count("@") > 0):
        res[3] = -1
    else:
        res[3] = 1

# Indeholder "//" efter efter http/https - double_slash_redirecting { -1,1 }
    if (strip_hdr.count("//") > 0):
        res[4] = -1
    else:
        res[4] = 1

# Findes der "-" i domænenavnet - Prefix_Suffix  { -1,1 }
    if (domain.count("-") > 0):
        res[5] = -1
    else:
        res[5] = 1

# Findes der mere et "." i domænenavnet - having_Sub_Domain  { -1,0,1 }
    if (domain.count(".") == 1):
        res[6] = 1
    elif (domain.count(".") == 2):
        res[6] = 0
    else:
        res[6] = -1

# Er certifikat > 365 dage (tjekker ikke for om udsteder er trusted - SSLfinal_State  { -1,1,0 }
    try:
        port = 443
        cert = ssl.get_server_certificate((domain, port))
        x509 = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert)

        if ((datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ') -
             datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')).days > 365):
            res[7] = 1
        # elif (issuer not trusted):
        #     res[7] = 0
        else:
            res[7] = -1
    except:
        res[7] = -1

# Har domænenavnet være registreret mere 1 år - Domain_registeration_length { -1,1 }
    try:
        if (whois_domain != -1):
            whois_domain = whois.whois(domain)
            if ((today - whois_domain.creation_date.date()).days > 365):
                res[8] = 1
            else:
                res[8] = -1
        else:
            res[8] = -1
    except:
        res[8] = -1

# Har Favicon { 1,-1 }
    try:
        for link in soup.find_all('link', href=True):
            if ("favicon" in str(link)):
                first_split = link['href'].split("//")
                # Test om der er http/https
                if ("http" in first_split[0]):
                    second_split = first_split[1].split("/")
                    # Hvis domænenavne forskellig fra url-domæne - gottem phishing
                    if (domain == second_split[0]):
                        res[9] = -1
                    else:
                        res[9] = 1
                # Hvis første tegn er "." så er den en lokal reference
                elif (first_split[0][0] == "."):
                    res[9] = 1
            else:
                # Ingen favicon - ikke phishing
                res[9] = 1
    except:
        res[9] = 1

# Benyttes en non-standard port { 1,-1 }
    try:
        port = re.findall(r":([0-9]+)", url)[0]
        if (port in [80, 8080, 443, 8443]):
            res[10] = 1
        else:
            res[10] = -1
    except:
        res[10] = -1


# Er der // efter http/https - HTTPS_token { -1,1 }
    try:
        if (strip_hdr.count("https") > 0):
            res[11] = -1
        else:
            res[11] = 1
    except:
        res[11] = 1

# Hvor mange referencer til eksterne objekter i forhold til total antal - Request_URL  { 1,0,-1 }
    if (soup != -1):    # Siden skal være hentet
        no_ref = 0
        no_ext_ref = 0
        for script_tag in soup.find_all('img', src=True):
            try:
                src_domain = re.findall(
                    r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)", script_tag["src"])[0]
                if not(src_domain in [".", ".."] or src_domain == domain):
                    no_ext_ref += 1
                no_ref += 1
            except:
                pass
        for script_tag in soup.find_all('audio', src=True):
            try:
                src_domain = re.findall(
                    r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)", script_tag["src"])[0]
                if not(src_domain in [".", ".."] or src_domain == domain):
                    no_ext_ref += 1
                no_ref += 1
            except:
                pass
        for script_tag in soup.find_all('embed', src=True):
            try:
                src_domain = re.findall(
                    r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)", script_tag["src"])[0]
                if not(src_domain in [".", ".."] or src_domain == domain):
                    no_ext_ref += 1
                no_ref += 1
            except:
                pass

        try:
            percentage = no_ext_ref / float(no_ref) * 100
            if percentage < 22.0:
                res[12] = 1
            elif 22.0 <= percentage < 61.0:
                res[12] = 0                     # Mistænkelig
            else:
                res[12] = -1
        except:
            res[12] = 1
    else:
        res[12] = 1

# Antal af bookmarks og eksterne links - URL_of_Anchor { -1,0,1 }
    if (soup != -1):    # Siden skal være hentet
        no_ref = 0
        no_ext_ref = 0
        for a in soup.find_all('a', href=True):      # Tjek all a-tags
            if a['href'] == "#" or a['href'] == "#content" or a['href'] == "#skip" or a['href'].lower() == "javascript ::void(0)" or not (domain in a['href']):
                no_ext_ref += 1
            no_ref += 1

        try:
            percentage = no_ext_ref / float(no_ref) * 100
            if percentage < 31.0:
                res[13] = 1
            elif 31.0 <= percentage < 67.0:
                res[13] = 0                     # Mistænkelig
            else:
                res[13] = -1
        except:
            res[13] = 1
    else:
        res[13] = 1

# Antallet af eksterne referencer i Meta, Scripts og Links - Links_in_tags { 1,0,-1 }
    if (soup != -1):    # Siden skal være hentet
        no_ref = 0
        no_ext_ref = 0
        for script_tag in soup.find_all('meta', src=True):
            try:
                src_domain = re.findall(
                    r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)", script_tag["src"])[0]
                if not(src_domain in [".", ".."] or src_domain == domain):
                    no_ext_ref += 1
                no_ref += 1
            except:
                pass
        for script_tag in soup.find_all('script', src=True):
            try:
                src_domain = re.findall(
                    r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)", script_tag["src"])[0]
                if not(src_domain in [".", ".."] or src_domain == domain):
                    no_ext_ref += 1
                no_ref += 1
            except:
                pass
        for script_tag in soup.find_all('links', src=True):
            try:
                src_domain = re.findall(
                    r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)", script_tag["src"])[0]
                if not(src_domain in [".", ".."] or src_domain == domain):
                    no_ext_ref += 1
                no_ref += 1
            except:
                pass

        try:
            percentage = no_ext_ref / float(no_ref) * 100
            if percentage < 17.0:
                res[14] = 1
            elif 17.0 <= percentage < 81.0:
                res[14] = 0                     # Mistænkelig
            else:
                res[14] = -1
        except:
            res[14] = 1
    else:
        res[14] = 1


# Tjek submit aktion i forms - SFH  { -1,0,1 }
    try:
        for form in soup.find_all('form', action=True):
            action_domain = re.findall(
                r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)", script_tag["action"])[0]
            if form['action'] == "" or form['action'] == "about:blank":
                res[15] = -1
            elif not(action_domain in [".", ".."] or action_domain == domain):
                res[15] = 0
            else:
                res[15] = 1
    except:
        res[15] = 1

# Benyttes der mail() eller mailto: - Submitting_to_email { -1,1 }
    if (page != -1):
        if re.findall(r"[mail\(\)|mailto:?]", page.text):
            res[16] = -1
        else:
            res[16] = 1
    else:
        res[16] = 1

# Indgår domæanenavnet i whois i url - Abnormal_URL { -1,1 }
    try:
        if (str(whois_domain.domain_name) in url):
            res[17] = 1
        else:
            res[17] = -1
    except:
        res[17] = -1

# Antal af omdirigeringer - Redirect  { -1,1 }
    if (page != -1):
        if len(page.history) <= 1:
            res[18] = 1
        elif len(page.history) <= 4:
            res[18] = 0
        else:
            res[18] = -1
    else:
        res[18] = 1

# on_mouseover  { -1,1 }
    if (page != -1):
        if re.findall("<script>.+onmouseover.+</script>", page.text):
            res[19] = -1
        else:
            res[19] = 1
    else:
        res[19] = 1

# Findes der kode for at fange højreklik - RightClick  { -1,1 }
    if (page != -1):
        if re.findall(r"event.button ?== ?2", page.text):
            res[20] = -1
        else:
            res[20] = 1
    else:
        res[20] = 1

# Benyttes alert med tekstfelter - popUpWindow  { -1,1 }
    if (page != -1):
        if re.findall(r"alert\(", page.text):  # Tjek for textfelter
            res[21] = -1
        else:
            res[21] = 1
    else:
        res[21] = 1

# Benettes skjulte iframes - Iframe { -1,1 }
    if (page != -1):
        if re.findall(r"[<iframe>|<frameBorder>]", page.text):  # Tjek om det virker
            res[22] = -1
        else:
            res[22] = 1
    else:
        res[22] = 1

# Alder på domæane - age_of_domain  { -1,1 }
    try:
        if ((today - whois_domain.creation_date.date()).days < 180):  # 180 dage ~ 6 måneder
            res[23] = -1
        else:
            res[23] = 1
    except:
        res[23] = 1

# Er domæne registreret i DNS - DNSRecord   { -1,1 }
    if (whois_domain == -1):
        res[24] = -1
    else:
        res[24] = 1

# Hvilken rank har den i Alexa the Web Information Company - web_traffic  { -1,0,1 }
    try:
        rank = int(BeautifulSoup(request.get(
            "http://data.alexa.com/data?cli=10&dat=s&url=" + url).text, "xml").find("REACH")['RANK'])
        if (rank < 100000):
            res[25] = 1
        else:
            res[25] = 0
    except:
        res[25] = -1

# Hvilken pagerank har url'en - Page_Rank { -1,1 }
    try:
        rank_checker_response = requests.post(
            "https://www.checkpagerank.net/index.php", {"name": domain})
        global_rank = int(re.findall(
            r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
        if global_rank > 0 and global_rank < 100000:
            res[26] = -1
        else:
            res[26] = 1
    except:
        res[26] = 1

# Findes url'en i Google Index - Google_Index { 1,-1 }
    site = search(url, 5)
    if(site):
        res[27] = 1
    else:
        res[27] = -1

# Links_pointing_to_page { 1,0,-1 }
    try:
        number_of_links = len(re.findall(r"<a href=", page.text))
        if number_of_links == 0:
            res[28] = 1
        elif number_of_links <= 2:
            res[28] = 0
        else:
            res[28] = -1
    except:
        res[28] = -1


# Statistical_report { -1,1 }
    res[29] = 1  # Man skal købe sig til at kunne forespørge via api

# Result  { -1,1 }
    res[30] = p_verdict
    return res
# ---------------------------------------------------------------------------------


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="""
    This script extracts Phishing features based on URLs.
    """)
    parser.add_argument("-u", help="URL: A single URL")
    parser.add_argument(
        "v", help="Verdict: Is URL a Phishing site=-1 else if not 1", type=int)
    parser.add_argument(
        "-i", help="Input FIle: Input filename containing URLs")
    args = parser.parse_args()
    url = args.u
    input_f = args.i
    verdict = args.v

    if (url):       # "Features" for en enkelt URL
        print(url)
        print(GetPhishingFeatures(url, verdict))

    if (input_f):   # Hent listen af URL'er fra en fil og skriv "features" ned i en fil
        output_f = input_f.split(".")[0] + ".out"
        print("Input filename : ", input_f)
        print("Output filename : ", output_f)

        with open(input_f, encoding="utf8") as fi, open(output_f, "w") as fo:
            Lines = fi.readlines()
            for line in Lines:
                tic = time.perf_counter()
                fo.write("{}\n".format(
                    ','.join(map(str, GetPhishingFeatures(line.strip(), verdict)))))
                toc = time.perf_counter()
                print(
                    f"It took {toc - tic:0.2f} seconds to get phishing details for {line.strip()}")
                # print("url {}\n".format(line.strip()))
                # print("url {}\n{}".format(line.strip(),
                #                           GetPhishingFeatures(line.strip(), verdict)))

        ''' Åbne input_f
			læs linje for linje
				CheckURLforPhishing(url) og output i en fil
		'''

    # if len(sys.argv) > 1:
    #     u = sys.argv[1]

    # print(GetPhishingFeatures(u, 1))

    # husk ved externe kald, brug "try catch"

    # w = whois.whois("pythonforbeginners.com")
