#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import re
import sys
import hmac
import codecs
import hashlib
import getpass
import itertools


PY2 = sys.version_info[0] < 3

if PY2:
    input = raw_input


def b64_hmac_md5(key, data):
    """
    return base64-encoded HMAC-MD5 for key and data, with trailing '='
    stripped.
    """

    # For Py3 and Unicode compatibility
    data = str2bytes(data)
    key = str2bytes(key)

    # In Py3 hmac.digest() returns bytes, so
    digest = hmac.HMAC(key, data, hashlib.md5).digest()
    bdigest = codecs.encode(digest, 'base64').decode().strip()

    return re.sub('=+$', '', bdigest)


def str2bytes(string):
    """
    Returns string encoded to bytes, in way that every letter is represented
    by only first byte after encoding it with 'UTF-16-LE' encoding.
    For ascii characters this means that its return is the same as
    str.encode(), but for other unicode strings (eg. Polish) this does its job.
    Example: str2bytes('ąśćóasco') --> b'\x05[\x07\xf3asco'
    """
    u16le = 'utf-16-le'
    if PY2:
        sse = sys.stdin.encoding or 'utf-8'
        return ''.join([ltr.decode(sse).encode(u16le)[0] for ltr in string])
    return bytes([letter.encode(u16le)[0] for letter in string])


# set of domain suffixes to be kept
_domains = ["ab.ca", "ac.ac", "ac.at", "ac.be", "ac.cn", "ac.il",
            "ac.in", "ac.jp", "ac.kr", "ac.nz", "ac.th", "ac.uk",
            "ac.za", "adm.br", "adv.br", "agro.pl", "ah.cn", "aid.pl",
            "alt.za", "am.br", "arq.br", "art.br", "arts.ro",
            "asn.au", "asso.fr", "asso.mc", "atm.pl", "auto.pl",
            "bbs.tr", "bc.ca", "bio.br", "biz.pl", "bj.cn", "br.com",
            "cn.com", "cng.br", "cnt.br", "co.ac", "co.at", "co.il",
            "co.in", "co.jp", "co.kr", "co.nz", "co.th", "co.uk",
            "co.za", "com.au", "com.br", "com.cn", "com.ec", "com.fr",
            "com.hk", "com.mm", "com.mx", "com.pl", "com.ro",
            "com.ru", "com.sg", "com.tr", "com.tw", "cq.cn", "cri.nz",
            "de.com", "ecn.br", "edu.au", "edu.cn", "edu.hk",
            "edu.mm", "edu.mx", "edu.pl", "edu.tr", "edu.za",
            "eng.br", "ernet.in", "esp.br", "etc.br", "eti.br",
            "eu.com", "eu.lv", "fin.ec", "firm.ro", "fm.br", "fot.br",
            "fst.br", "g12.br", "gb.com", "gb.net", "gd.cn", "gen.nz",
            "gmina.pl", "go.jp", "go.kr", "go.th", "gob.mx", "gov.br",
            "gov.cn", "gov.ec", "gov.il", "gov.in", "gov.mm",
            "gov.mx", "gov.sg", "gov.tr", "gov.za", "govt.nz",
            "gs.cn", "gsm.pl", "gv.ac", "gv.at", "gx.cn", "gz.cn",
            "hb.cn", "he.cn", "hi.cn", "hk.cn", "hl.cn", "hn.cn",
            "hu.com", "idv.tw", "ind.br", "inf.br", "info.pl",
            "info.ro", "iwi.nz", "jl.cn", "jor.br", "jpn.com",
            "js.cn", "k12.il", "k12.tr", "lel.br", "ln.cn", "ltd.uk",
            "mail.pl", "maori.nz", "mb.ca", "me.uk", "med.br",
            "med.ec", "media.pl", "mi.th", "miasta.pl", "mil.br",
            "mil.ec", "mil.nz", "mil.pl", "mil.tr", "mil.za", "mo.cn",
            "muni.il", "nb.ca", "ne.jp", "ne.kr", "net.au", "net.br",
            "net.cn", "net.ec", "net.hk", "net.il", "net.in",
            "net.mm", "net.mx", "net.nz", "net.pl", "net.ru",
            "net.sg", "net.th", "net.tr", "net.tw", "net.za", "nf.ca",
            "ngo.za", "nm.cn", "nm.kr", "no.com", "nom.br", "nom.pl",
            "nom.ro", "nom.za", "ns.ca", "nt.ca", "nt.ro", "ntr.br",
            "nx.cn", "odo.br", "on.ca", "or.ac", "or.at", "or.jp",
            "or.kr", "or.th", "org.au", "org.br", "org.cn", "org.ec",
            "org.hk", "org.il", "org.mm", "org.mx", "org.nz",
            "org.pl", "org.ro", "org.ru", "org.sg", "org.tr",
            "org.tw", "org.uk", "org.za", "pc.pl", "pe.ca", "plc.uk",
            "ppg.br", "presse.fr", "priv.pl", "pro.br", "psc.br",
            "psi.br", "qc.ca", "qc.com", "qh.cn", "re.kr",
            "realestate.pl", "rec.br", "rec.ro", "rel.pl", "res.in",
            "ru.com", "sa.com", "sc.cn", "school.nz", "school.za",
            "se.com", "se.net", "sh.cn", "shop.pl", "sk.ca",
            "sklep.pl", "slg.br", "sn.cn", "sos.pl", "store.ro",
            "targi.pl", "tj.cn", "tm.fr", "tm.mc", "tm.pl", "tm.ro",
            "tm.za", "tmp.br", "tourism.pl", "travel.pl", "tur.br",
            "turystyka.pl", "tv.br", "tw.cn", "uk.co", "uk.com",
            "uk.net", "us.com", "uy.com", "vet.br", "web.za",
            "web.com", "www.ro", "xj.cn", "xz.cn", "yk.ca", "yn.cn",
            "za.com"]


def extract_domain(host):
    """
    Domain name extractor. Turns host names into domain names, ported
    from pwdhash javascript code"""
    host = re.sub('https?://', '', host)
    host = re.match('([^/]+)', host).groups()[0]
    domain = '.'.join(host.split('.')[-2:])
    if domain in _domains:
        domain = '.'.join(host.split('.')[-3:])
    return domain


_password_prefix = '@@'


def generate(password, uri):
    """
    generate the pwdhash password for master password and uri or
    domain name.
    """
    realm = extract_domain(uri)
    if password.startswith(_password_prefix):
        password = password[len(_password_prefix):]

    password_hash = b64_hmac_md5(password, realm)
    size = len(password) + len(_password_prefix)
    nonalphanumeric = len(re.findall(r'[^a-zA-Z0-9_]', password)) != 0

    return apply_constraints(password_hash, size, nonalphanumeric)


def apply_constraints(phash, size, nonalphanumeric):
    """
    Fiddle with the password a bit after hashing it so that it will
    get through most website filters. We require one upper and lower
    case, one digit, and we look at the user's password to determine
    if there should be at least one alphanumeric or not.
    """
    starting_size = size - 4
    starting_size = 0 if starting_size < 0 else starting_size
    result = phash[:starting_size]

    extras = itertools.chain((ord(ch) for ch in phash[starting_size:]),
                             itertools.repeat(0))
    extra_chars = (chr(ch) for ch in extras)
    nonword = re.compile(r'\W')

    def next_between(start, end):
        interval = ord(end) - ord(start) + 1
        offset = next(extras) % interval
        return chr(ord(start) + offset)

    for elt, repl in (
            (re.compile('[A-Z]'), lambda: next_between('A', 'Z')),
            (re.compile('[a-z]'), lambda: next_between('a', 'z')),
            (re.compile('[0-9]'), lambda: next_between('0', '9'))):
        if len(elt.findall(result)) != 0:
            result += next(extra_chars)
        else:
            result += repl()

    if len(nonword.findall(result)) != 0 and nonalphanumeric:
        result += next(extra_chars)
    else:
        result += '+'

    while len(nonword.findall(result)) != 0 and not nonalphanumeric:
        result = nonword.sub(next_between('A', 'Z'), result, 1)

    amount = next(extras) % len(result)
    result = result[amount:] + result[0:amount]

    return result


def console_main():
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Domain: ").strip()

    password = getpass.getpass("Password for {}: ".format(domain))
    generated = generate(password, domain)

    copied_to_clipboard = False

    try:
        import pyperclip
        pyperclip.copy(generated)
        copied_to_clipboard = True
    except ImportError:
        pass

    if copied_to_clipboard:
        print("Password was copied to clipboard.")
    else:
        print(generated)

if __name__ == '__main__':
    console_main()
