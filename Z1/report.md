# HEŠOVANJE LOZINKI

### Inženjering zahteva

##### Password encoder:

1. SHA-256 koristeći salt

- Prednosti: Veoma brz
- Mane: Lak za brute-force i dictionary attack

2.  BCryptPasswordEncoder

- Prednosti: Otporan na brute-force i dozvoljava konfigurisanje kako bi se mogao otežati sa razvojem hardvera
- Mane: Ako sistem ima puno korisnika i ne toliko hardverske moci, može postati usko grlo

3.  SCryptPasswordEncoder

- Prednosti: Otporniji od BCrypt-a na napade
- Mane: Potreban sposobniji hardver nego za BCrypt i generalno sporiji

Odabrana zlatna sredina BCrypt sa cost faktorom 10 koji predstavlja computational cost odnosno 2^10 = 1024 iteracija hesiranja. Što je veći broj, više vremena je potrebno da bi se izračunao heš, a što je manji, lakši je za brute-force.

##### Provajder:

1. Bouncy Castle
2. Nimbus
3. Spring security crypto

Izabran spring security crypto 5.6.3 zbog ease-of-use u datom okruženju. Kasnije otkriven CVE-2023-34034 (Using wildcard as a pattern in Spring Security configuration for WebFlux creates a mismatch in pattern matching between Spring Security and Spring WebFlux, and the potential for a security bypass.)
Poslednja verzija ima ranjivost CVE-2024-22234 (Broken Access Control in Spring Security With Direct Use of isFullyAuthenticated).

### Implementacija

Preduslovi lozinke koje je lozinka morala da zadovolji:

1. dužina od 8 karaktera
2. 1 specijalan karakter 3. 1 broj

Nakon ispunjenih zahteva korišćen je BCryptPasswordEncoder koji je generisao heš lozinke sa dodatnim nasumično generisanom salt-om od 8 karaktera. Karakteri su mogli biti slovo, broj kao i specijalni znak.
Za svakog korisnika, pored heš lozinke, čuvan je i salt te lozinke. Nakon 3 meseca, lozinka ističe, i na prvom logovanju korisnik je promptovan da ažurira lozinku.
Nova lozinka mora da ispunjava iste preduslove kao i stare s tim što se uporedjuje leksički da li je nova lozinka ista kao i neka od prethodnih 10 (rotacija lozinki). Svaka nova lozinka ima i svoj novi salt koji se za nju čuva. Posto je BCrypt relativno spor algoritam i pošto se dodaje novi salt na svaku novu lozinku, brute-force napadi su drastično usporeni.
Za generisanje nasumičnih vrednosti, korišcen je SecureRandom paket u javi.
Šifra se kombinovala sa salt-om koristeci XOR operaciju.

## Mehanizam revizije (Auditing)

Postoje gotovi sistemi za logovanje kao što su logback u Javi koji omogućavaju logovanje.

- Logovi su struktuirani, odnosno daju jasne odgovore na pitanja: "KO?", "ŠTA?" i "KADA?".
- Kako bismo obezbedili neporecivost akcije, pored korisničkog imena, korisno je logovati i IP adresu sa koje je akcija izvršena, kao i timestamp koji je obavezan deo svakog log zapisa.
- Da bi sakrili osetljive podatke moguće je kriptovati ih ili ih uopšte ni ne logovati ako nije potrebno.
- Da bi se obezbedila pouzdanost log datoteka potrebno je čuvati datoteke na više lokacija (više servera, cloud,..).
- Da bi se očuvao integritet log fajlova moguće je digitalno potpisivanje ili heširanje.
- Kako bi se izbegla "pretrpanost" datoteka potrebno ih je redovno arhivirati. logback implementira roll mehanizam za arhiviranje na osnovu veličine datoteke ili proteklog vremena.

# Dodatne bezbednosne kontrole

Implementirano na prethodnom projektu:

1. _Autentifikacija_ 1. Dvofaktorska Autentifikacija (2FA): zahtjeva od korisnika da pruži 2 oblika identifikacije prije pristupa sistemu. Uključivalo je nešto što korisnik zna tj. lozinku i nešto što korisnik ima tj. kod poslat putem SMS-a ili email-a. 2. Oporavak Lozinke: omogućava korisnicima da bezbjedno resetuju svoje zaboravljene lozinke. Vrši se verifikacija identiteta korisnika prije dozvoljavanja same promjene. 3. OAuth Protokol: Omogućava korisnicima sigurnu autentifikaciju tako što koriste već postojeći nalog (Google nalog) umjesto kreiranja novog.
2. _Autorizacija_
   Uloge zasnovane na kontroli pristupa (RBAC): korisnicima dodjeljene uloge na osnovu kojih je ograničen pristup metodama i resursima u aplikaciji. Informacije o ulogama nalaze se unutar JWT tokena.
3. _Upravljanje unosom_ 1. ReCAPTHCA za forme: Zaštita od spamovanja i automatskih zloupotreba formi. Implementirana je verzija reCAPTCHA v2 koja podrazumjeva checkbox "I'm not a robot'" i izazove sa slikama.
   2.Sprečavanje SQL Injection Napada: implemenitrano kroz rigorozne validacije, kao i parametrizovane upite. 3. Sprečavanje XSS Napada: implementirano kroz čišćenje svih korisničkih unosa koji se prikazuju na stranici. 4. Sprečavanje Path Traversal Napada: korišćene su bezbedne API funkcije za pristup fajl sistemu, odnosno onemogućen je neautorizovan pristup datotekama i direktorijumima.

Implementirane bezbjednosne kontrole u velikoj mjeri odgovaraju preporučenim bezbjednosnim konfiguracijama, prateći standarde i najbolje prakse kao što su OWASP Top 10 i NIST smjernice. Dvofaktorska autentifikacija, RBAC, i zaštita od uobičajenih web ranjivosti poput SQL Injection i XSS napada su u skladu sa industrijskim preporukama za bezbjednu praksu. Međutim, konstantne promene u informacionoj bezbjednosti i pojava novih prijetnji zahtjevaju neprekidno ažuriranje i prilagođavanje ovih kontrola da bi se održao visok nivo sigurnosti.
