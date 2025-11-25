# python_101
# Uvod u programiranje

Kada bi pisanim jezikom znali zadavati naredbe računalu, mogli bi mu
naređivati da kontinuirano izvršava naše \"recepte\". Mogli bi
automatizirati razne zadatke! To je programiranje: zadavanje naredbi
računalu putem jezika koji je osmišljen baš za tu svrhu. Obzirom da su
računala vrlo efikasna u obavljanju dosadnih i repetitivnih radnji i da
to rade brzo i precizno, to je vrlo korisna vještina.

Programiranje je, međutim, puno više od samo automatizacije poznatih nam
procesa. Takvim razmišljanjem stvaramo i uvjete za nove ideje i
mogućnosti. Možemo osmisliti potpuno nove pristupe raznim problemima. Na
ovaj način je, na primjer, nastao softver s grafičkim sučeljem koji nam
omogućuje zadavanje naredbi računalu kroz vizualne metafore radije nego
kroz tekstualne naredbe. Danas nam gotovo više nije moguće zamisliti rad
sa računalima bez ove inovacije, ali u početku to nije bila nimalo
jednostavna zamisao. Također, ovako su nastali Internet i World Wide
Web, precizniji medicinski aparati, računalne igre, algoritmi koji uče,
umjetna inteligencija, mogućnost programiranja satelita u svemiru i
robota koji istražuju Mars te mnogi drugi sustavi koji nas danas
okružuju te nam pomažu i zabavljaju nas. Ovako su nastali i računalni
virusi i ostali maliciozni softver, kontrola i krađa informacija,
utjecaj na ljudske odluke i opredjeljenja na daleko većoj i suptilnijoj
razini no ikad prije, kibernetičko ratovanje te kojekakve druge
opasnosti i nepoznatosti. Ovako su nastali Google, Facebook, Amazon i
druge gigantske web korporacije koje donose mnoge korisne usluge, ali i
počinju kontrolirati sve veću količinu informacija. Ovako nastaje sve
što su ljudi sposobni osmisliti, a može se provesti putem zadavanja
naredbi umreženim računalima\...

Ipak, ovaj tekst se ne tiče šireg utjecaja korištenja računala na gotovo
sve sfere ljudske djelatnosti već na osnove upravljanja računalom putem
programskih jezika pa ćemo se fokusirati samo na to. Važno je samo
držati na umu koliko toga je moguće postići programiranjem jer se
prilikom učenja osnova na tu činjenicu može lako zaboraviti. Za
usporedbu nam može poslužiti matematika. Dok tek učimo osnovne
aritmetičke račune lako je propustiti koliki značaj matematika ima u
arhitekturi, fizici, glazbi i mnogim drugim sferama ljudske djelatnosti.

U svakom slučaju, danas smo do te mjere okruženi raznim grafičkim
sučeljima da je često teško zamisliti što možemo s programiranjem izvan
konteksta razvoja takvog softvera. Programiranje je drugi način
komunikacije koji se temelji na formalnim jezicima i formiranju procesa
koji računalo na zahtjev može izvršiti bilo koji broj puta. Kao
praktična vještina, programiranje nam omogućuje automatizaciju
kojekakvih radnih zadataka, a izrada aplikacija s grafičkim sučeljem je
samo jedan vid korištenja ove vještine. Kao teorijsko znanje,
programiranje nam omogućava bolji uvid u rad računala i suvremenih
informacijskih sustava, ali i u formalne načine upravljanja putem
strukturiranih podataka.

O terminologiji ćemo kasnije, ali recimo za sada da zapis naredbi
izrečenih nekim programskim jezikom, odnosno skup programskih
instrukcija, nazivamo \"programskim kôdom\" što se često jednostavno
skraćuje u \"kôd\"[^1]. Kako bismo počeli programirati, moramo odabrati
neki programski jezik koji propisuje *sintaksu* za pisanje kôda. Taj
jezik nam omogućuje da razgovaramo s računalom. Sintaksa je skup pravila
koji propisuje kako ispravno formirati neki prirodni ili umjetan jezik,
odnosno koje rečenice izrečene jezikom su ispravne, a koje nisu.

Za potrebe ovog teksta odabran je programski jezik **Python**, ali
većina prikazanih koncepata i mehanizama tvore osnovu razumijevanja
programiranja koja je primjenjiva u gotovo bilo kojem suvremenom
programskom jeziku. Kada se nauči jedan programski jezik, mnogi osnovni
koncepti ostaju isti i u drugima.

Python je popularan programski jezik vrlo *visoke razine*[^2] i
*općenite namjene* koji je dostupan za sve danas popularne operativne
sustave. Neke prednosti ovog programskog jezika i razlozi radi kojih se
često uči kao prvi programski jezik su sljedeći:

-   **Brzo postizanje rezultata i brzo usvajanje jezika**: napisati
    program koji radi nešto korisno zahtijeva manje posla nego u većini
    drugih jezika. Također, Python se brzo uči i često navodi kao
    izvrstan jezik za prvi susret s programiranjem. Ipak, za razliku od
    mnogih drugih \"početničkih\" jezika, Python je koristan i
    profesionalcima.

-   **Čitljiv kôd**: sintaksa je dizajnirana s naglaskom na čitljivost.
    Python kôd je sličan engleskom jeziku te sadrži manje posebnih
    znakova (poput vitičastih zagrada i točka-zareza) od većine drugih
    jezika.

-   **Više-paradigmatski pristup**: Python dopušta proceduralno,
    objektno i funkcijsko programiranje. U njemu možemo napisati
    jednostavnu skriptu, ali i kompleksan program s grafičkim sučeljem
    ili web aplikaciju.

-   **Baterije uključene**: Python dolazi s velikom zbirkom *standardnih
    modula* koji proširuju jezik s vrlo korisnim i često potrebnim
    mogućnostima (na primjer čitanje i zapis posebnih formata, rad s
    datotekama i operativnim sustavom, slanje elektroničke pošte, rad s
    WWW tehnologijama \...). Drugim riječima, mnoge programski
    naprednije radnje su već uključene u samu instalaciju ovog
    programskog jezika.

-   **Aktivna zajednica**: Python je vrlo popularan i za mnogo toga se
    aktivno koristi. Radi toga postoji velik broj kvalitetnih proširenja
    mogućnosti ovog programskog jezika (i.e. modula) koji se aktivno
    razvijaju. Drugim riječima, u posebnim slučajevima (poput rada sa
    slikama i drugom multimedijom ili statističkim podacima) postoji već
    velik broj kvalitetnih proširenja koji nam olakšavaju rad. Također,
    lako je pronaći pomoć i dobiti podršku za česte probleme.

## Instalacija Pythona

Python programski kôd možemo pisati na papiru pa čak i na zidu pećine i
to bi još uvijek bio jezik Python. Ipak, kako bismo kôd pisan u Pythonu
*izvršili* potrebno ga je zapisati kao računalni tekst. Taj tekst se
zatim putem posebnog programa prevodi u drugu vrstu kôda koji je
računalu moguće direktno provesti, a ljudima nije čitljiv. O detaljima
ćemo kasnije, ali recimo za sada da je taj poseban program koji prevodi
Python u instrukcije izvršive računalu sama *implementacija* programskog
jezika i da ga je potrebno instalirati kako bismo mogli izvršavati
naredbe napisane u tom programskom jeziku.

Obzirom da je implementacija Pythona računalni program, a i sama
definicija jezika se razvija dodavanjem i zastarijevanjem koncepata,
Python razvojem dobiva različite verzije. Minimalna pretpostavljena
verzija Pythona za potrebe ovog teksta je 3.3., a preporuča se
instalirati zadnju 3.x verziju.

Koristite Python 3 Ova skripta nije namijenjena za Python 2.x i mnogi
primjeri u toj verziji neće raditi ili će raditi pogrešno.

U trenutku pisanja ovog teksta, Python 2 još uvijek na nekim operativnim
sustavima (MacOS te razne Linux distribucije) dolazi unaprijed
instaliran, ali se može smatrati zastarjelim i ta verzija Pythona se
koristi samo kako bi se održala kompatibilnost sa starijim sustavima
koji još nisu prerađeni u noviju verziju. Provjerite dakle da je Python
koji pokrećete Python 3, a ne 2.

Kada se Python instalira kroz standardni postupak (tj. registrira se u
operativnom sustavu), Python datoteke postaju *izvršive*, odnosno mogu
se direktno pokretati kao programi. Na primjer, \"duplim klikom\" ili u
sistemskoj komandnoj liniji. Python datoteke prepoznajemo po tome što im
je nastavak \".py\", ali su te datoteke zapravo obične tekstualne
datoteke i tipičan nastavak bi im bio \".txt\". Nastavak \".py\"
jednostavno naznačuje da se u njima ne nalazi slobodan tekst već tekst
napisan u jeziku Python. Također, uz instalaciju Pythona dolaze i
popratne komponente poput programa za interaktivno izvršavanje
programskih naredbi, dokumentacije i raznih dodatnih proširenja
mogućnosti ovog jezika.

Operativni sustav (OS) Windows ne uključuje instalaciju Pythona već ga
je potrebno dodatno instalirati. Opis instalacije za Windows OS je u
nastavku. Što se tiče raznih Linux distribucija i MacOS-a, Python je
često unaprijed instaliran, ali treba provjeriti verziju te instalirati
Python 3.x ukoliko je potrebno. Upute za instalaciju za MacOS i Linux
distribucije možete pronaći na [python.org](http://www.python.org).

### Instalacija na Windows OS-u

Standardna instalacija na Windows OS-u se obavlja putem \"instalera\"
referentne implementacije Pythona s [python.org](http://www.python.org).
Python instaliran na ovaj način dolazi sa svim standardnim dijelovima
jezika i jednostavno ga je instalirati putem uobičajenog grafičkog
sučelja za instalaciju *desktop* aplikacija. Na slici
[1](#fig:wininstall){reference-type="ref" reference="fig:wininstall"}
vidimo kako izgleda pokretanje instalacije novijih verzija Pythona.

![Instalacija Pythona na Windows OS-u](/slike/windows_install.png)

{#fig:wininstallwidth="\\textwidth"}
Dok klik na \"Install Now\" obavlja većinu posla, ipak je korisno
primijetiti neke detalje i uključiti dodatne mogućnosti. Python će se po
zadanim postavkama instalirati u korisnički direktorij (na slici je
instalacija za korisnika koji se zove Z) i to u pod-direktorij
\"AppData\\Local\\Programs\\Python\". Ovo je zgodno zapamtiti jer katkad
treba pronaći instalaciju Pythona na disku. Glavni razlog za to je
instalacija proširenja (koja se u Pythonu nazivaju \"moduli\") za ovaj
programski jezik. U ovom smislu je vrlo korisna i mogućnost **Add Python
3.x to PATH** koja po zadanim postavkama nije uključena, ali dobro ju je
uključiti. Tada nakon instalacije možemo Python alate koristiti iz bilo
kojeg direktorija, što je posebno korisno za instalaciju dodatnih
modula, odnosno proširenja mogućnosti ovog programskog jezika.

## Pisanje i izvršavanje Python kôda

Kao što smo već rekli, manji Python program nije ništa drugo nego jedna
obična tekstualna datoteka s instrukcijama napisanim u jeziku Python i s
ekstenzijom \".py\" radije nego \".txt\". Ovo više manje stoji za sve
programske jezike, osim što drugi koriste vlastite ekstenzije. Python
datoteke s nastavkom .py može izvršavati direktno bez dodatnih
korisničkih koraka. Drugim riječima, .py datoteke možemo jednostavno
pokrenuti klikom miša ili unosom u komandnu liniju. Kod drugih vrsta
jezika moramo prvo automatski prevesti tekstualne datoteke koje sadrže
instrukcije u binarne datoteke koje su izvršive (kao što su to .exe
datoteke).

Drugi način izvršavanja Python kôda je unosom u Python komandnu liniju.
Ova komandna linija nije isto što i komandna linija operativnog sustava
jer izvršava Python kôd radije no sistemske naredbe. Python komandna
linija je vrlo korisna za učenje i testiranje kôda, a iskusni programeri
je koriste i za jednostavnije administrativne ili analitičke zadatke.
Nije međutim podobna za pisanje programa koje planiramo izvršiti veći
broj puta ili obavljanje kompleksnijih radnji. Ova mogućnost nije toliko
univerzalna među programskim jezicima kao što je to zapis programa u
tekstualne datoteke. Ipak, ova komandna linija nam **omogućava direktnu
eksperimentaciju** i jedna od prednosti Pythona i to posebno za potrebe
učenja programiranja. Ovu mogućnost valja, dakle, često koristiti!

Standardna instalacija Pythona dolazi s programom \"IDLE\" koji pruža
jednostavno grafičko sučelje za direktno izvršavanje kôda. Nakon što smo
instalirali Python, pokrenimo program IDLE kako bismo krenuli izvršavati
programske naredbe jer je ovo u početku vrlo korisno za upoznavanje
koncepata i eksperimentaciju s mogućnostima. IDLE se ponaša kao i većina
aplikacija s grafičkim sučeljem, odnosno moguće ju je pokrenuti kroz
*Start menu* ili ekvivalente u drugim operativnim sustavima.

![Izvršavanje Python kôda putem sučelja IDLE](/slike/idle.png)

{#fig:idlewidth="\\textwidth"}
Kada pokrenemo IDLE, dočekati će nas glavno sučelje ovog programa koje
je prikazano na slici [2](#fig:idle){reference-type="ref"
reference="fig:idle"}. U glavnom prozoru IDLE-a naredbe se upisuju nakon
redaka koje počinju s \"$>>>$\", a izvršavaju pritiskom na tipku *enter*
odnosno *return*. U ovom slučaju smo izvršili jednostavan *izraz*
`1 + 1`{.python}. Kada se taj izraz evaluira pritiskom na tipku *enter*,
rezultat se ispisuje u idućem retku koja ne započinje s \"$>>>$\" kako
bi bilo jasno da se radi o rezultatu, a ne o naredbi. Obzirom da još
nismo spomenuli niti jednu posebnu naredbu za programske jezike,
probajte izvesti nekoliko osnovnih matematičkih radnji. IDLE je sam po
sebi sjajan kao kalkulator, a dobiti ćete dojam kako ovakvo sučelje
funkcionira. Nemojte se uplašiti ukoliko vam se ne ekran ispišu crvena
slova koja javljaju grešku, to je normalno.

Osim same komandne linije, IDLE funkcionira i kao program za izradu
tekstualnih datoteka odnosno omogućuje i standardan pristup
programiranju. Ako iz padajućeg izbornika odaberemo mogućnost
\"File-\>New File\", otvoriti će nam se nova tekstualna datoteka kao što
je vidljivo na slici [3](#fig:idle_text){reference-type="ref"
reference="fig:idle_text"}. Datoteka sadrži tipičan program za prvi
susret s programiranjem koji ćemo kasnije podrobnije analizirati.

![IDLE i pisanje tekstualnih datoteka](/slike/idle_text.png)

{#fig:idle_textwidth="\\textwidth"}
Novi prozor koji nam se otvorio je jednostavan program za pisanje
tekstualnih datoteka (poput Notepada i sličnog softvera), a ne komandna
linija kao glavni prozor IDLE-a. U novonastalu datoteku možemo upisati
bilo koji program i zatim ga izvršiti putem mogućnosti iz padajućeg
izbornika \"Run-\>Run Module\" ili pritiskom na tipku \"F5\". Jedini
zahtjev je da prvo sačuvamo datoteku na disk pri čemu je dobro paziti da
joj dodijelimo ekstenziju .py. IDLE kao softver je, naime, dosta
asketske prirode pa neke verzije ne paze na to umjesto nas. Rezultat ove
radnje je vidljiv na slici [4](#fig:idle_text_run){reference-type="ref"
reference="fig:idle_text_run"}.

![IDLE i rezultat izvršavanja programa](/slike/idle_text_run.png)

{#fig:idle_text_run width="\\textwidth"}
Upravo smo izvršili računalni program! Ovu datoteku nismo morali
pokretati kroz IDLE, mogli smo je i jednostavno pokrenuti direktno iz
operativnog sustava. Ipak, prije no što se bacimo na samo programiranje
recimo nešto o primjerima u ovom tekstu jer ih ubuduće nećemo više
prikazivati kroz slike softvera s grafičkim sučeljem već kao programski
kôd.

## Primjeri

Obzirom da se radi o programiranju, ovaj tekst je prepun primjera.
Primjeri su posebno označeni kako bi bilo jasno da se radi o kôdu,
radije nego o slobodnom tekstu. Na primjer:

Ovakvi primjeri su najčešći i prikazuju dio Python koda kakav bi se
nalazio u nekoj .py datoteci. Ove datoteke je najbolje za početak pisati
u softveru koji nam je jednostavno koristiti pa kasnije potencijalno
preći na profesionalniji softver za programiranje. Za upoznavanje s
ovakvim softverom i odabir aplikacije za pisanje kôda vidi poglavlje
[1.6](#softver){reference-type="ref" reference="softver"}, a za sada se
zadržimo na primjerima u ovom tekstu.

Primjeri U ovoj tekstu primjeri su neobično važni jer se upravo unutar
primjera često prenose novi koncepti i mogućnosti tako da ih je vrlo
važno sve pročitati i dobro razumjeti jer kasniji primjeri zahtijevaju
da su raniji koncepti već usvojeni.

Osim spomenute vrste primjera, postoji još jedna:

Primjeri u kojima neki reci počinju s \"$>>>$\" su česti u Python
literaturi i označavaju da se radi o interaktivnom izvršavanju kôda
kojeg je korisnik unio u komandnu liniju kao što smo prikazali ranije.
Na ovaj način se često prikazuju osnovni koncepti, a pojava ovakvog
primjera naznačuje da s prikazanim treba eksperimentirati u Python
komandnoj liniji (npr. IDLE-u) kako bi bolje usvojili prikazane koncepte
i mehanizme.

Riječ je o mogućnosti Pythona da se kôd upisuje i izvršava redak po
redak što je izvrsno za učenje jezika jer omogućava direktnu
eksperimentaciju. Reci koji počinju s \"$>>>$\" su oni koje mi upisujemo
u Python komandnu liniju, a reci bez tih znakova se mogu pojaviti samo
nakon redaka s početnim \"$>>>$\" i prikazuju rezultat izvršavanja
prijašnjeg retka, ako postoji. Naravno, znakovi \"$>>>$\" nisu dio kôda
već jednostavno naznaka gdje se nalazi početak linije koja se izvršila.
Drugim riječima, njih ne prepisujemo kada želimo isprobati kôd!

U svakom slučaju, ovakva mogućnost direktnog izvršavanja kôda je izvrsna
za učenje programiranja i eksperimentiranje pa je topla preporuka
koristiti ju čim više. Kada god niste sigurni kako nešto funkcionira i
koji je rezultat ili vrsta rezultata određenog izraza, eksperimentirajte
s time u Python komandnoj liniji.

Vrijedi napomenuti i da primjeri iz komandne linije prikazuju kôd koji
nije nužno međusobno povezan među recima, dok je to kod primjera iz
datoteka uvijek slučaj.

## Moj prvi program

Rekli smo već da se s Pythonom brzo postižu rezultati pa umjesto teorije
krenimo s implementacijom tradicionalnog programa za prvi susret s
programiranjem, a obzirom da radimo u vrlo čitljivom i produktivnom
programskom jeziku, odvesti ćemo ovaj program i korak dalje! Svi
spomenuti koncepti u ovom poglavlju su pobliže objašnjeni kasnije u
skripti.

Napravite novu tekstualnu datoteku s nazivom \"pozdrav_svijetu.py\".
Jedan način za ovo je odabir mogućnosti \"File \> New File\" u programu
IDLE. Pa zatim \"File \> Save\" u novom prozoru kada ispunimo datoteku.
Sadržaj datoteke treba biti sljedeći:

Ova datoteka je *računalni program* koji ispisuje \"Pozdrav, svijete!\"
na ekran. Prikazani program nije posebno uzbudljiv, ali ga možemo
smatrati kompletnom aplikacijom[^3]. Ekstenzija \".py\" označava da se
radi o Python kôdu. Ako je Python instaliran na sustavu, ova datoteka se
može pokrenuti kao *izvršiva* datoteka. Drugim riječima, dupli klik na
ovu datoteku (ili unos u komandnu liniju) i ovaj program će ispisati
\"Pozdrav, svijete!\" na ekran i završiti izvršavanje programa. Ako se
sustav umjesto toga požali na nepoznatu ekstenziju, znači da Python nije
pravilno instaliran odnosno da nije registriran u operativnom sustavu.

Ako pak na pokretanje datoteke samo neki prozor bljesne na ekranu i
odmah se zatvori ili se naoko ništa ne dogodi, šanse su da se program
ispravno izvršio. Naime, početnicima je čest problem vidjeti rezultate
ovog programa jer se rezultat ispisuje u komandnu liniju, a taj prozor
se uglavnom zatvori čim program završi. Za ovo je kriv operativni sustav
koji komandnu liniju zatvori čim je program gotov s izvršavanjem. Jedan
od načina na koji možemo riješiti problem je da dodamo još jednu naredbu
u naš program koja računalu govori da pričeka neki naš unos prije no što
se završi izvršavanje.

Otvorite \"pozdrav_svijetu.py\" i promijenite sadržaj u:

Probajmo sada pokrenuti \"pozdrav_svijetu.py\" duplim klikom na
datoteku. Vježba je uspješna ako vidimo ekran na kojem su ispisana dva
retka teksta (\"Pozdrav, svijete!\" i \"Pritisni \<enter\> za kraj\")
koji se se zatvara (ili vraća u komandnu liniju) kad pritisnemo tipku
*enter*. Sad smo već i doradili naš program kako bi zaobišli određene
osebujnosti operativnog sustava. Ako program još uvijek ne radi, šanse
su da smo negdje učinili pogrešku u sintaksi pa provjerite da su zagrade
i navodnici ispravno zatvoreni.

Općenito rečeno, računalni program je sustav *računalu izvršivih
naredbi*. Te naredbe rade na temelju specificiranih podataka jer
**računalo može raditi samo s podacima**. Posljedice slanja tih podataka
određenom hardveru (ekstremniji primjeri bi bili nuklearna elektrana ili
satelit u svemiru) mogu itekako imati utjecaja na stvarni svijet, ali
računalni programi interno rade samo s podacima. Možemo pojednostavljeno
reći da se računalni programi sastoje od *radnji* i od *podataka*.
Zapravo i sam zapis programa možemo smatrati podacima[^4], ali biti će
nam lakše početi programirati ako razlikujemo dijelova kôda koji
*prenose instrukcije* odnosno koje *reprezentiraju radnje* i dijelove
kôda koji *prenose informacije*, odnosno koji jednostavno
*reprezentiraju podatke*.

Pogledajmo kako to funkcionira u programu koji smo upravo napisali. U
našem programu, prva naredba se sastoji od poziva na *funkciju*
`print`{.python} s vrijednošću `'Pozdrav, svijete!'`{.python} kao
*parametrom* što zajedno tvori jedan *izraz*:
`ispiši 'Pozdrav, svijete!' na ekran`{.python}. Ovaj izraz se sastoji od
poziva na jednu radnju i svih podataka potrebnih za izvršavanje te
radnje. Ti podaci su u ovom slučaju jednostavno tekst koji treba
ispisati, a radnja se provodi pozivom na funkciju. Druga naredba se, na
isti način, sastoji od poziva na funkciju `input`{.python} s vrijednošću
`'Pritisni <enter> za kraj'`{.python}. Funkciju ovdje možemo shvatiti
kao \"naredbu računalu\" radije no u striktno matematičkom smislu, a
*poziv na funkciju* je naredba da se funkcija izvrši. Funkcija je jedan
od temeljnih načina na koji u suvremenim programskim jezicima zadajemo
radnje koje računalo treba izvršiti. Možemo reći da osnovne radnje
\"pakiramo\" u funkcije što nam omogućuje da izvršavamo kompleksnije
radnje kroz jednu naredbu. `print`{.python} je najosnovnija funkcija za
izvještavanje korisnika o rezultatima programa ili o važnim
informacijama za vrijeme izvršavanja programa, a `input`{.python} je
najosnovnija funkcija koja korisniku omogućuje unos vrijednosti u
program. Drugim riječima, `input`{.python} i `print`{.python} su osnovne
*input/output* naredbe u Pythonu. Obje funkcioniraju kroz komandnu
liniju jer bilo kakvo grafičko sučelje unosi dodatne komplikacije u
program i zahtjeve za operativni sustav. Programiranje grafičkog sučelja
za ovaj program bi, na primjer, bilo znatno kompleksnije za izvesti od
onoga što program već radi.

U našem programu, funkciju `input`{.python} koristimo samo za zadršku
programa od zatvaranja prije no što smo stigli pročitati informacije
koje nam je program ispisao. Ovo je zapravo trik koji koristimo kako nam
operativni sustav ne bi zatvorio prozor prije no što pročitamo rezultate
programa. U idućoj vježbi je prikazano kako se `input`{.python}
uobičajeno koristi.

Otvorite \"pozdrav_svijetu.py\" i promijenite sadržaj u kôd prikazan u
primjeru [\[listing:pozdrav3\]](#listing:pozdrav3){reference-type="ref"
reference="listing:pozdrav3"}, a zatim pokrenite program i pratite upute
na ekranu.

U ovom zadatku, pojavljuju se novi koncepti, *komentar* i *varijabla*.

Komentari se naznačuju znakom `#`{.python} i sav tekst nakon tog znaka
se smatra slobodnim tekstom koji se ne izvršava, a ne programskim kôdom.
Znak `#`{.python} se može pojaviti bilo na početku ili unutar retka.
Komentari služe pružanju dodatnih informacija o kôdu i vrlo su korisni
za poboljšanje čitljivosti i planiranje programa. U kompleksnom kôdu, na
primjer, korisno je napisati riječima što se u nekom dijelu odvija kako
bi se olakšao razvoj i kasnije preinake. Prilikom razvoja, često je
korisno i prvo slobodnim jezikom napisati što se sve mora gdje odvijati
pa tek zatim, kad struktura i logika programa postane jasna,
isprogramirati sam programski kôd.

Komentari Kôd je korisno komentirati i preporuča se bogato korištenje
komentara. Na taj način se mogu pružiti dodatna objašnjenja koja služe
boljem razumijevanju kôda. Također, vrlo su korisni kada čitamo tuđi kôd
ili se vratimo na vlastiti kôd koji smo napisali ranije pa zatim nismo
neko vrijeme radili na njemu.

U ovom tekstu komentari u primjerima su vrlo važni jer objašnjavaju kôd,
podsjećaju na ranije spoznaje pa čak i uvode nove koncepte.

Obratite, dakle, pažnju na komentare u primjerima jer se njima skreće
pažnja na važne ili nove koncepte. Kraći komentari koji se odnose na
jedan redak kôda se pišu u istom retku nakon samog kôda. Duži komentari
se najčešće pišu u redak iznad samog kôda te se nakon njih ne ostavlja
prazan redak. Ukoliko je komentar predugačak za redak kôda[^5], tada se
komentar može podijeliti u više redaka, a svaku je potrebno započeti
znakom `#`{.python}.

Komentarlisting:komentar print(\"jao meni\") \# komentar za ovaj redak

\# komentar za retke kôda koje slijede print(\"aha, aha\")

\# komentar koji se ne odnosi na neki poseban kôd

\# komentar koji je predugačak da bi stao u jedan redak kôda se može \#
prelomiti u dva ili više redaka, a u ovom slučaju se odnosi \# na kôd
odmah nakon komentara print(\"avaj\")

Varijable možemo shvatiti kao nazive koji stoje za druge vrijednosti. Te
vrijednosti su programeru najčešće nepoznate u trenutku pisanja kôda i
mogu se promijeniti za vrijeme izvršavanja programa. Varijable su nam
nužno potrebne kako bi se mogli referirati na razne podatke koji su
rezultati radnji u programu, koje si unijeli korisnici ili koji su pak
dohvaćeni iz vanjskih datoteka, baza podataka ili raznih *online*
usluga. U primjeru
[\[listing:pozdrav3\]](#listing:pozdrav3){reference-type="ref"
reference="listing:pozdrav3"}, `text`{.python} je varijabla. To možemo
prepoznati ponajprije zato zato jer joj se u retku
`text = input("Unesi tekst i pritisni <enter>: ")`{.python} *pridružuje*
vrijednost. Naime, znak `=`{.python} je *operator* za pridruživanje
vrijednosti varijabli. Uz funkcije, operatori (npr. `+`{.python} i
`-`{.python}) su drugi osnovan način zadavanja specifičnih radnji s
podacima. Pridruživanje vrijednost varijablama te izvršavanje radnji
putem funkcija i operatora je podrobnije opisano u idućem poglavlju, kao
i njihova povezanost sa širim konceptima *izjava* i *izraza*. Ono što
vrijedi spomenuti odmah su pravila imenovanja varijabli, funkcija i
ostalih elemenata koji imaju specifična imena.

Tekst `'Unesi tekst i pritisni <enter>: '`{.python} ili broj
`1`{.python} su vrijednosti, ne stoje za nešto drugo već jesu upravo taj
niz znakova odnosno taj broj. Varijabla `text`{.python} je drugačija,
ona ne stoji za niz od četiri slova `'text'`{.python} već je naziv za
što god je korisnik unio u program putem funkcije `input`{.python}.

Nazivi i pravila imenovanja Nazivi (npr. varijabli i funkcija) u Pythonu
i većini drugih programskih jezika se smiju sastojati samo od slova,
brojki i donje crte (\_) i ne smiju počinjati s brojem. Ne smiju, dakle,
sadržavati razmake i interpunkcijske znakove. Također, ne smiju biti
rezervirane riječi kao što su to riječi `if`{.python}, `and`{.python},
`while`{.python} i slične.

Što se funkcija tiče, kao prvi susret možemo proučiti kako radi funkcija
`input`{.python}. Ta funkcija:

1.  prima tekst za prikaz korisniku (koji mu tipično daje upute) kao
    ulazni podatak

2.  ispisuje taj tekst na ekranu te čeka da korisnik upiše nešto i
    potvrdi unos tako što stisne *enter*

3.  kao rezultat funkcije vraća tekst koji je korisnik napisao prije no
    što je stisnuo *enter*

Vrijednost varijable `text`{.python} je dakle varijabilna i točnu
vrijednost uopće ne moramo znati prilikom pisanja programa: ona je što
god da je korisnik unio putem funkcije `input`{.python} *za vrijeme
izvršavanja* programa. U naredbi
`text = input('Unesi tekst i pritisni <enter>')`{.python}, prvo se
izvršava izraz koji se sastoji od poziva funkcije `input`{.python} s
jednom vrijednosti kao parametrom. Taj izraz vraća vrijednost koju je
korisnik unio i ta vrijednost se pridružuje varijabli `text`{.python}. U
ostatku programa, kada se želimo referirati na koju god vrijednost da je
korisnik unio možemo to činiti putem varijable `text`{.python} kao u
naredbi `print(text)`{.python}. Dapače, moramo tako jer ne možemo
unaprijed znati koju će vrijednost korisnik unijeti! Općenitije, opis
funkcije `input`{.python} prikazuje kako radi tipična funkcija: primi
parametre, na osnovu njih provede neke radnje pa vrati rezultat. Taj
rezultat često pridružujemo nekoj varijabli kako bi se na njega mogli
kasnije referirati.

### Moja prva pogreška

Prije no što krenemo dalje, recimo nešto i o pogreškama u kôdu. One će
nam se često dešavati i to nije ništa neobično. Dapače, događaju se i
iskusnim programerima, a najveća razlika je što će iskusan programer
brže prepoznati o čemu se radi i ispraviti grešku. Drugim riječima, kada
vidimo crvena slova na ekranu to nas ne treba nimalo obeshrabriti.
Najčešće pogreške u početku su greška u sintaksi pisanja. Ovo se
najčešće događa kada zaboravimo zatvoriti zagradu, navodnike ili dodati
zarez gdje je potrebno.

Kada pokrenemo ovaj program, sustav će javiti sljedeću grešku:

Problem je što smo u retku 2 zaboravili zatvoriti zagradu. Obzirom da se
naredbe mogu pisati u više redaka, Python je pogrešku uočio tek u retku
3 pa nam to i javlja. Kada vidimo pogrešku vrste `SyntaxError`{.python}
to znači da nešto ne valja u retku koji nam javlja sustav ili u retku
prije toga. U ovom slučaju, greška je u retku 2. Kod pogreška je važno
zapamtiti sljedeće:

Pogreške Pogreške će nam se često dešavati, posebno u početku. To je
normalno i znači da smo radili i pokušavali. Bez obzira na koliko je
tekst pogreške dugačak, poruka koju ju opisuje je u zadnjem retku pa nju
valja pročitati prvu. Reci prije toga služe kako bi lakše pronašli
pogrešku u kôdu. S vremenom ćemo naučiti vrste pogrešaka i biti će nam
ih sve lakše ispravljati.

Pogledajmo za sada još jednu čestu pogreško, a kasnije ćemo se njima
baviti podrobnije.

Obzirom da je sada sintaksa ispravna, program će se početi izvršavati,
ali će se u retku 3 dogoditi sljedeća pogreška:

Kada nam se pojavi pogreška vrste `NameError`{.python} to znači da smo
se negdje referirali na naziv (npr. varijable ili funkcije) koji ne
postoji. U ovom slučaju smo varijablu u retku 2 nazvali `text`{.python},
a u retku 3 se referiramo na naziv `tekst`{.python} koji u ovom programu
nije definiran. Ovo će nam također biti česta pogreška i vrlo često se
javlja uslijed tipfelera. Na primjer kada napišemo \"prnit\" umjesto
\"print\".

Sada kada se više ne bojimo pogrešaka, možemo iskoristiti prikazane
koncepte, dodati jedan novi za kontrolu toka programa i možemo
isprogramirati mali računalni upitnik. Ovaj program je vidljiv u
primjeru [\[listing:kviz\]](#listing:kviz){reference-type="ref"
reference="listing:kviz"}.

Unesimo taj primjer u tekstualnu datoteku i pokrenimo. Kao što vidimo,
igraču je omogućen odabir odgovora kroz vrijednost koju unosi u komandnu
liniju. Neko grafičko sučelje bilo bi samo proširenje ovog programa koja
bi tu vrijednost unijela kroz igračev pritisak na gumb ili što slično te
omogućilo korištenje multimedije.

Nakon što je igrač unio odabir, tok programa se nastavlja u odnosu na
taj odabir. Konkretnije, prikazani kôd uključuje *kondicional* koji
odlučuje koji dio kôda će se izvršiti. Kad bismo ga pročitali normalnim
jezikom, taj kondicional bi mogao zvučati ovako: \"Ako je igrač unio
malo slovo \"a\", tada ispiši tekst vezan za odabir \"a\". Ako je pak
igrač unio malo slovo \"b\", tada ispiši tekst vezan za odabir \"b\".
Ako je pak igrač unio malo slovo \"c\", tada ispiši tekst vezan za
odabir \"c\". A ako je igrač unio bilo što drugo, tada ispiši tekst
vezan za nepoznati odabir.\" Većina riječi u prikazanom kôdu nam je sama
po sebi razumljiva, a riječ `elif`{.python} u Python kôdu je jednostavno
skraćeni oblik engleskog izraza *else if* odnosno "osim ako".

Naš kondicional se ovdje sastoji od četiri *uvjeta*. Kôd pisan uvučeno
ispod uvjeta (nakon redaka koji počinju s `if`{.python}, `elif`{.python}
ili `else`{.python}), izvršava se samo ako je uvjet zadovoljen. U
Pythonu se uvlačenjem kôda naznačava koji reci kôda se izvršavaju u
odnosu na koji uvjet. Ako je, na primjer,
`if player_choice == "c":`{.python} uvjet zadovoljen, tada se izvršavaju
reci 16 i 17. Sve retke koji se izvršavaju na ovaj način zajedno
nazivamo *blok* kôda. Dvotočka nam naznačava da se nakon retka koji
njome završava očekuje novi blok kôda odnosno da ćemo uvući retke koje
se izvršavaju u odnosu na redak koja završava s \":\".

Navedeno ćemo kasnije detaljnije objasniti, ali za sada je važno
zapamtiti da je uvlačenje u Pythonu značajno te da označava koji reci se
izvršavaju zajedno i pod što pripadaju! Također, ovdje se radi o
osebujnosti Pythona koja zgraža mnoge puriste. U drugim jezicima,
uvlačenje je uglavnom stvar stila, a blok kôda se često naznačuje
vitičastim zagradama (\"{\" i \"}\"). Ipak, bilo koji programer koji
drži do sebe će i u drugim programskim jezicima kôd uvući kako je
prikazano jer ga je tako puno ugodnije za čitati.

Primijetimo i dvostruki znak jednakosti, odnosno `==`{.python}. Ovo je
jednostavno operator za provjeru jednakosti. `a == b`{.python} čitano
normalnim jezikom je: \"Da li je a jednako b?\" i rezultat može biti
`True`{.python} ili `False`{.python}. Sjetimo se, znak `=`{.python} u
Pythonu (i mnogim drugim jezicima), služi pridruživanju vrijednosti
varijablama, a ne provjeri jednakosti! Drugim riječima `a = 1`{.python}
bi čitali \"varijabli `a`{.python} pridruži vrijednost `1`{.python}\", a
ne \"je li vrijednost pridružena varijabli `a`{.python} jednaka broju
`1`{.python}\".

U svakom slučaju, naš prvi program je sada dovoljno dorađen da smo
dobili neki dojam o programiranju i sada možemo dublje ući u teme koje
smo upravo otvorili. U ovom dijelu teksta programiranje je prikazano od
programa prema korištenim konceptima kako bi se dobio uvid u osnove
pisanja programa te se u neke koncepte nije dublje ulazilo. Kako bi
mogli programirati potrebno je biti dobro upoznat s osnovnim programskim
konceptima te o mogućnostima koje neki specifičan jezik pruža. Zato su u
nastavku cjeline razrađene obratno, od terminologije i najosnovnijih
koncepata prema specifičnim temama koje ćemo obraditi u sljedećem
redoslijedu:

1.  **Radnje:** izjave, izrazi, operatori, funkcije i metode

2.  **Podaci:** osnovne vrste vrijednosti (brojevi, booleove vrijednosti
    i vrijednost `None`{.python})

3.  **Proširenja mogućnosti:** rad s modulima

4.  **Kontrola toka:** kondicionali, petlje i pokušaji

5.  **Tekst:** osnove razumijevanja računalnog teksta i programski rad s
    istim

6.  **Putanje i datoteke:** rad s tekstualnim datotekama, putanjama i
    datotečnim sustavom

7.  **Strukture podataka:** popisi, rječnici i skupovi

8.  **Definicija funkcija:** kreiranje vlastitih radnji

9.  **Definicija modula:** kreiranje vlastitih proširenja

10. **Definicija klasa:** kreiranje vlastitih vrsta vrijednost i vezanih
    radnji

Svaka od navedenih tema biti će popraćena bogato komentiranim primjerima
kako bismo naučili koristiti prikazane teme u praksi. Ipak, prije no što
krenemo dublje u sve ovo, krenimo od općenitijeg pregleda nekih osnovnih
koncepata i pojmova.

## Osnovni koncepti i pojmovi

Kao što ste već vjerojatno uočili, tema programiranja prožeta je
vlastitom specijaliziranom terminologijom. Mnoge termine upoznat ćemo
kroz rad s vezanim konceptima. Ipak, prije no što se bacimo na samo
\"štrikanje\" kôda, korisno se upoznati s nekim osnovnim pojmovima.

### Što je to \"programski jezik\"?

Već smo rekli da je Python *programski jezik* koji je *visoke razine* i
*općenite namjene*. Što je to \"programski jezik\"? Jednostavno rečeno,
to je formalan jezik koji je namijenjen za davanje instrukcija računalu.
Tekstualan zapis ovih instrukcija nazivamo *programski kôd* ili često
samo *kôd*. Ali što je \"formalan jezik\"? Za naše potrebe možemo reći
da je to umjetan jezik koji zadovoljava strogo definiranu sintaksu i ima
strogu specifikaciju. Formalni jezici izbjegavaju pojave višeznačnosti i
istoznačnosti koje se pojavljuju u prirodnim jezicima. Cilj je postići
da kad napišemo nešto formalnim jezikom, za razliku od prirodnog jezika,
postoji samo jedna moguća ispravna interpretacija napisanog.

\"Programski jezik\" je u svojoj srži *specifikacija* formalnog jezika s
posebnom namjenom. Kôd pišemo prema toj specifikaciji i možemo ga pisati
na bilo koji medij koji podržava tekst. Recimo da čitamo ovaj tekst u
tiskanom izdanju. Python programi preneseni kroz primjere nisu ništa
manje \"Python programi\" zato jer su na papiru. Bili bi programi i da
su zapisani ugljenom na zid pećine. Međutim, da bi ih računalo moglo
*izvršiti*, moramo 1) pohraniti kôd kao računalni tekst i 2) izvršiti
taj kôd putem posebnog programa koji ga zna prevesti u instrukcije koje
računalo može provesti. Taj poseban program je *implementacija*
programskog jezika. Kada smo ranije \"instalirali Python\" zapravo smo
instalirali njegovu referentnu implementaciju. Implementaciju možemo
promatrati kao realizaciju specifikacije, a na računalima se ta
realizacija provodi kroz softver.

Implementacija programskog jezika Specifikacija programskog jezika se
implementira aplikacijom koju je potrebno instalirati kako bi se taj
programski jezik mogao izvršavati.

Perceptivniji dio publike primijetit će ovdje potencijalan problem:
programski jezik implementiran je aplikacijom koja je, po svojoj
prirodi, implementirana nekim programskim jezikom. Programski jezici se,
prema tome, implementiraju programskim jezicima! U najčešćem slučaju,
programski jezici *više razine* se implementiraju u programskim jezicima
*niže razine*. Standardna implementacija Pythona, koja je dostupna s
[python.org](http://www.python.org), zove se CPython (kada ju je
potrebno diferencirati od drugih implementacija Pythona) i, kako ime
kaže, implementirana je u programskom jeziku C. Kada netko kaže
\"instaliraj si pajton\", šanse su da misli na CPython.[^6]

### Razine programskih jezika i izvršavanje kôda

Kod programskih jezika, pridjev \"visoke razine\" znači da je jezik
visoko apstrahiran u odnosu na način na koji računala hardverski primaju
instrukcije, odnosno da koristi jednostavnu sintaksu i konstrukte nalik
prirodnom jeziku kako bi se povećala produktivnost u pisanju programa te
poboljšala čitljivost i razumijevanje napisanog kôda. Pri tome način na
koji računalo izvršava instrukcije ne utječe (jako) na sam dizajn
jezika.

Računalo pak razumije samo nule i jedinice. Nema struje, ima struje. Čim
je jezik niže razine, tim je bliži hardverskoj logici rada računala.
Danas se jezici poput C-a katkad spominju kao jezici niže razine, ali
preciznije rečeno C je sistemski jezik visoke razine. Konstrukti koje
stvaramo u C-u ne odgovaraju direktno logici računala, ali C je
orijentiran na efikasnost i dopušta upravljanje hardverom (na primjer,
upravljanje zauzećem memorije) što jezici visoke razine danas obavljaju
automatski. U Pythonu, na primjer, ne možemo direktno upravljati
zauzećem memorije jer mu to jednostavno nije namjena i u praksi upravo
radi toga može postići već reklamiranu brzinu i jednostavnost pisanja
kôda. Ono što se, naravno, gubi tim pristupom je *efikasnost izvedbe*,
ali danas nam je u mnogim slučajevima važnija *efikasnost pisanja* kôda
jer, obzirom na brzinu današnjih računala, za mnoge zadatke efikasnost
izvedbe jednostavno više nije problem.

Programski jezici najniže razine su potpuno ovisni o arhitekturi
računala i najčešće ih nazivamo *assembly* jezicima. Instrukcije koje
dajemo putem ovakvih jezika imaju otprilike jedan na jedan odnos prema
radnjama koje računalo zapravo obavlja. U ranim danima programiranja,
odnosno u prvom razdoblju u kojem su se računala počela programirati
pohranjenim programima radije nego hardverskim promjenama, bilo je
moguće programirati samo u ovakvim jezicima. Također, ovakvi programi su
daleko najefikasniji za izvedbu jer uglavnom direktno odgovaraju
hardverskim radnjama. S rastom računalne snage ovo prestaje biti problem
za mnoge aplikacije, a aplikacije koje su namijenjene za maksimalnu
efikasnost (operativni sustavi, sustavi koji funkcioniraju u stvarnom
vremenu, računalne igre \... ) se sve češće programiraju u tzv.
sistemskim jezicima poput C-a i već dugo je to standard. Pisati složene
sustave u *assembly* jezicima bilo bi problematično. Drugi razlog
korištenju *assembly* jezika je bio što jednostavno nisu postojale druge
paradigme u programiranju. Razvoj programskih jezika je uvelike razvoj
logičkih konstrukata i metafora podobnih za programiranje ljudima, a
koji se mogu prevesti u direktne instrukcije računalima.

U svakom slučaju, na najnižoj razini je *strojni kôd*: instrukcije
zapisane u binarnom kôdu koji računalo može direktno izvršavati putem
svog hardvera. Računalu, naravno, sve o čemu smo da sada pričali treba
prevesti u nule i jedinice koje direktno prenose određene instrukcije
hardveru. Skup tih instrukcija je propisan samim procesorom koji
koristimo, a kôd napisan u bilo kojem jeziku se na ovaj ili onaj način
prevodi u skup ovakvih instrukcija koje su direktno hardverski izvršive.
Izvršavanje kôda, dakle uvijek zahtijeva prevođenje u izvršivu verziju
koja više nije ljudski čitljiva.

U ovom smislu možemo razlikovati interpretirane i kompajlirane jezike.
Kod interpretiranih jezika naredbe je moguće izvršavati direktno, bez
posebnog procesa prevođenja u izvršivu datoteku. Python je ovakav jezik
(iz korisničke perspektive), što i omogućuje interaktivno izvršavanje
naredbi u komandnoj liniji. Jezici poput C-a, C++-a, Jave i C\#-a su pak
kompajlirani jezici. Kako bi se kôd napisan u ovakvim jezicima mogao
izvršiti, potrebno ga je prvo prevesti u izvršivu datoteku i taj proces
se naziva kompajliranje.

Prednost interpretacije je mogućnost direktnog izvršavanja kôda, a
manjak to što se za vrijeme izvršavanja programa (eng. *runtime*) mogu
dogoditi greške koje su je bilo moguće pronaći u procesu kompajliranja
kao i manja efikasnost izvršavanja kôda. Prednosti i mane kompajliranja
su upravo obratno.

### Namjena programskih jezika

Već smo spomenuli da je Python jezik \"općenite namjene\". Takav opis
programskog jezika znači da nema neku posebnu namjenu već široku paletu
upotreba (npr. matematičke operacije, rad s datotekama, administracija
sustava, izrada softvera s grafičkim sučelja, obrada podataka, izrada
web-stranica, itd.). Postoje i jezici s definiranom primarnom namjenom
koji se koriste u nekoj specifičnoj domeni. Na primjer, programski jezik
R je namijenjen za statističke postupke što ga čini izvrsnim za provedbu
istih nad podacima i upravljanje podacima u te svrhe, ali nije podoban
za druge radnje (npr. obrada teksta, izrada web-stranica ili aplikacija
s grafičkim sučeljem).

Uz navedeno, mnogi jezici koji su općenite namjene u praksi postanu
popularni za određene svrhe. C je, na primjer, praktički *lingua franca*
operativnih sustava. JavaScript i PHP se koriste gotovo isključivo za
programiranje web aplikacija odnosno web stranica. Python se pak
etablirao kao dobar jezik za učenje programiranja, ali i u području
analitičke obrade podataka, strojnog učenja i tzv. znanstvenog
računarstva.

### Softver, programi, aplikacije, skripte \...

Raščistili smo neke apstraktne pojmove vezane uz prirodu i izvedbu
programskih jezika. Pogledajmo još neke pojmove vezane uz ciljeve
programiranja. Programiranje, složit ćemo se, primarno služi izradi
*računalnih programa*. Računalni programi vrsta su *softvera* odnosno
sačinjavaju ih instrukcije računalu. Neki programi su *aplikacije*, neki
*skripte*, a neki pak sistemski softver poput *operativnih sustava*.

Aplikacije su programi s nekom specifičnom namjenom i koje zahtijevaju
operativni sustav za funkcioniranje. Aplikacija je softver koji je
namijenjen za diseminaciju krajnjim korisnicima, odnosno onima koji nisu
sudjelovali u implementaciji iste. Ovakav softver vrlo često ima i
grafičko sučelje.

Skripta je program koji je, često vrlo brzo[^7], napisan s nekom vrlo
specifičnom namjenom (npr. \"kopiraj sve slike koje zadovoljavaju uvjet
u neki direktorij i promjeni im rezoluciju\" ili \"preuzmi podatke iz
baze podataka, spoji ih s vanjskim podacima i zapiši ih u XML\") i kojeg
ima smisla izvršavati samo u tu usku svrhu. Skripte se katkad pokreću i
samo jednom te ih nakon toga više nema razloga pokretati jer su obavile
za što su namijenjene. Skripte vrlo često nisu namijenjene diseminaciji
krajnjim korisnicima te ih koriste samo oni koji su ih napisali ili se
ugrađuju kao automatski izvršavani elementi raznih sustava poput web
usluga. Skripte nemaju grafičko sučelje.

### Sastavni dijelovi programskog kôda

Način na koji možemo podijeliti osnovne sastavne dijelove kôda uvelike
ovisi o vrsti jezika odnosno o paradigmama unutar kojih je jezik
dizajniran. Te paradigme su široka tema koju ćemo uglavnom zaobići jer
nam za sada nisu potrebne[^8], ali recimo samo da je Python
*imperativan* jezik što znači da u njemu formalno zapisujem naredbe koje
računalu govore *što da napravi*. Ovo je najlakše objasniti u kontrastu
s *deklarativnim* jezicima u kojima formalno zapisujemo *što želimo
dobiti kao rezultat*. Primjer deklarativnog jezika specifične namjene je
SQL (*Structured Query Language*) koji služi radu s relacijskim bazama
podataka.

Najosnovniji sintaktički element imperativnih jezika je *izjava* (eng.
*statement*) koja služi zadavanju onoga što smatramo jednom radnjom. Ta
radnja može biti i složena, odnosno može se sastojati od više podređenih
radnji. Neke izjave su posebne naredbe propisane programskim jezikom, a
neke su *izrazi*. Izraz je kombinacija podataka i radnji iz koje možemo
izračunati neku vrijednost. Programerski žargon ovdje kopira matematički
pa se kaže da se izrazi *evaluiraju* čime se izračunava vrijednost.
Izrazi se u načelu sastoje od operatora i operanada, ali sadrže i druge
koncepte kao što je to funkcija. O detaljima ovoga je riječ u sljedećem
poglavlju ([\[radnje\]](#radnje){reference-type="ref"
reference="radnje"}) koje se upravo podrobnije bavi radnjama.

Obzirom na razinu pisanja, možemo spomenuti *retke* i *blokove* kôda.
Redak teksta je prirodan način podjele kôda nekog programa, pa reci
često odgovaraju individualnim izjavama. Blok kôda je skupina redaka
koji se izvršavaju kao jedna cjelina. Koncept \"bloka\" je važniji no
što se možda na prvi pogled čini. U primjeru
[\[listing:kviz\]](#listing:kviz){reference-type="ref"
reference="listing:kviz"} smo već vidjeli kondicional gdje svaki
`if`{.python}, `elif`{.python} ili `else`{.python} dio očekuje blok kôda
u nastavku koji se smije sastojati od minimalno jednog retka, ali često
ih ima i više.

Organizacija kôda se dalje dijeli s jedne strane u datoteke (gdje
različiti programski jezici imaju različitu logiku spajanja različitih
datoteka), a s druge generalizira putem definiranja vlastitih funkcija i
vrsta podataka odnosno objektnog programiranja. Ove razine su nam za
sada previše jer za razliku od do sada opisanog nisu nužno potrebne u
svakom Python programu pa ćemo o njima kasnije, kada usvojimo osnove.

## *Notepad* na stereoidima! ili U čemu pisati Python kôd? {#softver}

Python programi su dakle obične tekstualne datoteke. Ipak, pisati ih u
aplikacijama za običan tekst koji dolaze instalirani s operativnim
sustavima (poput Notepada i sličnog softvera) je pomalo naporno. Korak
iznad su naprednije verzije aplikacija za običan tekst koje omogućavaju
lakši rad sa strukturiranim tekstom poput HTML-a ili raznih programskih
jezika. Ovakve aplikacije, između ostaloga, posebno označavaju različite
dijelove kôda koristeći se bojama i vrstom slova (podebljana i kurziv),
kao što je slučaj i u primjerima u ovom tekstu. Primjer ove vrste
softvera je [Notepad++](https://notepad-plus-plus.org/).

Ovakav softver je napredak u odnosu na najobičnije urednike teksta i
može nam poslužiti za pisanje, ali svejedno nije direktno usmjeren prema
pisanju programskog kôda. Jednu aplikaciju usmjerenu prema pisanju i
izvršavanju kôda smo upravo ukratko predstavili i riječ je o programu
IDLE koji dolazi uključen u standardnu instalaciju Pythona. Prednost
ovog programa je Python komandna linija koja je vrlo korisna za učenje i
isprobavanje. Komponenta za pisati tekst, međutim, i nije neki veliki
napredak u odnosu na Notepad budući da je IDLE kao aplikacija za pisanje
tekstualnih datoteka dosta jednostavna [^9] i ne donosi mnoge mogućnosti
koje srodan softver često posjeduje.

Na razini iznad običnih urednika teksta je softver posebno dizajniran za
pisanje kôda s kompleksnim mogućnostima koje se po potrebi mogu
uključiti, ali i ne moraju. Kao preporučene predstavnike možemo
spomenuti [Atom](https://atom.io), [VS
Code](https://code.visualstudio.com) i [Sublime
Text](https://www.sublimetext.com)[^10].

Na najkompleksnijoj razini, postoje posebna \"softverska okruženja\" za
pisanje kôda. Ovakav softver zove se ***I**ntegrated **D**evelopment
**E**nvironment* (odnosno IDE softver) i uključuje mnoge dodatne
mogućnosti poput pronalaženja najčešćih grešaka i analize kôda, pomoć
pri spajanju različitih razina (e.g. programski kôd, baze podataka i web
tehnologije), automatskog preimenovanja i preseljenja dijelova kôda i
sličnih korisnih mogućnosti. Kod IDE softvera možemo razlikovati softver
orijentiran prema više jezika i softver specijaliziran za jedan jezik.

Što se pisanja Pythona tiče, ovdje ćemo izdvojiti dva IDE rješenja. Prvo
se zove [Thonny](http://thonny.org) i posebno nam je zanimljivo jer se
radi o softveru namijenjenom za početnike koje skriva kompleksnost
tipičnu za ovu vrstu softvera. Za profesionalan razvoj, pak, može se
preporučiti [PyCharm](https://www.jetbrains.com/pycharm) IDE. Ova
aplikacija dolazi u više varijanti: edukacijska verzija, verzija za
zajednicu i profesionalna verzija. Jedino profesionalna verzija se
plaća, a za potrebe ove skripte nije potrebna jer su njene dodatne
mogućnosti uglavnom vezane za izradu weba i komunikaciju s bazama
podataka radije nego za općenito Python programiranje. Edukacijska
verzija je pojednostavljena pa čak i uključuje neke Python vježbe što ju
čini zanimljivom za početnike, ali dobro je zapamtiti da je ta verzija
namijenjena za prijelaz u profesionalnije varijante ovog softvera.

Neki popularni IDE-i za više jezika uključuju
[Eclipse](https://www.eclipse.org) i [Visual
Studio](https://www.visualstudio.com). Najproduktivnije pisanje kôda
može se ostvariti upravo kroz IDE softver. To postaje posebno značajno
za veće projekte i kada često pišemo kôd, ali ovakav softver u početku
pretpostavlja od korisnika znanje o programiranju te visoku razinu
računalne pismenosti.

Obzirom na sve ovo, u čemu pisati Python kôd? Za prve susrete je
svejedno, najbolje u poznatom vam softveru koji ne zahtijeva
prepoznavanje novih mogućnosti poput IDLE-a[^11] ili
[Notepad++](https://notepad-plus-plus.org/). Zatim se vrlo brzo dobro
prebaciti na [Thonny](http://thonny.org). Dapače, nije loše ni krenuti
iz ovog softvera jer je isti namijenjen upravo za početnike. A ako tko
krene raditi kompleksnije projekte, korisno se upoznati s punim PyCharm
IDE-om ili sličnim okruženjem.

## Možda vrijedi znati i \...

U nastavku su ukratko opisane neobavezne teme koje možda nekome pomognu.
Riječ je o softveru za programiranje, o distribucijama Pythona
usmjerenim na tzv. znanstveno računarstvo i rad s podacima te o
razlikama između Pythona 2 i Pythona 3.

### Neke korisne distribucije za Windows OS

Python se vrlo često koristi u analitičkom radu i ima velik broj
dodatnih proširenja upravo za rad s podacima. Instalirati sva proširenja
može biti naporno, posebno na Windows OS-u, pa postoje posebne
instalacije Pythona koje dolaze s dodatnim komponentama.

Pored standardne instalacije, vrlo korisna distribucija Pythona za
operativni sustav Windows je [WinPython](http://winpython.github.io).
Ova *distribucija* donosi portabilnu verziju Pythona s velikim brojem
korisnih dodatnih modula primarno usmjerenih na korištenje Pythona za
rad s podacima. Ali što je *distribucija*? To je jednostavno softverski
paket koji se sastoji od same implementacije programskog jezika (bez
koje, kao što smo već rekli, kôd nije izvršiv), dodatnih modula i
popratnog softvera poput alata za pisanje i provjeru kôda. Obzirom da se
Python vrlo često koristi u obradi podataka pa tako i znanosti, česte su
tzv. znanstvene distribucije među kojima je i WinPython, a svakako treba
spomenuti i
[Anacondu](http://https://www.continuum.io/anaconda-overview).

WinPython je namijenjen da bude portabilan pa se ne registrira u sustavu
sam od sebe, ali dolazi s konfiguracijskim alatom (WinPython control
panel) s kojim je moguće tu instalaciju registrirati u sustavu (u
glavnom izborniku: *Advanced -\> Register distribution*). Kada se
provede ta naredba, WinPython se ponaša kao da je instaliran putem
standardnog Python instalera.

### Python 2 i 3

U nastavku su ukratko opisane glavne razlike između Pythona 2 i Pythona
3 za slučaj da netko planira koristiti stariju literaturu, baš mora
programirati u Pythonu 2 ili ih jednostavno zanimaju razlike. Ako ništa
od navedenog nije slučaj, slobodno preskočite ovaj dio!

Python se kao jezik i kao softver kontinuirano razvija, te postoje
starije i novije verzije. Python kôd napisan za starije verzije je u
načelu kompatibilan s novima budući da nove verzije najčešće donose nove
alate, mogućnosti i ispravke, a ne promjene starijih mogućnosti. Jedna
od iznimaka od ovog pravila je prijelaz iz Pythona 2.x u Python 3.x.
Python 3 donosi neke promjene radi kojih kôd pisan za Python 2 često
nije validan u Pythonu 3.

U trenutku pisanja, Python 3 možemo smatrati standardom i ovaj tekst je
orijentiran na Python 3. Ipak, radi se o relativno recentnoj promjeni i
Python 2 .x (zadnja verzija je python 2.7.x) je još uvijek donekle
relevantan. Razlog sporom prelasku s 2 na 3 je primarno bio u
prebacivanju velikih Python modula na Python 3, ali danas su gotovo svi
relevantni moduli već prilagođeni za trojku. Glavni razlog spominjanju
ove razlike je u korištenju starije literature (obzirom da se radi o
programskom jeziku koji se aktivno razvija, \"starija\" literatura je
izdana prije svega nekoliko godina!) koja uglavnom donosi još uvijek
relevantne teme. Također, knjige pisane relativno nedavno će često
napominjati da je \"Python 2 još uvijek standard\" što danas možemo
ignorirati.

Kako bi čitali štivo napisano za Python 2 i adaptirali ga za Python 3,
postoji nekoliko razlika koje trebamo držati na umu:

1.  Naredba `print`{.python} je promijenila ponašanje: Python 2 izjava
    `print`{.python}  \
    `'Hello, world!'`{.python} je u Pythonu 3 postala funkcija i piše se
    `print('Hello, world!')`{.python}. Glavna razlika u sintaksi su
    zagrade, što znači da je u velikom broju print naredbi pisanih za
    Python 2 samo potrebno dodati zagrade kod riječi \"print\" (kako je
    upravo prikazano) i dobit ćemo validan Python 3.

2.  U Pythonu 3 je lakše raditi s **unicode tekstom**. Otvaranje
    tekstualnih datoteka i rad s tekstom koji sadržava ne-ASCII znakove
    (a danas bi svaki tekst trebali tretirati na ovaj način) je bolje
    usvajati kroz štivo koje se temelji na Pythonu 3.

3.  U Pythonu 2, **dijeljenje cijelih brojeva** se ponaša prema logici
    računala i programskih jezika, pa, na primjer, rezultat operacije
    `5 / 2`{.python} je 2! Po logici računala, dijeljenje dva broja će
    vratiti broj iste vrste kao i dva ulazna broja, što nije intuitivno.
    U Pythonu 3, ovaj izraz se ponaša po \"standardnoj\" matematičkoj
    logici, odnosno rezultat operacije `5 / 2`{.python} je 2.5 kako
    bismo i očekivali. Drugim riječima, u Pythonu 3 ovaj problem više
    nije relevantan i u starom štivu se može ignorirati sve dok smo
    sigurni da programiramo u Pythonu 3.

4.  Python 2 funkcija `input`{.python} je izbačena iz jezika, a Python 2
    funkcija `raw\_input`{.python} je postala nova `input`{.python}
    funkcija za Python 3. Drugim riječima, funkcija `input`{.python} se
    jednostavno ne ponaša više kao u Pythonu 2, a stara `input`{.python}
    funkcija više ne postoji.

Ostale razlike između Pythona 2 i 3 su suptilnije i početniku
nepotrebne. Za par godina i ovaj cijeli dio teksta će biti moguće
izbaciti.

[^1]: Kôd se često piše i bez naglaska, odnosno jednostavno \"kod\". U
    ovom tekstu se naglasak koristi kako bi se riječ lako razlikovala od
    čestog prijedloga \"kod\" u rečenicama poput \"Kod prikazanog kôda
    možemo uočiti \...\". Također, kôd je zbirna imenica koja označava
    skup znakova za zapis programa. Množina \"kodovi\" se ne koristi u
    ovom značenju već bi značila isto što i riječ \"šifre\" ili
    \"identifikatori\".

[^2]: Razine ćemo objasniti kasnije, ali za sada vrijedi spomenuti da
    visoka razina načelno znači da je jednostavniji za korištenje od
    jezika niske razine.

[^3]: Usput rečeno, radi se o tradicionalnom primjeru za prvi susret s
    programiranjem koji je poznatiji u svojoj engleskoj inačici *Hello,
    world!*.

[^4]: Dapače, ovo je vrlo važan napredak u povijesti razvoja suvremenih
    računala. Računala su se prije toga programirala hardverski, odnosno
    prespajanjem žica i mehaničkim sklopkama.

[^5]: Koji se najčešće skraćuje na 80 ili 120 znakova po retku.

[^6]: Ostale implementaciju uključuju, na primjer, Jython (Java
    implementacija), IronPython (.net implementacija) i PyPy
    (alternativa CPythonu orijentirana na efikasnost), ali ove nisu
    relevantne za potrebe ove skripte.

[^7]: Odnosno u znatno kraćem vremeno no što to pretpostavlja razvoj
    neke aplikacije.

[^8]: Ako koga zanima više, s osnovama se može upoznati putem [ovog
    Wikipedia
    članka](https://en.wikipedia.org/wiki/Comparison_of_programming_paradigms)

[^9]: namijenjen je da bude sastavni dio instalacije pa je tako u naravi
    minimalističan

[^10]: Od spomenute tri aplikacije, jedino se Sublime naplaćuje za
    kontinuirano korištenje, ali za testiranje je dostupan bez
    ograničenja

[^11]: IDLE = IDE + Eric Idle
# Radnje: Izjave, izrazi, operatori, funkcije i metode {#radnje}

Osnovna namjena programiranje je reći računalu što da *radi*. Ono što
nam je posebno zanimljivo u definiciji sastavnih dijelova programskog
kôda je vrlo svrsishodna podjela na radnje i podatke.

Programi se, slobodno govoreći, sastoje od *radnji* i od *podataka*.
Zapravo, obzirom da je program zapisan na računalo, cijeli zapis program
se sastoji od podataka pa na nekim razinama ova distinkcija ne
funkcionira. Dapače, velik napredak u povijesti računarstva je prelazak
na \"programe pohranjene kao podatke\". Ipak, ova podjela nam je vrlo
korisna za učenje i razumijevanje suvremenog programiranja. Radnje se
provode putem posebnih riječi koje tvore osnovu programskog jezika,
*operatora* te putem *funkcija* i *metoda*.

Većina radnji ovisi o vrsti podataka. Koje radnje možemo obavljati s
kojim podacima? Radnja `print`{.python} je univerzalna, bilo koju vrstu
podataka možemo ispisati na ekran iako katkad taj ispis korisniku neće
imati smisla. Programi su sami po sebi tekst, pa se sve može pretvoriti
u tekst. Što je s ostalim radnjama? Jasno je da možemo zbrojiti dva
broja, ali da li možemo zbrajati tekst? A tekst i broj? Probajte u
IDLE-u izvršiti sljedeće izraze: `16 + 26`{.python},
`'a' + 'b'`{.python} i `'z' + 42`{.python}. Da li su se svi izrazi
uspješno izvršili? Zašto?

Važno je dakle uočiti da radnje koje možemo provesti s nekim podacima
ovise o *vrsti tih podataka*. Upravo je u poglavljima
[\[podaci_vrste\]](#podaci_vrste){reference-type="ref"
reference="podaci_vrste"} i
[\[podaci_tekst\]](#podaci_tekst){reference-type="ref"
reference="podaci_tekst"} riječ o osnovnim vrstama podataka i radnjama s
njima jer bez tog znanja ne možemo smisleno pristupiti programiranju.
Ipak, prije no što krenemo na to, upoznajmo se s osnovnim načinima
zadavanja radnji računalu putem programskog jezika Python. Vrijedi znati
i da se ti načini mogu generalizirati i na mnoge druge programske
jezike, pa vrijede općenito za programiranje iako se detalji među
jezicima razlikuju.

## Izjave i izrazi

Najosnovniji element imperativnih jezika je *izjava* (eng. *statement*).
Izjava služi zadavanju onoga što smatramo jednom naredbom za provođenje
neke radnje. Ta naredba može biti i kompleksna, odnosno može se
sastojati od više podređenih radnji. Neke izjave su posebne riječi
propisane programskim jezikom, a neke su *izrazi*. Izraz (eng.
*expression*) je kombinacija radnji i podataka iz koje možemo izračunati
neku vrijednost. Programerski žargon ovdje kopira matematički pa se kaže
da se izrazi *evaluiraju* čime se izračunava vrijednost izraza. Izrazi
se u načelu sastoje od operatora i operanada, ali sadrže i druge
koncepte kao sastavne dijelove što je to funkcija. Pogledajmo primjere:

``` python
Izjave i izrazilisting:statements_expression \>\>\> 17 + 25 42 \>\>\> 
n = 17 + 25 \>\>\> 
if n print('broj je paran') 
else: print('broj je neparan')

broj je paran \>\>\> x = round(3.14)
```

U retku 1 vidimo jedan izraz, `17 + 25`{.python}. Ovaj izraz se sastoji
od operatora `+`{.python} te dva cijela broja kao operanada,
`17`{.python} i `25`{.python}. Ovaj izraz također tvori i jednu izjavu
koju u engleskom programskom žargonu nazivamo *expression statement*.
Redak 2 je rezultat evaluacije ovog izraza.

U retku 3 nalazi se jedna jednostavna izjava, ova izjava sadrži izraz
`17 + 25`{.python} te dodjelu rezultata ovog izraza varijabli
`n`{.python}. U ovoj izjavi prvo se evaluira izraz te se zatim rezultat
izraza dodjeljuje varijabli `n`{.python}. Dakle, nakon evaluacije izraza
s desne strane, izvršava se `n = 42`{.python}. Dodjela varijabli se ne
smatra izrazom jer nema rezultat, to je jednostavno dodjela \"imena\"
rezultatu izraza, odnosno pridruživanje rezultata izraza varijabli
`n`{.python}.

Pod jednostavne izjave smatramo one koje se logički pišu u jedan
redak[^1]. Pored jednog ili više izraza, te izjave mogu sadržavati i
posebne konstrukte poput pridruživanja vrijednosti varijabli te drugih
izjava zadanih posebnim riječima koje propisuje Python. Ovih riječi nema
puno, rijetko se mijenjaju i u Pythonu 3 uključuju: `assert`{.python},
`pass`{.python}, `del`{.python}, `return`{.python}, `yield`{.python},
`raise`{.python}, `break`{.python}, `continue`{.python},
`import`{.python}, `global`{.python} i `nonlocal`{.python}. Obzirom da
se radi o specijaliziranim \"naredbama\", s većinom ovih izjava ćemo se
upoznavati kasnije u tekstu kada nam teme i znanje dozvole da ih
kvalitetno obradimo.

U retku 4 započinje složena izjava `if`{.python} koja završava u retku
7. Rezultat izvršavanja ove izjave možemo vidjeti u retku 10. Ovu izjavu
možemo pročitati na sljedeći način: ako je n paran broj, tada na ekran
ispiši tekst \"broj je paran\", a ako nije, tada ne ekran ispiši tekst
\"broj je neparan\". U retku 4, prvo se evaluira izraz
`n \% 2`{.python}. Kao što je opisano u pregledu aritmetičkih operatora,
operator `%`{.python} vraća ostatak cjelobrojnog dijeljenja. Nakon toga
se evaluira izraz koji provjerava da li je rezultat jednak nuli, odnosno
u ovom slučaju `0 == 0`{.python}. Evaluacija tog izraza je vrijednost
`True`{.python} što rezultira time da se izvršava redak 5, a ne redak 7.
Sve navedeno tvori jedan kondicional što je pobliže opisano u poglavlju
[\[kondicionali\]](#kondicionali){reference-type="ref"
reference="kondicionali"}.

Složene izjave sadrže više komponenata i logički se pišu u više redaka.
Tako, na primjer, izjava `if`{.python} sadrži i komponentu
`else`{.python}. U Pythonu, složenih izjava ima još manje nego
jednostavnih te one služe kontroli toka (`if`{.python},
`while`{.python}, `for`{.python} i `try`{.python}), definiciji vlastitih
funkcija i klasa (`def`{.python} i `class`{.python}) te radu s
korutinama `async`{.python}. Kontrola toka se obrađuje u poglavlju
[\[kontrola_toka\]](#kontrola_toka){reference-type="ref"
reference="kontrola_toka"}, definicija funkcija i klasa u dijelu
[\[abstrakcija\]](#abstrakcija){reference-type="ref"
reference="abstrakcija"}, a korutine nisu obrađene u ovoj knjizi.

Vrijedi i napomenuti da je složene izjave relativno nepraktično
izvršavati u komandnoj liniji pa ćemo ih rijetko viđati u primjerima
koji se koriste komandnom linijom.

U retku 11 primjera
[\[listing:statements_expression\]](#listing:statements_expression){reference-type="ref"
reference="listing:statements_expression"} vidimo izjavu koja se sastoji
od poziva na funkciju `round`{.python} putem oblih zagrada unutar kojih
se nalaze parametri za tu funkciju. U ovom slučaju, funkcija prima jedan
parametar, broj `3.14`{.python}. Poziv na tu funkciju čini jedan izraz,
a rezultat se pridružuje varijabli `x`{.python}.

Sada kad razumijemo osnovne koncepte u zadavanju naredbi u programskim
jezicima, odnosno izjave i izraze, pogledajmo pobliže detalje korištenja
operatora i funkcija jer su oni najosnovniji elementi provođenja radnji
putem programskih jezika.

## Operatori

Operatori su najjednostavniji način provođenja radnji u programiranju, a
mnogi su nam poznati iz matematike (npr. `+`{.python} i `-`{.python})
čak i ako nemamo iskustva s programiranjem. Operatora ima relativno mali
broj i možemo ih svrstati u nekoliko skupina koje su opisane u nastavku.
Oni su tipično neki simbol, ali mogu biti i više simbola (poput
`!=`{.python}) ili pak riječi (poput `in`{.python} ili `and`{.python}).
Uvijek su kratki za zapisati, ali ono što ih čini operatorima je stil
njihova korištenja, a ne dužina u broju znakova. Također, operatora
postoji relativno mali broj i svi mogući operatori su unaprijed određeni
samim propisom programskog jezika. Drugim riječima, nije moguće
definirati vlastite operatore.

Operatori se pišu između dvije vrijednosti ili varijable s kojima će se
provoditi radnja kao, na primjer, u izrazu `x + y`{.python}. U tom
izrazu znak `+`{.python} je operator, a varijable `x`{.python} i
`y`{.python} su operandi, odnosno vrijednosti s kojima se izvršava
radnja naznačena operatorom.

Operande najčešće odvajamo razmacima od operatora. Striktno govoreći,
korištenje razmaka nije nužno u slučajevima kada je operator neki
poseban simboli opcionalno (na primjer, `x * y`{.python} i
`x*y`{.python} su ekvivalentni izrazi), ali kada je operator riječ, isto
ne vrijedi jer se tada isti ne može razlikovati od imena varijable. Na
primjer, `a and b`{.python} je validan izraz, ali `aandb`{.python} nije
već se referira na jednu varijablu koja se zove \"aandb\". Kao dobar
stil pisanja kôda, dakle, preporuča se uvijek stavljati razmake prije i
poslije operatora čak i kada sintaksa to ne zahtijeva.

Slijedi pregled najčešćih operatora u Pythonu. Svrha ovog dijela je dati
pregled operatora, ne podrobno objasniti korištenje svakog. Većina ovih
operatora će se detaljnije objasniti kasnije u tekstu tamo gdje to
najviše odgovara gradivu, a na ove tablice se uvijek možete vratiti kao
referencu.

### Pridruživanje vrijednosti varijabli

Daleko najčešći operator koji ćemo koristiti u kôdu je *operator za
pridruživanje vrijednosti varijabli*. To je operator `=`{.python}. Važno
je zapamtiti da ovaj operator ne provjerava jednakost (tome služi
operator `==`{.python}), već dodjeljuje vrijednosti nekoj varijabli. U
Pythonu stoji i ideja da ovime dodjeljujemo imena različitim
vrijednostima kako bi se na njih kasnije mogli referirati. To će često
biti vrijednosti koje ne znamo za vrijeme pisanja programa kao što je to
slučaj kada korisnika zatražimo unos funkcijom `input`{.python}.

``` python
Pridruživanje vrijednosti varijablilisting:pridruzivanje_vrijednosti
\>\>\> x = 16 \# pridruži vrijednost 16 novoj varijabli x \>\>\> y = 26
\# pridruži vrijednost 26 novoj varijabli y \>\>\> x + y \# rezultat
ovog izračuna nismo pridružili niti jednoj varijabli 42 \>\>\> z = x + y
\# definiraj novu varijablu z kako bi se kasnije mogao pozvati na
rezultat \>\>\> print(z) \# pozovi se na vrijednost varijable z 42
\>\>\> z = y - x \# pridruži novu vrijednost varijabli z \>\>\> print(z)
\# pozovi se na vrijednost varijable z 10

\>\>\> text = input(\"Upiši neki tekst: \") \# pridruži korisnički unos
varijabli \"text\" Upiši neki tekst: neću \>\>\> print(text) \#
varijabla text se sada referira na što god da je korisnik upisao 'neću'
```

Važno je primijetiti da su nam varijable nužne kako bi programirali.
Egzaktne vrijednosti vrlo često nisu poznate za vrijeme pisanja
programa. Na primjer, varijabla `text`{.python} se referira na rezultat
izvršavanja funkcije `input`{.python}, odnosno na koji god tekst da je
korisnik upisao. Bez korištenja te varijable ne bismo imali načina da se
pozovemo na korisnički unos koji može biti bilo što.

### Aritmetički operatori

Operatori koji su nam najpoznatiji su operatori iz osnova matematike. To
su aritmetički operatori i najčešće se koriste s brojevima, ali neki se
mogu koristiti i s drugim vrstama vrijednosti, kao što ćemo vidjeti u
idućem poglavlju. Pregled je vidljiv u tablici
[1](#tab:operatori-aritmetika){reference-type="ref"
reference="tab:operatori-aritmetika"}.

``` center
``` {#tab:operatori-aritmetika}
  **operator**        **operacija**                     **primjer**   **rezultat**
  ------------------- --------------------------------- ------------- --------------
  $\boldsymbol{+}$    zbrajanje                         $7\:+\:2$     9
  $\boldsymbol{-}$    oduzimanje                        $7\:-\:2$     5
  $\boldsymbol{*}$    množenje                          $7\:*\:2$     14
  $\boldsymbol{**}$   potenciranje                      $7\:**\:2$    49
  $\boldsymbol{/}$    dijeljenje                        $7\:/\:2$     3.5
  $\boldsymbol{//}$   cjelobrojno dijeljenje            $7\://\:2$    2
  $\boldsymbol{\%}$   ostatak cjelobrojnog dijeljenja   $7\:\%\:2$    1

  : Aritmetički operatori
```
```

Zanimljivost kod aritmetičkih operatora je da se svi mogu spojiti s
operatorom za pridruživanje vrijednosti varijabli (tj. `=`{.python})
kako bi se skratilo pisanje izraza poput `x = x + 1`{.python} u
`x += 1`{.python}. Drugim riječima, možemo u isto vrijeme odraditi
aritmetičku operaciju i rezultat pridružiti varijabli. Ovo je najlakše
objasniti primjerom
[\[listing:dodjeljivanje_aritmetika\]](#listing:dodjeljivanje_aritmetika){reference-type="ref"
reference="listing:dodjeljivanje_aritmetika"}.

``` python
Skraćeno izvršavanje aritmetičkih operacija i pridruživanja
varijablilisting:dodjeljivanje_aritmetika \>\>\> x = 1 \>\>\> x = x + 2
\# zbroji x i 2 pa pridruži novu vrijednost varijabli x \>\>\> print(x)
\# x sada ima novu vrijednost, nije više 1 3 \>\>\> x += 2 \# isto što i
x = x + 2 samo kraće za pisati \>\>\> print(x) 5 \>\>\> x \*= 2 \# isto
što i x = x \* 2 samo kraće za pisati \>\>\> print(x) 10 \>\>\> x /= 2
\# isto što i x = x / 2 \>\>\> print(x) 5.0
```

### Operatori za usporedbu

Osim aritmetičkih operacija, vrijednosti često uspoređujemo. Sve
vrijednosti možemo međusobno provjeriti da su jednake koristeći se
operatorom `==`{.python} ili nejednake koristeći se operatorom
`!=`{.python}. Kod vrijednosti koje podržavaju sortiranje možemo još i
provjeravati da li su veće ili manje od drugih vrijednosti. Operatore za
usporedbu možemo vidjeti na tablici
[2](#tab:operatori-usporedba){reference-type="ref"
reference="tab:operatori-usporedba"}.

``` center
``` {#tab:operatori-usporedba}
  **operator**          **operacija**       **primjer**    **rezultat**
  --------------------- ------------------- -------------- --------------
  $\boldsymbol{==}$     jednako             $7\:==\:2$     False
  $\boldsymbol{!\!=}$   nejednako           $7\:!\!=\:2$   True
  $\boldsymbol{<}$      manje               $7\:<\:2$      True
  $\boldsymbol{<\!=}$   manje ili jednako   $7\:<\!=\:2$   True
  $\boldsymbol{>}$      veće                $7\:>\:2$      False
  $\boldsymbol{>\!=}$   veće ili jednako    $7\:>\!=\:2$   False

  : Operatori za usporedbu
```
```

### Logički operatori

Različite operacije je često potrebno i logički povezivati. Na primjer
provjeravati da je više uvjeta zadovoljeno ili da je barem jedan od
uvjeta zadovoljen. Tome služe logički operatori `and`{.python},
`or`{.python} i `not`{.python} prikazani na tablici
[3](#tab:operatori-bool){reference-type="ref"
reference="tab:operatori-bool"}. Ovi operatori zajedno s operatorima za
usporedbu imaju posebno značajnu ulogu kod kondicionala, odnosno *if
\... then \... else* konstrukcija.

``` center
``` {#tab:operatori-bool}
  **operator**   **operacija**       **primjer**            **rezultat**
  -------------- ------------------- ---------------------- --------------
  **and**        logičko i           $7 > 2$ and $7 < 10$   True
  **or**         logičko ili         $7 < 2$ or $7 < 10$    True
  **not**        logička inverzija   not $7\:>\:2$          False

  : Logički operatori
```
```

### Operatori za provjeru članstva

Često su korisni i operatori za provjeru članstva. Ovo su dva operatora
koja nam govore da li neki tekst ili struktura podataka sadrži određeni
element. Uloga ovih operatora će nam postati puno jasnija kada naučimo
strukture podataka, ali za sada primjere možemo pokazati koristeći se
tekstom. Operatori za provjeru članstva su prikazani na tablici
[4](#tab:operatori-clanstvo){reference-type="ref"
reference="tab:operatori-clanstvo"}.

``` center
``` {#tab:operatori-clanstvo}
  **operator**   **operacija**   **primjer**            **rezultat**
  -------------- --------------- ---------------------- --------------
  **in**         sadrži          \"a\" in \"abc\"       True
  **not in**     ne sadrži       \"a\" not in \"abc\"   False

  : Operatori za provjeru članstva
```
```

### Operatori za provjeru identiteta

Uz provjeravanje jednakosti postoje i operatori za provjeru identiteta
koji su vidljivi na tablici
[5](#tab:operatori-identitet){reference-type="ref"
reference="tab:operatori-identitet"}. Važno je primijetiti da ovi
operatori nisu isto što i provjera jednakosti. Provjera jednakosti
provjerava da li se dvije vrijednosti mogu smatrati ekvivalentnima
odnosno "istima", a provjera identiteta provjerava da li se radi o istoj
vrijednosti u memoriji računala.

``` center
``` {#tab:operatori-identitet}
  **operator**   **operacija**         **primjer**     **rezultat**
  -------------- --------------------- --------------- --------------
  **is**         je isti objekt        True is 1       False
  **is not**     ne nije isti objekt   True is not 1   True

  : Operatori za provjeru identiteta
```
```

Ovo će početi imati više smisla kada dođemo do objektnog programiranja,
ali za sada možemo upotrebu prikazati sljedećim primjerom:

``` python
Provjera jednakosti i operator islisting:operator_is \>\>\> True == 1 \#
True se može smatrati jednakom vrijednosti 1 True \>\>\> True is 1 \#
True nije posve ista vrijednost u memoriji kao i 1 False
```

### Prioritet izvršavanja operacija

U ranijim primjerima prikazivali smo samo izraze koji se koriste jednim
operatorom. Što se međutim zbiva kada u istom izrazu koristimo više
operatora? Na primjer, koliko je `2 + 2 * 3`{.python}? Kako bismo
izračunali taj izraz potreban nam je koncept prioriteta operatora.
Pogledajmo primjer.

``` python
Provjera jednakosti i operator islisting:operator_precedence \>\>\> 2 +
2 \* 3 \# prvo se množi a onda zbraja 8 \>\>\> (2 + 2) \* 3 \# prvo se
evaluira operacija u zagradama, a tek onda množi 12
```

Kao što znamo iz matematike, postoji zadani redoslijed izvršavanja
operatora. Operacije prema prioritetu operatora. U prethodnom primjeru,
operator `*`{.python} ima veći prioritet od operatora `+`{.python} pa je
prva operacija koja se izvršava operacija `2 * 3`{.python}. Ukoliko
želimo promijeniti taj redoslijed, moramo koristiti zagrade oko jedne
operacije (dakle jednog operatora i njegovih operanada). Vrijedi
zapamtiti da zagrade nisu nikad greška. Izraz `2 + 2 * 3`{.python} isti
je kao i izraz `2 + (2 * 3)`{.python}. Drugim riječima, kada nismo
sigurni u zadani prioritet operatora, uvijek možemo koristiti zagrade
kako bi se osigurali u redoslijed izvršavanja operacija.

Dok se prikazani primjer koristi konceptima koji su nam najvjerojatnije
poznati iz matematike, u programskim jezicima to često nije tako
jednostavno. Prvi razlog je zato što se radnje ne moraju ponašati po
pravilima iz matematike (iako je to najčešći slučaj), a drugi to što u
programskim jezicima postoje operatori koji nam nisu poznati iz
matematike.

U svakom slučaju, za Python vrijedi kako je navedeno u sljedećem popisu.
Operatori zapisani na vrhu popisa imaju najveći prioritet.

1.  izrazi u zagradama

2.  izvršavanje funkcija

3.  potenciranje (`**`{.python})

4.  pretvaranje brojeva u negativne (`-x`{.python})

5.  množenje, dijeljenje, cjelobrojno dijeljenje, ostatak
    (`*, /, //, %`{.python})

6.  zbrajanje i oduzimanje (`+, -`{.python})

7.  provjera članstva, provjera identiteta i
    usporedbe(`in, not in, is, is not, <, <=, >, >=, !=, ==`{.python})

8.  booleovi operatori (`not, and, or`{.python})

Situacija je zapravo nešto kompleksnija, ali ovdje se navode samo
koncepti s kojima smo već upoznati. Potpunu tablicu koja definira
redoslijed izvršavanja možete pronaći u službenoj
[dokumentaciji](https://docs.python.org/3/reference/expressions.html#operator-precedence).

## Funkcije i metode

*Funkcije* su jedan od osnovnih građevnih blokova u suvremenom
programiranju i služe provođenju onoga što percipiramo kao \"jednu
radnju\" (iako ta radnja može interno prilično kompleksna).

Operatora, dakle, ima relativno mali broj i obavljaju neke osnovne
radnje. Drugi način provođenja radnji u programiranju je funkcijama.
Funkcija ima vrlo velik broj i obavljaju najrazličitije radnje koje su
najčešće znantno kompleksnije od onih koje obavljaju operatori. Već smo
vidjeli funkciju koja ispisuje tekst na ekran (`print`{.python}) i koja
pita korisnika za unos (`input`{.python}). Postoje i mnoge druge
funkcije, za sortiranje, zbrajanje svih brojeva u nekom popisu, pristup
tekstualnim datotekama, kopiranje i brisanje datoteka, slanje
elektroničke pošte i tako dalje. Python s verzijom 3.8 ima 69 ugrađenih
funkcija vrlo različitih namjena. Ugrađene funkcije su one koje dolaze
kao sastavni dio samog jezika i s mnogima od njih ćemo se upoznati
kasnije u ovom tekstu, a cijeli popis možete pronaći u službenoj
[dokumentaciji](https://docs.python.org/3/library/functions.html).

Uz ugrađene funkcije, Python dolazi s velikom \"knjižnicom\" proširenja
(eng. *add-on* ili *plugin*). Ta proširenja u Pythonu nazivamo
*modulima* i detaljnije se obrađuju u poglavlju
[\[moduli\]](#moduli){reference-type="ref" reference="moduli"}. Za sada
nam je važno da moduli donose mnoge dodatne funkcije za matematiku, za
rad s različitim vrstama podataka, datotekama, sustavom ili pak slanje
elektroničke pošte, da spomenemo samo neke mogućnosti. Osim modula koji
dolaze s Pythonom, možemo i preuzeti velik broj modula koje je razvila
zajednica. Također, ne samo da možemo definirati vlastite funkcije[^2]
nego bez toga nećemo daleko dogurati s programiranjem. Funkcija dakle
teoretski ima beskonačno.

Za sada nam je važno naučiti neke temeljne koncepte vezane uz funkcije,
a kroz ovaj tekst ćemo se s mnogima i pobliže upoznati gdje to bude
svrsishodno. Kada se upoznamo s osnovama, naučiti ćemo i definirati
vlastite funkcije.

Svaka funkcija:

1.  Prima 0 ili više ulaznih vrijednosti, odnosno parametara (koji se
    često nazivaju i argumenti).

2.  Provodi neke radnje (na temelju ulaznih vrijednosti ako postoje).

3.  Vraća neku vrijednost. Ako rezultat nije relevantan vraća vrijednost
    `None`{.python}[^3]

Što je dakle funkcija u programskim jezicima? Ulazne vrijednosti za
funkciju zovemo *parametri* ili *argumenti*. Python interno koristi
engleski izraz *argument*, ali mi ćemo koristiti hrvatski izraz
*parametar* jer nam je jeziku prirodniji.

Funkcija može i ne mora primiti parametre, zatim se u funkciji dešavaju
određene radnje (npr. zbrajaju se ulazni parametri ili se ispisuju na
ekran) i na kraju funkcija vraća neku vrijednost. Funkcija koja zbraja
ulazne parametre vraća njihov zbroj kao rezultat. Kod te funkcije, kao i
kod većine, rezultat je relevantan i uopće razlog izvršavanja funkcije.
Kod funkcije `print`{.python}, funkcija ispisuje na ekran, a vraća
vrijednost `None`{.python}. Funkcije čija povratna vrijednost nije
relevantna vraćaju vrijednost `None`{.python}. U svakom slučaju,
funkcije u Pythonu uvijek imaju povratnu vrijednost.

Parametri se pišu u oble zagrade koje kod funkcija i metoda imaju
posebno značenje i označavaju naredbu[^4] za izvršavanje funkcije. Čak i
kada funkcija ne prima nikakve parametre, oble zagrade su potrebne kako
bi se funkcija izvršila. U engleskom žargonu često kažemo i da se
funkcija \"poziva\" (eng. *call*), a to rješenje koristi i Python pa
ćemo često naići na jezično rješenje da treba \"pozvati funkciju\",
odnosno u engleskoj literaturi \"*call a function*\", što znači isto što
i \"izvršiti funkciju\". Pogledajmo primjer
[\[listing:funkcija_izvrsavanje\]](#listing:funkcija_izvrsavanje){reference-type="ref"
reference="listing:funkcija_izvrsavanje"}.

Kao što vidimo u zadnjem slučaju, kada pokušamo oblim zagradama izvršiti
nešto što nije funkcija dobivamo grešku
`TypeError: 'int' object is not callable`{.python}. U slobodnom
prijevodu, greška u vrsti podataka: objekt vrste cijeli broj se ne može
pozvati, odnosno nije izvršiv. Navedena greška demonstrira upotrebu
ranije opisane terminologije.

``` important
Izvršavanje funkcija Funkcije se pozivaju oblim zagradama. Oble zagrade
nakon riječi naznačuju da se neki kôd poziva. Na primjer,
`print`{.python} se jednostavno referira na tu funkciju i ne izvršava
je. `print()`{.python} izvršava tu funkciju.
```

### Pozivanje i parametri

Funkcije i metode, dakle, provode radnje na temelju ulaznih parametara.
Ponekad primaju i nula parametara, ali to je rjeđi i najjednostavniji
slučaj. Kako se parametri šalju funkcijama kad ih je više od jedan?
Postoje dva načina: pozicijski ili po imenu. Do sad smo koristili samo
pozicijski pristup i slali samo jedan parametar. Pogledajmo funkciju
`round`{.python} koja zaokružuje broj na cijeli ili na određen broj
decimala kao primjer funkcije s dva parametra.

``` python
Obvezni i opcionalni parametrilisting:parametri_obveznost \>\>\> pi =
3.1416 \>\>\> round(pi) \# obavezan parametar, što se zaokružuje, bez
toga radnja nema smisla 3 \>\>\> round(pi, 2) \# drugi parametar je
opcionalan, na koliko decimala 3.14
```

Funkcija `round`{.python}, dakle, uzima jedan obvezan i jedan opcionalan
parametar. U primjeru
[\[listing:parametri_obveznost\]](#listing:parametri_obveznost){reference-type="ref"
reference="listing:parametri_obveznost"} smo parametre definirali
pozicijski. Prvi parametar je broj koji se zaokružuje, a drugi broj
decimala na koji će se zakruživati. Različite funkcije imaju posve
različite parametre i njihov broj ovisi o tome što funkcija radi. Kako
saznati parametre neke funkcije? Možemo čitati *online* dokumentaciju
ili pak iskoristiti ugrađenu funkciju `help`{.python}.

### Interna dokumentacija i funkcija help

Ukoliko u Pythonu potražimo pomoć za funkciju `round`{.python} dobit
ćemo sljedeći ispis:

``` python
Pomoć za funkciju roundlisting:help_round \>\>\> help(round) \"\"\" Help
on built-in function round in module builtins:

round(number, ndigits=None) Round a number to a given precision in
decimal digits.

The return value is an integer if ndigits is omitted or None. Otherwise
the return value has the same type as the number. ndigits may be
negative. \"\"\"
```

Primijetite razliku između `help(round)`{.python} i
`help(round())`{.python}. U prvom slučaju ne izvršavamo funkciju
`round`{.python} već se na nju referiramo pa ju funkcija `help`{.python}
prima kao parametar. U drugom slučaju izvršavamo funkciju
`round`{.python} pa će funkcija `help`{.python} primiti rezultat
izvršavanja te funkcije kao parametar, što nije ono što želimo postići.

Redak teksta koji nam opisuje koje parametre prima ova funkcija je
`round(number, ndigits=None)`{.python}. Nju valja čitati ovako:
\"Funkcija round prima jedan obavezan parametar koji se zove
`number`{.python} te jedan opcionalan parametar `ndigits`{.python}\".
Parametar `ndigits`{.python} je opcionalan zato jer mu je već pridružena
vrijednost `None`{.python}. Svi parametri kojima je već pridružena neka
vrijednost su opcionalni i moramo ih definirati samo ukoliko želimo
promijeniti unaprijed zadanu vrijednost.

Parametre možemo jednostavno poslati pozicijski u ovu metodu, na prvom
mjestu nalazi se *number*, a na drugom, opcionalno, *ndigits*. Vidimo da
svaki parametar uz poziciju ima i svoje ime. Ta imena možemo koristiti
prilikom pozivanja funkcije kako bi parametre definirali putem imena, a
ne pozicije. Pogledajmo primjer:

``` python
Pozicijski i imenovani
parametrilisting:pozicijski_i\_imenovani_parametri \>\>\> n = 3.142
\>\>\> round(number=n) \# bilo koji parametar možemo i imenovati 3
\>\>\> round(number=n, ndigits=2) \# sintaksa je ista pridruživanju
vrijednosti varijabli 3.14 \>\>\> round(ndigits=2, number=n) \# kada su
parametri imenovani, pozicija je nebitna 3.14
```

Imenovani parametri su korisni kad želimo preskočiti neki opcionalan
parametar i kad funkcije koje koristimo imaju velik broj parametara i
želimo osigurati da im nismo zamijenili redoslijed. Korištenje
imenovanih parametara često i poboljšava čitljivost kôda, pogotovo kod
funkcija koje primaju velik broj ulaznih vrijednosti. Postoje i funkcije
koje primaju varijabilan broj parametara i kod kojih moramo koristiti
imenovane parametre kako bi postigli određenu funkcionalnost. Kao
kompleksniji primjer možemo prikazati naredbu `print`{.python} koju smo
do sada koristili samo u najosnovnijem obliku.

``` python
Pomoć za funkciju printlisting:help_print \>\>\> help(print) Help on
built-in function print in module builtins:

print(\...) print(value, \..., sep=' ', end='', file=sys.stdout,
flush=False)

Prints the values to a stream, or to sys.stdout by default. Optional
keyword arguments: file: a file-like object (stream); defaults to the
current sys.stdout. sep: string inserted between values, default a
space. end: string appended after the last value, default a newline.
flush: whether to forcibly flush the stream.
```

Usredotočimo se za sada samo na parametre funkcije `print`{.python}.
Vidimo novi koncept. Prvi parametar se zove `value`{.python}, a nakon
njega dolazi `...`{.python}. To znači da možemo poslati bilo koji broj
vrijednosti kao parametre za `value`{.python}. Sve ove vrijednosti će se
ispisati na ekran razdvojene razmakom, osim ako nismo naredili
drugačije. Pogledajmo primjer:

``` python
Funkcija print s više parametaralisting:print_vise_parametara \>\>\>
print('a', 'b', 'c') a b c
```

Funkcija `print`{.python} je u liniji 1 primila tri vrijednosti koje će
ispisati, `'a', 'b'`{.python} i `'c'`{.python}. Sve tri vrijednosti su
ispisane razdvojene razmakom, a na kraju je ispisan znak za prelazak u
novi redak. Ove mogućnosti možemo kontrolirati parametrom
`sep`{.python}, koji definira znak koji razdvaja vrijednosti, i
parametrom `end`{.python} koji definira znak koji s kojim se završava
ispis. Obzirom da se sve vrijednosti koje pošaljemo pozicijski ispisuju
razdvojene znakovima koje definira `sep`{.python} i završavaju znakovima
koje definira `end`{.python}, kako poslati te parametre? Koristeći se
imenima. Pogledajmo primjer.

``` python
Funkcija print s više parametara i definiranim sep i
endlisting:print_sep_end \>\>\> print('a', 'b', 'c', sep=' - ', end='
\...') a - b - c \... \>\>\> print('a', 'b', 'c', sep='') a b c
```

U prikazanom primjeru, `'\n'`{.python} se referira na znak za novi
redak, što je pobliže opisano u poglavlju o tekstu. Redak 1 prikazuje
naredbu koja ispisuje tri vrijednosti i spaja ih sa znakovima razmak,
crtica, razmak, a završava ispis sa znakovima razmak, tri točkice i
novim retkom. Redak 3 prikazuje naredbu koja koristi znak za novi redak
kao `sep`{.python} pa se svaka vrijednost ispisuje u novom retku.

### Metode

*Metode* su posebna vrsta funkcija. To su funkcije vezane za vrste
vrijednosti i uvijek rade nešto s vrijednošću za koju su vezane.
Pogledajmo razliku između funkcije `print`{.python}, i metode
`upper`{.python} koju posjeduju vrijednosti vrste tekst, odnosno u
Python terminima `str`{.python}, i koja pretvara sva mala slova u
velika.

U načelu, ugrađene funkcije implementiraju radnje koje se mogu provoditi
s više vrsta vrijednosti. Na primjer `print(t)`{.python} ispisuje
tekstualni prikaz varijable `t`{.python} bez obzira na vrstu vrijednosti
koja je toj varijabli pridružena. Hipotetska funkcija
`upper(t)`{.python} bi dozvoljavala varijabli `t`{.python} da bude samo
tekst pa ju je logičnije vezati uz samu vrijednost:
`t.upper()`{.python}. `t.upper(t)`{.python} bi bilo u ovom slučaju
redundantno pisati pa se pretpostavlja da metoda prima vrijednost prije
točke kao prvi parametar. Na taj način je funkcija `upper`{.python}
dostupna samo kroz tekstualne vrijednosti što pogoduje organizaciji kôda
jer ju smješta u jedini kontekst u kojem je iskoristiva. Poziv
`x.upper()`{.python} javlja grešku
`AttributeError: 'int' object has no attribute 'upper'`{.python} jer
objekti vrste `int`{.python} nemaju \"mogućnost\" odnosno metodu
`upper`{.python}: to kod brojeva jednostavno nema smisla jer se veže uz
koncept promjene veličine slova.

``` important
Metode Metode su funkcije koje su vezane uz određenu vrstu vrijednosti i
implicitno primaju tu vrijednost kao prvi parametar.
```

[^1]: Termin \"logički pišu\" se koristi zato jer je jedan redak moguće
    podijeliti u više koristeći se posebnom sintaksom, kao i više redaka
    spojiti u jedan. Ovo se međutim smatra lošom praksom u pisanju kôda.

[^2]: Kao i vrste podataka, metode i module, ali ne i operatore.

[^3]: Dok prve dvije točke stoje za sve programske jezike, treća nije
    univerzalna.

[^4]: koja je tehnički gledano operator

# Podaci: Vrijednosti i njihove vrste

Računalo može provoditi radnje samo s *podacima*. Broj 42 je podatak,
kao i 3.14. Tekst "Život, svemir i sve!" je podatak. Ove podatke ne
percipiramo kao zbirke podataka pa ih uobičajeno jednostavno zovemo
*vrijednosti*. Ne treba puno razmišljati kako bi shvatili da postoji
beskonačno različitih vrijednosti. Također, sjetimo se sljedećeg
programa:

``` python
Nepoznati podatak za vrijeme izvršavanja programalisting:
nepoznati_podatak text = input("Unesi tekst i pritisni <enter>: ") 
print(text) 
input("Pritisni <enter> za kraj")
```

U programu prikazanom u primjeru
<a href="#listing:nepoznati_podatak" data-reference-type="ref"
data-reference="listing:nepoznati_podatak">[listing:nepoznati_podatak]</a>,
vrijednost varijable `text` je prilikom pisanja programa nepoznata. To
je što god da je korisnik koji je pokrenuo program unio kad ga je
računalo to zatražilo. Drugim riječima, ne samo da postoji beskonačno
različitih vrijednosti već iste najčešće nisu poznate prilikom pisanja
programa. Ovo mora biti tako: kada bi sve vrijednosti bile unaprijed
zapisane u neki program, taj program bi uvijek radio istu stvar!

U uvodu smo već uočili da postoje različite vrste vrijednosti. Čak i
izvan sfere programiranja razlikujemo "brojke i slova". Osnovne vrste
vrijednosti u kontekstu programiranja su **cijeli** i **decimalni
brojevi**, **tekst**, **booleove vrijednosti** i vrijednost
**None**[^1]. Ostale vrste vrijednosti možemo stvoriti koristeći se ovim
osnovnim vrstama i strukturama podataka (o kojima će biti riječ
kasnije). Na primjer, datum se sastoji od tri cijela broja, a možemo ga
ljepše prikazati ukoliko ga pretvorimo u tekst sa znakovima ".", "-" ili
"/" između znamenki. Ali čak i u tom slučaju, datum je tri broja koji
ima posebna pravila prikaza kao tekst i posebna pravila za zbrajanje i
oduzimanje na razini brojeva. Sve vrste vrijednosti koje nam dakle
trebaju za rad s datumima su cijeli brojevi i tekst za potrebe prikaza.
Osnovne vrste vrijednosti su dakle temeljne za programiranje i zapis
strukturiranih podataka kao i stvaranje kompleksnijih vrsta vrijednost
pa krenimo s upoznavanjem istih.

U ovom dijelu ćemo objasniti atomske vrijednosti, odnosno cijele i
decimalne brojeve, booleove vrijednosti i vrijednost `None`. To su one
vrijednosti koje ne možemo raščlaniti na sastavne dijelove. Booleove
vrijednosti (`True` i `False`) i vrijednost `None` su uistinu
jednostavne vrijednosti i neće nam trebati puno da opišemo rad s njima.
Brojevi su znatno kompleksnija tema, ali rad s njima nam je već bar
donekle poznat iz matematike. S druge strane, tekst je vrlo važno
podrobnije objasniti jer je znatno kompleksnija tvorevina od ostalih
osnovnih vrsta vrijednosti. Također, rad s računalnim tekstom nam nije
toliko poznat iz drugih područja i specifičan je za programiranje. Za
razliku od brojeva, tekst slijedi druga pravila na papiru i na računalu
(što uključuje i rad u softveru koji imitira papir, kao što je npr.
*Microsoft Word*) pa su nam pristup radu i mogućnosti manje poznate.
Naravno, tekst je od vrlo velikog značaja za programiranje, World Wide
Web i razmjenu podataka. Radi svega navedenog, tekstu će se posvetiti
zasebno poglavlje.

## Brojevi

Postoje više vrsta brojeva, a one koje daleko najčešće koristimo su
cijeli i decimalni brojevi. Ove vrste vrijednosti se u Pythonu nazivaju
`int` i `float` što su relativno standardni nazivi za ove vrste
vrijednosti u programiranju i bazama podataka. Riječ `int` je skraćeni
oblik engleske riječi *integer* koja doslovno znači cijeli broj. Riječ
`float` dolazi od engleskog izraza *floating point number* i ovaj
koncept je malo problematičniji jer se ponešto razlikuje od decimalnih
brojeva koji su nam poznati iz matematike s ploče u školi. Takve brojeve
možemo shvatiti kao računalnu aproksimaciju decimalnih brojeva koji
omogućuju varijaciju između raspona i preciznosti. Ipak, u daleko
najvećem broju problema koje rješavamo programiranjem, `float` brojeve
možemo shvatiti kao decimalne, a razlika nam je jedino važna ukoliko
zahtijevamo preciznost na jako velikom broju decimala. Također, za
razliku od jezika niže razine i baza podataka, Python nema više vrsta
cijelih i decimalnih brojeva koje podržavaju različite minimalne i
maksimalne veličine ili broj decimala pa u ovu temu nećemo ulaziti jer
je nepotrebna za osnove programiranja i većinu programa napisanih u
Pythonu[^2].

S brojevima se najčešće radi putem aritmetičkih operatora. Slijede neki
primjeri iz interaktivnog rada s Pythonom s kojima smo se već upoznali
kod objašnjenja operatora, ali vrijedi ponoviti. Obzirom da su brojevi i
operacije s brojevima došle "s papira", najčešće radnje s brojevima
provodimo upravo kroz operatore jer nam je tako najprirodnije i najkraće
pisati.

``` python

>>> 12 + 8 20 
>>> 12 - 8 4 
>>> 12 * 8 96 
>>> 12 ** 8 # potenciranje, 12 na 8 429981696 
>>> 12 / 8 1.5 
>>> 12 // 8 # cjelobrojno dijeljenje 1 
>>> 12 4
```

Operatore nećemo podrobnije ovdje opisivati jer su detaljnije prikazani
u poglavlju <a href="#radnje" data-reference-type="ref"
data-reference="radnje">[radnje]</a>. Osim standardnih matematičkih
operacija s operatorima, Python ima ugrađene dodatne matematičke
funkcije i konstante mnoge od kojih su dostupne kroz *standardan modul*
`math`. "Modul" je proširenje mogućnosti Pythona i možemo ga jednostavno
shvatiti kao *plug-in*. "Standardan" modul znači da se radi o modulu
koji dolazi s Pythonom i uvijek je dostupan, odnosno koji ne zahtijeva
dodatan korak instalacije modula. U primjeru
<a href="#listing:brojevi_operacije2" data-reference-type="ref"
data-reference="listing:brojevi_operacije2">[listing:brojevi_operacije2]</a>
koristimo dodatne funkcije koje donosi modul `math`, a zadržimo se za
sada na brojevima, dok će o modulima biti riječ u poglavlju
<a href="#moduli" data-reference-type="ref"
data-reference="moduli">[moduli]</a>:

``` python

>>> round(3.1416) # funkcija za zaokruživanje je ugrađena u Python 3 
>>> round(3.1416, 2) 3.14 
>>> import math # koristiti ćemo modul math pa ga moramo uključiti 
>>> math.ceil(3.1416) # zaokruži na prvi viši cijeli broj, obratno je "floor" 4 
>>> math.sqrt(625) # drugi korijen 25.0 
>>> math.sin(45) # sinus; uključene su i ostale trigonometrijske funkcije 0.8509035245341184 
>>> math.pi 3.141592653589793 # konstanta \pi
```

Modul `math` donosi i mnoge druge mogućnosti, a postoje i kompleksna
proširenja Pythona orijentirana na rad s brojevima bilo da se radi o
naprednijoj matematici ili specijalizacijama poput statistike. Obzirom
da se ovdje u načelu radi ili o poznatim nam matematičkim postupcima i
funkcijama (u slučaju modula `math`, to su mogućnosti poput korjenovanja
i trigonometrijskih funkcija) ili pak o naprednim područjima nevezanim
za osnove programiranja (npr. statistika, strojno učenje) no o novim
konceptima ovdje možemo stati s prikazom rada s brojevima i prikazati
druge vrste vrijednosti koje su specifičnije za programiranje.

## Booleove vrijednosti

Različitih brojeva i tekstualnih nizova ima beskonačno, ali samo su
dvije booleove vrijednosti i označavaju "da" i "ne", odnosno istinu i
neistinu, postoji i ne postoji, ima struje i nema struje, 1 i 0 ... Ove
dvije vrijednosti su neobično važne za računarstvo jer su to binarne
znamenke koje u kontekstu suvremenih digitalnih elektroničkih računala
tvore binarni brojevni sustav putem kojeg kodiramo bilo koje podatke za
potrebe interakcije s računalnim hardverom odnosno za potrebe pohrane u
memoriju i izvršavanje instrukcija. U programiranju, ove dvije
vrijednosti imaju i širu logičku upotrebu, kao što ćemo uskoro vidjeti u
primjerima. U Pythonu ih nazivamo `True` i `False`.

### Usporedba brojeva

Do bool vrijednosti u programima često dolazimo posebnim operatorima i
metodama za usporedbu. Ovakvi operatori i metode služe provjeri
istinitosti neke tvrdnje odnosno odgovaraju na da-ne pitanja. Pogledajmo
prvo najčešće operatore za usporedbu brojeva:

``` python

>>> x = 2 # ovo je pridruživanje varijabli, a ne provjera jednakosti 
>>> y = 3 
>>> x < y # x je manje od y True 
>>> x >= y # x je veće ili jednako y False 
>>> x == y # x je jednako y False 
>>> x != y # x je različit od y True 
>>> x + y == 5 # rezultat izraza "x + y" iznosi 5 True 
>>> x + (y == 5) # što se ovdje dogodilo ??? 2
```

Neke detalje smo spomenuli već u uvodu i podrobnije objasnili u
poglavlju <a href="#radnje" data-reference-type="ref"
data-reference="radnje">[radnje]</a>, ali vrijedi ponoviti. Primijetimo
operator `==` u izrazu `x == y`. Rekli smo da operator `=` znači
pridruživanje vrijednosti varijabli. Bilo bi višeznačno koristiti isti
znak za operator koji provjerava jednakost pa za to postoji poseban
operator: `==`.

Na primjer, u matematici:

``` python
Znak "=" u matematicilisting:bool2 x = 1 # (pridruživanje: neka x bude 1) x + 1 = 2 # (tvrdnja jednakosti: x + 1 je jednako 2)
```

U Pythonu:

``` python

>>> x = 1 # pridruživanje: "neka x bude 1", ovo nije izraz pa nema rezultata 
>>> x + 1 == 2 # provjera jednakosti: "da li se izraz "x + 1" evaluira u 2" True
```

A kako to da je izraz `x + y == 5` različit od izraza `x + (y == 5)`?
Prvi dio odgovora leži u redoslijedu izvršavanja operacija. Kao što je
opisano u poglavlju <a href="#radnje" data-reference-type="ref"
data-reference="radnje">[radnje]</a>, prvo se provode aritmetičke
operacije pa zatim operacije usporedbe. U izrazu `x + y == 5` prvo se
provodi zbrajanje pa tek zatim usporedba. Taj izraz je, dakle, isto što
i `(x + y) == 5`. U izrazu `x + (y == 5)` smo zagradama promijenili
redoslijed izvršavanja operacija: prvo se provodi usporedba `y == 5`
koja vraća rezultat `False`. Zatim se provodi zbrajanje, a u ovom
slučaju to je izraz `x + False`. False je ekvivalentan vrijednosti 0 pa
je taj izraz isto što i `x + 0` te iznosi vrijednosti varijable `x`,
odnosno `2`. Za redoslijed izvršavanja operatora znamo kako iz
prijašnjeg poglavlja tako i iz osnova matematike. Za vrijednosti True i
False vrijedi zapamtiti da su ekvivalentne vrijednostima `1` i `0` i da
mnogi jezici dopuštaju aritmetičke operacije s njima. Navedeno je
pobliže prikazano u primjeru
<a href="#listing:bool_je_broj" data-reference-type="ref"
data-reference="listing:bool_je_broj">[listing:bool_je_broj]</a>.

``` python

>>> n = 42 
>>> n + True # True je jednak 1 43 
>>> n - True 41 
>>> n + False # False je jednak 0 42 
>>> n * False 0 
>>> True == 1 True 
>>> True is 1 # ali True je u memoriji različita vrijednost od 1 False 
>>> True is not 1 True
```

### Usporedba drugih vrsta vrijednosti

Situacije koje provjeravamo s očekivanim odgovorima "da" i "ne" ovise
najviše o vrstama vrijednosti. Za brojeve se odnose na matematičke
koncepte (veće, manje, jednako ), ali što je na primjer s tekstom? Tekst
podržava mnoštvo tvrdnji koje možemo provjeravati, pogledajmo neke od
njih:

``` python

>>> a = ’nešto’ 
>>> b = ’nešto drugo’ 
>>> a == b # većina osnovnih vrsti podataka dopušta provjeru jednakosti False 
>>> ’d’ in a # da li se znak ’d’ nalazi u tekstu a False 
>>> ’dr’ in b # da li se znakovi ’drugo’ nalaze u tekstu b True 
>>> b.startswith(a) # posebne provjere se često provode posebnim metodama za vrste vrijednosti True 
>>> s = ’122’ 
>>> s.isdigit() # da li se tekst sastoji samo od brojeva? True 
>>> s = ’abc’ # da li se tekst sastoji samo od slova? 
>>> s.isalpha() True 
>>> s = ’abc4’ 
>>> s.isalpha() False
```

### Koje vrijednosti postoje?

Također, bilo koju vrijednost možemo reducirati na bool vrijednost
odnosno na "postoji/ne-postoji". Velika većina vrijednosti se
procjenjuje kao `True` jer se odnosi na vrijednost koju smatramo
"postojećom". Kod brojeva je ovdje očito o čemu se priča, 0 se
procjenjuje kao `False`, a svi ostali brojevi kao `True`. Dapače, već
smo vidjeli su vrijednosti `True` i `False` ekvivalentne brojevima 1 i 0
te da je čak s njima i moguće provoditi aritmetičke operacije. Kod
ostalih vrijednosti, međutim, također postoje "prazne vrijednosti" koje
se smatraju `False`. Riječ je u načelu o praznim "zbirkama": tekst od 0
znakova, popis s 0 elemenata itd. S mnogim zbirkama, odnosno
*strukturama podataka*, ćemo se sresti u idućim poglavljima jer su
strukture podataka nezaobilazna tema za programiranje.

``` python

>>> bool(42) True 
>>> bool(0) False 
>>> bool(None) # vrijednost None je opisana u nastavku ovog poglavlja False 
>>> bool(’neki tekst’) # tekst koji sadrži barem jedan znak True 
>>> bool(”) # prazan tekstovni niz, tekst od nula znakova False 
>>> bool([]) # prazan popis, više o popisima kasnije False # ali zapamtimo da se prazne zbirke procjenjuju kao False
```

### Booleovi operatori

Također, booleove vrijednosti se mogu kombinirati booleovim operatorima
`and` i `or`. Bool vrijednost se može i negirati, odnosno pretvoriti u
suprotnu bool vrijednost pomoću operatora `not` koji prethodi varijabli,
odnosno vrijednosti. Na primjer:

``` python

>>> True and False False 
>>> True or False True 
>>> not False True 
>>> True and not False True# shodno gore navedenom: 
>>> x = 1 
>>> y = 2 
>>> x + y == 3 and x == 1 True 
>>> x + y == 1000 and x == 1 False 
>>> x + y == 1000 or y == 2 True 
>>> not x == 1 False
>>> a = ’nešto’ 
>>> b = ’nešto drugo’ 
>>> a.startswith(’n’) and b.startswith(’n’) True 
>>> a.startswith(’n’) and b.startswith(’x’) False 
>>> a.startswith(’n’) or b.startswith(’x’) True 
>>> a.startswith(’n’) and not b.startswith(’x’) True
```

## None

`None` je jedinstvena vrijednost koja označava nepostojanje vrijednosti.
Drugim riječima, postoji samo jedna moguća vrijednost čija vrsta je
`None` i ta vrijednost je `None`. Možda zvuči čudno, ali ova vrijednost
je vrlo korisna kada je potrebno eksplicitno zapisati da neka varijabla
"nema vrijednost".

Promotrimo, na primjer, razliku između vrijednosti `None` i vrijednosti
`0`.

``` python
Čemu služi vrijednost None?listing:none broj_knjiga = 0 broj_knjiga = None
```

U slučaju `broj_knjiga = 0` znači poznatu informaciju: "nula knjiga".
Kada bi se ovaj podatak koristio, na primjer, za broj posuđenih knjiga,
vrijednost 0 bi značila da nema posuđenih knjiga. S druge strane,
vrijednost `None` kod `broj_knjiga = None`, pak, znači: "broj knjiga je
nepoznat". Vrijednost `None` posebno je korisna za rad s podacima i
dizajn vlastitih funkcija (što je prikazano kasnije). U drugim jezicima
i bazama podataka, vrijednost `None` se često naziva `null`.

Za razliku od brojeva, teksta i booleovih vrijednosti, s vrijednosti
`None` nemamo posebne radnje jer za ovu vrstu vrijednosti nemaju smisla.

[^1]: Koja se u mnogim drugim jezicima i bazama podataka često zove
    `null`.

[^2]: Ako pak krenete programirati, na primjer, rakete i svemirske
    brodove, informirajte se. Barem je jedna već pala radi pogrešnih
    konverzija iz jedne vrste broja u drugi, vidi na primjer [Ariane
    5](https://en.wikipedia.org/wiki/Ariane_5#Notable_launches).

# Moduli: Proširenja mogućnosti

Programski jezici tipično u svojoj osnovnoj specifikaciji definiraju
samo osnovne mogućnosti i vrste vrijednosti. Specifičnije radnje (poput
kopiranja datoteka, trigonometrijskih ili statističkih izračuna ili
slanja elektroničke pošte), vrste vrijednosti (poput datuma ili putanje
na disku) i konstante (poput broja $`pi`$) se ne nalaze u osnovnoj
specifikaciji već u proširenjima jezika. Ova proširenja se vrlo često na
engleskom zovu knjižnice (eng. *libraries*), a u Pythonu se zovu moduli
(eng. *modules*).

Python modul, dakle, unosi dodatne mogućnosti u jezik. To je ranije
napisan kôd čije elemente možemo ponovno koristiti u novim programima. U
računalnom slengu, modul možemo shvatiti kao *plug-in*. Već smo upoznali
jedan takav modul: `math`. Kako bi mogli početi koristiti modul,
potrebno ga je "uvesti" u vlastiti kôd.

``` python
Korištenje modula pomoću naredbe importlisting:
moduli_import import math 
print(math.sqrt(2)) 
print(math.pi)
```

Rezultat koda gore je ispis korijena iz dva i pi konstante, ali to nije
zašto ga ovdje prikazujemo. Linija `import math` govori Pythonu da uveze
modul `math` koji je ostatku koda u toj datoteci dostupan kroz ime
`math` i to ime se ponaša kao varijabla. Svi članovi tog modula
(funkcije, vrste vrijednosti i konstante) dostupni su pisanjem nakon
točke. Kao i kod metoda, točka označava članstvo odnosno članove modula
koristimo pisanjem točke nakon imena modula kao gore u linijama
`math.sqrt(2)` i `math.pi`.

Dvije stvari su nam ovdje važne. Prva je da se kod uvoza modula događa
slična stvar kao i u pridruživanju vrijednosti varijabli: neko ime se
"rezervira" za određenu upotrebu. Pogledajmo primjer:

Riječ "math", naravno, nema posebno značenje u Pythonu pored toga što je
naziv standardnog modula i smije se koristiti proizvoljno. Kada ne
koristimo modul math, ovo nije problem. Ukoliko prikazano jest problem,
jer imamo vlastitu varijablu koju želimo zvati isto kao i neki modul
koji želimo koristiti, najbolje je promijeniti ime varijable, ali
postoji i mogućnost promjene naziva modula prilikom uvoza:

Također, Python dozvoljava i uvoz samo jednog člana nekog modula.

``` python
>>> from math import pi 
>>> print(pi) 3.141592653589793 
>>> pi = 100 
>>> print(pi) 100
```

Na ovaj način, ne uvozimo ime `math` već direktno ime `pi`. To znači da
nam ime `math` u ostatku koda nije relevantno, ali ako redefiniramo
varijablu `pi`, izgubiti ćemo vrijednost koju smo uvezli iz modula
`math`. Ovaj način uvoza je koristan kada želimo koristiti samo jedan
ili mali broj članova nekog modula jer možemo koristiti naziv člana
modula direktno (na primjer `pi`) radije nego u obliku `math.pi` (na
primjer `math.pi`). Kao i kod uvoza cijelih modula, članove možemo
preimenovati koristeći se riječi `as`.

``` python
>>> from math import pi as x 
>>> print(x) 3.141592653589793
```

## Standardna knjižnica

Kako to da smo nakon osnovne instalacije Pythona mogli jednostavno
napisati `import math` i modul `math` je dostupan? Kao što smo već u
uvodu spomenuli, jedna od odluka Pythona je da su “baterije uključene“.
To znači da Python dolazi s velikim brojem modula koji su uključeni u
instalaciju Pythona. Te module zajednički nazivamo “standardnom
knjižnicom“ i ona dolazi s velikim brojem modula koji proširuju Python s
kojekakvim mogućnostima. Popisu modula i dokumentaciji možete pristupiti
[ovdje](https://docs.python.org/3/library/index.html).

S mnogim korisnim modulima ćemo se upoznati kroz tekst, a nabrajati ih
sve ovdje ne bi bilo svrsishodno jer u standardnoj knjižnici postoji
velik broj modula. Slijedi odabir često korisnih modula kako bi dobili
dojam o čemu se radi i informirali se o mogućnostima koje su dostupne
kroz standardnu instalaciju Pythona:

- **rad s tekstom**

  - `string` - znakovi definirani prema ASCII standardu i dodatne radnje
    s tekstom

  - `unicodedata` - UNICODE šifrarnik za kodiranje teksta

  - `re` - regularni izrazi

- **rad s brojevima**

  - `math` - dodatne matematičke funkcije i konstante

  - `statistics` - dodatne statističke funkcije

  - `random` - generacija slučajnih brojeva

- **rad s vremenom**

  - `time` - očitanje vremena

  - `datetime` - vrste vrijednosti za datume kao i sate, minute ...

- **rad s putanjama i datotekama**

  - `pathlib` - vrsta vrijednosti za putanje na disku

  - `shutil` - radnje s datotekama, kao što su kopiranje, preimenovanje
    i brisanje

- **rad s podatkovnim datotekama**

  - `csv` - čitanje i pisanje razgraničenog teksta

  - `json` - čitanje i pisanje JSON datoteka

- **rad s internetom i webom**

  - `email, smtplib, imaplib` - elektronička pošta

  - `html, xml` - rad s HTML-om i XML-om

  - `urllib` - rad s URL-ovima, uključujući i dohvat podataka s weba

- **zapisivanje i komprimiranje podataka**

  - `pickle` - zapisivanje Python objekata na disk i usnimavanje istih

  - `sqlite3` - stvaranje SQLite relacijskih baza podataka

  - `zipfile` - rad sa zip komprimiranim datotekama

Sa spomenutim modulima smo tek zagrebli površinu standardne knjižnice.
Ipak, prikazali smo mnoge korisne module, a velik dio standardne
knjižnice ima veze temama koje su nam za sada prenapredne, kao što su to
funkcijsko programiranje, testiranje, profiliranje i debagiranje kôda,
asinkrono i višeprocesorsko programiranje i tako dalje. Stoga ćemo se za
sada zaustaviti s prikazom standardne knjižnice, a kroz ovaj tekst ćemo
se upoznati s mnogim modulima u praksi.

## Instalacija dodatnih modula

Python, dakle, dolazi s mnogim zanimljivim mogućnostima sam po sebi, ali
što ako nam treba više? Što ukoliko želimo zapisati .pdf, .docx ili
.xlsx datoteku, crtati rasterske ili vektorske slike, raditi napredne
znanstvene analize ili pak isprogramirati aplikaciju s grafičkim
sučeljem ili video igru?

Pored standardne knjižnice za Python postoji izuzetno velik broj modula
koje razvijaju korisnici. Mnogi od ovih modula su veliki i kvalitetni
projekti koji se već dugo razvijaju i koji se često koriste u znanosti i
industriji. Katalog dodatnih modula je dostupan kroz [Python Package
Index](https://pypi.org/) (odnosno PyPi) i sadrži preko 200 000 modula.

# Kontrola toka: Kondicionali, petlje i pokušaji

U programiranju ne bismo daleko dogurali kada bismo jedino mogli po redu
izvršavati jedinične radnje. S jedne strane moramo moći prema određenim
uvjetima odabrati koje naredbe će se izvršiti, a koje ne. Ovo postižemo
*kondicionalima*. S druge strane moramo moći ponavljati iste naredbe.
Ovo postižemo *petljama*. U nastavku ćemo se upoznati s detaljima i
riječ je o standardnim komponentama gotovo svih programskih jezika. U
mnogim jezicima visoke razine postoji i treći koncept u kontroli toka, a
to je *pokušaj* provođenja određenih naredbi s jasno definiranim kôdom
koji će se izvršiti ako neka od naredbi ne uspije.

## Kondicionali: Ako ... onda ...

Kondicionali služe *odabiru* kôda koji će se izvršiti. Kada su neke
linije ovisne o kondicionalu, tada se neće izvršavati uvijek već samo
kada su određeni uvjeti zadovoljeni. Time dobivamo mogućnosti poput:
"ako se neki izraz evaluira kao True, napravi nešto; a ako ne, napravi
nešto posve drugo". Na taj način možemo reći stvari poput:

- Ako direktorij ne postoji, stvori ga.

- Ako datoteka postoji pitaj korisnika da li ju želi prepisati novom
  datotekom.

- Ako korisničko ime već postoji, javi da je zauzeto, a ako korisničko
  ime ne postoji, stvori novog korisnika.

- Ako je korisnik upisao odgovor "a", javi da je odgovor točan, a ako je
  korisnik upisao "b", "c" ili "d" javi da je odgovor netočan, a u svim
  ostalim slučajevima javi da odgovor nije prepoznat.

<div class="important">

Kondicionali Kondicionali služe uvjetnom izvršavanju kôda. Oni prema
određenim uvjetima odabiru koji će se reci izvršiti, a koji ne.

</div>

Kondicionale u programskim jezicima tipično reprezentiramo sa složenom
izjavom `if`, a minimalan oblik te izjave u Pythonu je:

``` python
Najjednostavniji oblik kondicionalalisting:kondicional1 if <izraz>: neka radnja
```

"Neka radnja" se izvršava samo ako izraz rezultira vrijednošću koja se
procjenjuje kao `True` (vidi poglavlje o booleovim vrijednostima za
detalje). Ova radnja se mora sastojati od barem jedne linije kôda, ali
može se sastojati i od više njih. Konkretnije, ispod svake `if` izjave
se očekuje uvučeni blok kôda. Taj blok koda, kao što je već rečeno, se
naznačuje tako što su sve linije u bloku jednako uvučene i izvršava se
samo ako je uvjet zadovoljen, a u suprotnom se preskače.

Što se uvlačenja kôda tiče, u Pythonu se uvijek uvlači nakon dvotočke
koja se, između ostalog, koristi u kondicionalima i petljama. Općenito
je pravilo da Python nakon retka koji završava s dvotočkom očekuje barem
jednu uvučen redak kôda odnosno minimalan blok kôda.

Standard u Pythonu je kôd uvlačiti sa četiri razmaka koji se u
prilagođenom softveru dobivaju pritiskom na tipku "tabulator" odnosno
"tab". Ovaj koncept se naziva "mekanim tabulatorom" (eng. *soft tab*)
jer služi istome čemu služi i sam znak tabulator, ali izbjegava taj znak
(što ima i smisla jer je tabulator po definiciji razmak varijabilne
dužine). Moguće je koristiti i znak tabulator, ali se treba pobrinuti da
se ne miješaju tabulatori i razmaci. Navedeno zvuči kompleksnije no što
je slučaj u praksi jer se za ujednačenost uglavnom pobrine softver u
kojem programiramo.

Moguće je napisati i kondicional koji će uvijek izvršiti neki kôd tako
što ga proširimo s komponentom `else` koja znači "u svim ostalim
slučajevima".

``` python
Kondicional koji će uvijek izvršiti radnjulisting:kondicional3 if <izraz>: neka radnja else: # u svim ostalim slučajevima neka druga radnja
```

U ovom obliku, "neka radnja" se izvršava kao i u prošlom, ali ako se ne
izvrši, tada će se izvršiti "neka druga radnja". Drugim riječima ovakav
kondicional će, za razliku od prošlog oblika, uvijek izvršiti neke
naredbe. Pogledajmo neke konkretne primjere:

Primjer prikazuje tri kondicionala. Prvi kondicional radi nešto samo ako
je uvjet zadovoljen. Druga dva kondicionala uvijek rade nešto jer imaju
komponentu `else` čiji kôd se izvršava kada niti jedan drugi uvjet nije
zadovoljen. Izvršavanje prikazanog koda, dakle, ispisati će dvije ili
tri rečenice jer prvi prikazani kondicional nema komponentu `else` dok
druga dva imaju. Koje su to?

<div class="pythonp">

<a href="#listing:kondicional4" data-reference-type="ref"
data-reference="listing:kondicional4">[listing:kondicional4]</a> x je
veće ili jednako y x + y je manje od 10

</div>

U prijašnjem primjeru svi izrazi koji se pojavljuju kao uvjeti se
evaluiraju u booleove vrijednosti. Kad želimo vidjeti rezultat određenog
izraza najjednostavnije je to probati u Python komandnoj liniji.

Što bi se dogodilo da smo koristili izraze koji se ne evaluiraju u
booleovu vrijednost poput `x + y`? U Pythonu je za potrebe kondicionala
moguće i implicitno pretvoriti bilo koju vrijednosti u booleovu
vrijednost. Drugim riječima, izjava `if vrijednost:` se izvršava kao da
smo pisali `if bool(vrijednost):`. Sjetimo se, izraz se uvijek evaluira
u vrijednost pa ranije napisano ujedno znači i `if bool(izraz)`.
Pogledajmo primjer:

<div class="pythonp">

<a href="#listing:kondicional5" data-reference-type="ref"
data-reference="listing:kondicional5">[listing:kondicional5]</a> bool(b)
se evaluira u True bool(x + y) se evaluira u True

</div>

Kako možemo napisati kondicional koji ima više od jednog eksplicitnog
uvjeta (ne računajući `else`)? U kondicionalima se često koriste dodatne
komponente *else if* koje služe upravo ovome. Python te riječi skraćuje
u riječ `elif`. Kondicional sa svim dozvoljenim komponentama izgleda
ovako:

``` python
Kondicional sa svim komponentamalisting:kondicional6 if <izraz1>: radnja 1 elif <izraz2>: radnja 2 elif <izraz3>: radnja 3 ... else: radnja n
```

A evo i konkretnog primjera kondicionala sa svim komponentama:

<div class="pythonp">

<a href="#listing:kondicional6" data-reference-type="ref"
data-reference="listing:kondicional6">[listing:kondicional6]</a> slučaj
"x je 3"

</div>

Drugim riječima, svaki kondicional ima nužno jedan `if` slučaj, a može
imati i bilo koji broj `elif` slučajeva i jedan `else` slučaj. Ovakav
kondicional smo već vidjeli u primjeru
<a href="#listing:kviz" data-reference-type="ref"
data-reference="listing:kviz">[listing:kviz]</a>, a u idućim poglavljima
ćemo za vježbu isprogramirati nešto konkretnije i iskoristiti
kondicionale. Upoznajmo se ipak prije toga i s petljama i pokušajima
kako bismo zaokružili koncept "kontrole toka".

## Petlje: ponavljanje naredbi

Petlje služe *ponavljanju* jedne ili više naredi. S petljama možemo dati
instrukcije poput "ponovi kôd za svaki element u popisu" ili "ponavljaj
neki kôd sve dok uvjet nije zadovoljen". Time možemo izraditi programe
koji na primjer crtaju geometrijske oblike, izrađuju bibliografski zapis
za svaku knjigu u nekoj bazi podataka ili čekaju korisnički unos i
ponavljaju se sve dok korisnik ne zatraži izlaz iz programa.

<div class="important">

Petlje Petlje ponavljaju naredbe. Iste naredbe treba ponavljati
petljama, a ne dupliciranjem kôda.

</div>

### Za svaki

Petlja koja se vrlo često koristi u programiranju, a u Pythonu je se
najčešće koristi petlja `for`. Kao i kod kondicionala, ovo je složena
izjava. Python koristi *for each* varijantu ove petlje koju skraćuje u
naziv `for`. Drugim riječima, `for` u Pythonu valja čitati "za svaki" i
ova petlja ponavlja naredbe za svaki element u nekom skupu
elemenata[^1]. Do sada jedina vrsta vrijednosti koju smo upoznali i koja
se može raščlaniti na elemente je `str`, odnosno niz znakova pa ćemo
upravo tu vrstu vrijednosti koristiti za primjere. Petlja `for` će
postati korisnija kada naučimo i strukture podataka o čemu je riječ u
zasebnom poglavlju.

Petljom `for` je dakle moguće provesti jednu ili više radnji za svaki
znak u nekom tekstu. Pogledajmo kako:

<div class="pythonp">

<a href="#listing:for_basic" data-reference-type="ref"
data-reference="listing:for_basic">[listing:for_basic]</a> t e k s t

</div>

Koncept "skupa vrijednosti po kojem se može prebirati" vrlo je važan pa
ima i vlastitu terminologiju. Prebiranje po nekom skupu vrijednosti
često nazivamo *iteracija* (eng. *iteration*), a vrsta vrijednosti po
kojoj se može prebirati je *iterabilna* (eng. *iterable*) vrsta
vrijednosti. Petlja `for` se "izvrti određen broj krugova" pa završi.
Jedan "krug" nazivamo jednom iteracijom. Iteracija kao proces je, dakle
proces prebiranja, a jedna iteracija je individualno izvršavanje naredbi
koje se ponavljaju. Jednu iteraciju unutar petlje često nazivamo i
korakom eng. *step* petlje.

O finijim detaljima spomenutog će biti riječ kasnije kada dođemo do
struktura podataka, ali terminologiju vrijedi znati i ranije jer se
često koristi u Python dokumentaciji i literaturi kao i u samom Python
jeziku prilikom, na primjer, javljanja pogrešaka.

<div class="important">

Iteracija Kada po nečemu iteriramo, tada po tome prebiremo jedan po
jedan element. Kada je nešto iterabilno tada se po tome može prebirati.
Ove riječi se često koriste u kôdu. Metode čiji naziv počinje s
prefiksom "iter" vraćaju rezultatu po kojem se može iterirati. Kada
Python javi grešku da nešto nije "iterabilno" tada pokušavamo prebirati
po vrsti vrijednosti koja se ne može raščlaniti na sastavne elemente.

</div>

U primjeru <a href="#listing:for_basic" data-reference-type="ref"
data-reference="listing:for_basic">[listing:for_basic]</a> smo vidjeli
kako možemo raditi sa svakim znakom u nekom tekstu odnosno sa svakim
elementom u nekom skupu vrijednosti. U retku `for znak in tekst:`,
`tekst` je skup vrijednosti po kojem se prebire, a `znak` je proizvoljan
naziv varijable koji unutar petlje možemo koristiti kako bi se
referirali na element u "ovoj iteraciji". U prvoj iteraciji, varijabla
`znak` je jednaka vrijednosti `"t"`. U drugoj iteraciji, jednaka je
vrijednosti `"e"` i tako dalje.

Što ukoliko samo želimo ponoviti neku radnju određen broj puta nevezano
za neki već postojeći skup vrijednosti poput vrijednosti `"tekst"`? Za
ovo nam je korisna funkcija `range` koja stvara niz brojeva od nekog
minimuma do nekog maksimuma. Ova funkcija je korisnija no što se na prvi
pogled možda čini pa ćemo je često susretati. Na primjer, često se
koristi u kombinaciji s petljom `for` kako bi odredila koliko puta će se
naredbe unutar petlje ponoviti. Pogledajmo primjer:

<div class="pythonp">

<a href="#listing:for_range" data-reference-type="ref"
data-reference="listing:for_range">[listing:for_range]</a> 0 tekst 1
tekst 2 tekst 3 tekst 4 tekst

</div>

Kao što vidimo, kada funkciji `range` pošaljemo jedan broj, ona stvara
niz brojeva od nule do poslanog broja, ne uključujući i taj broj. Ovdje
smo to iskoristili da bismo ponovili radnju 5 puta. Kako bi bilo jasnije
što se zbiva, ispisali smo i vrijednost varijable `i` svaki put, ali
varijablu `i` uopće ne moramo koristiti unutar petlje ako nam nije
potrebna.

### Dok se uvjet ne zadovolji

Druga vrsta petlje u Pythonu je petlja `while` koja je također često
vrlo korisna. Ova petlja ne prebire po nečemu već se izvršava sve dok
neki uvjet nije zadovoljen. Njome možemo izvesti isto što i u prošlom
primjeru:

<div class="pythonp">

<a href="#listing:while_basic" data-reference-type="ref"
data-reference="listing:while_basic">[listing:while_basic]</a> 0 tekst 1
tekst 2 tekst 3 tekst 4 tekst

</div>

Primjer <a href="#listing:for_basic" data-reference-type="ref"
data-reference="listing:for_basic">[listing:for_basic]</a> također
možemo postići ovom petljom, ali nešto zaobilaznijim putem:

<div class="pythonp">

<a href="#listing:while_index" data-reference-type="ref"
data-reference="listing:while_index">[listing:while_index]</a> t e k s t

</div>

U prikazanim primjerima svejedno je da li koristimo petlju `for` ili
petlju `while`, ali petlja `while` zahtijeva nešto više komponenata.
Također, ova petlja krije jednu opasnost koja se u `for` petlji može
teško dogoditi: lako je moguće da se `while` petlja krene izvršavati
zauvijek! Idući primjer prikazuje ovakvu grešku i ako ga pokrenete
pripremite se da će te morati nasilno ugasiti Python, jer se ovaj
program neće nikad završiti.

U prošlom primjeru je greškom ispuštena naredba `i += 1` pa se uvjet za
završetak ponavljanja kôda nikad neće zadovoljiti. Naredba
`print("nema kraja")` će se stoga pokušati izvrtiti beskonačan broj
puta. Izvršavanje ovog programa će završiti tek kad ga nasilno ugasimo
tako što smo prekinuli sistemski proces ili ugasili računalo.

Prikazana beskonačna petlja je rezultat greške i njezino ponašanje je
nepoželjno. Ipak, postoje situacije u kojem su beskonačne petlje zapravo
vrlo korisne i puno ih je lakše postići petljom `while` no petljom
`for`. Tipičan primjer su aplikacije koje kad se pokrenu čekaju
korisničke naredbe koje zatim izvršavaju na zahtjev. Navedeno stoji za
gotovo sve aplikacije s grafičkim sučeljem. U ovom slučaju, petlja se
nikad neće sama po sebi završiti, ali postoji mehanizam koji ju u
posebnim slučajevima može prekinuti. Pogledajmo prvo kako funkcioniraju
mehanizmi za prekidanje petlje, a konkretni primjeri korištenja `while`
petlji u ovom smislu su preneseni kasnije u tekstu.

Postoje dvije jednostavne Python izjave koje služe upravljanju petljama
i koje se smiju koristiti samo unutar petlji. Te izjave su `break`, koja
služi prekidanju petlje i `continue`, koja služi prelasku na idući korak
petlje.

### Prekini petlju

Jednostavna izjava `break` čim se izvrši završava petlju u kojoj se
nalazi. Ova izjava se koristi kada je potrebno izaći iz petlje prije no
što bi ona završila sama po sebi.

<div class="pythonp">

<a href="#listing:for_break" data-reference-type="ref"
data-reference="listing:for_break">[listing:for_break]</a> n e k i

</div>

Izjava "prekini petlju", odnosno `break`, je nužna u prije spomenutim
beskonačnim `while` petljama. Pogledajmo praktičan primjer:

Izvrši ovaj program. Kako se ponaša? Ne radi ništa korisno, ali je
program koji se ponaša bliže računalnim aplikacijama. Naš "prvi program"
odnosno primjer <a href="#kviz" data-reference-type="ref"
data-reference="kviz">[kviz]</a> se mogao izvršiti samo jednom i onda je
izašao. Prikazani mehanizam omogućuje da se program nastavlja, odnosno
ponavlja, sve dok korisnik ne odluči prestati raditi s njim.

Jedna zanimljivost kod prekida petlje u Pythonu je što petlja `for`
podržava i komponentu `else` koja se izvršava samo ako petlja nije
prekinuta s naredbom `break`. Ova mogućnost je često korisna prilikom
pretraživanja. Pogledajmo primjer koji provjerava da li se u nekom
tekstu nalazi traženo slovo:

<div class="pythonp">

<a href="#listing:for_else" data-reference-type="ref"
data-reference="listing:for_else">[listing:for_else]</a> kada je slovo
pronađeno Unesi neki tekst: riba ribi grize rep Unesi slovo koje se
traži: a Slovo "a" JE pronađeno!

</div>

<div class="pythonp">

<a href="#listing:for_else" data-reference-type="ref"
data-reference="listing:for_else">[listing:for_else]</a> kada slovo nije
pronađeno Unesi neki tekst: riba ribi grize rep Unesi slovo koje se
traži: x Slovo "x" NIJE pronađeno!

</div>

Za vježbu pokušajte izvesti prijašnji program bez da koristite
komponentu `else` petlje `for`!

### Preskoči korak u petlji

Jednostavna izjava `continue` čim se izvrši prelazi na idući korak
petlje u kojoj se nalazi. Ova izjava se koristi kada je potrebno
preskočiti korak u petlji.

<div class="pythonp">

<a href="#listing:for_continue" data-reference-type="ref"
data-reference="listing:for_continue">[listing:for_continue]</a> n k t k
s t

</div>

Na prikazani način možemo izvršiti petlju koja se izvršava za određen
broj slučajeva, ali se preskaču slučajevi koji (ne) zadovoljavaju
određene uvjete.

Pogledajmo još pobliže u pogreške i upravljanje njima pa se možemo
baciti i na konkretnije programe.

## Pogreške i pokušaji

Javljanje pogrešaka je normalna stvar u programiranju, a kod programskih
jezika viših razina se pokušava čim jasnije korisniku dati do znanja što
je i gdje je pošlo po krivu. Python omogućava i presretanje pogrešaka
što nam pruža nove mogućnosti za kontrolu toka programa. Pogledajmo prvo
pobliže Python pogreške, a zatim i kako ih presretati.

Što se dogodi kad Python prilikom izvršavanja kôda naiđe na pogrešku?
Recimo da smo pokušali izvršiti izraz `n + 1`, a varijabli `n` nije
pridružena vrijednost.

Usredotočimo se na zadnju liniju. Python javlja `NameError` s
`name 'n' is not defined` kao detaljima pogreške. U trenutku kad je
naišao na pogrešku Python je stvorio objekt vrste `Exception` (u ovom
slučaju `NameError`) s nekom porukom. Zatim je prijavio grešku opisanu
tim objektom korisniku te prekinuo izvršavanje. Sve linije prije zadnje
su ispis koda u kojemu se dogodila greška. Ovaj dio može biti vrlo
dugačak, ali važno je zapamtiti da nam je za opis greške najvažnija
zadnja linija i u mnogim slučajevima je dovoljno pročitati samo nju uz
informacije u kojoj se točno liniji kôda javlja pogreška. Ispis ranijeg
kôda služi lakšem pronalaženju greške u vlastitom ili tuđem kôdu i
posebno je koristan kod većih programa.

Također, postoji više vrsta grešaka koje je najlakše pronaći u
interaktivnom radu:

Dapače, ukoliko prilikom učenja Pythona ne vidite često kojekakve
pogreške, šanse su da trebate promijeniti pristup! Upravo prikazana
greška pojednostavljeno kaže "Greška u vrsti podataka: brojevi i tekst
se ne mogu zbrajati".

Najčešće pogreške koje Python javlja su:

- **SyntaxError** - javlja se kada kôd nije dobro formiran; najčešće
  pogreške ovog tipa su neujednačene zagrade ili navodnici, manjak
  zareza ili dvotočki na mjestima na kojima se moraju pojavljivati i
  slično

- **NameError** - javlja se kada koristimo neki naziv čija vrijednost
  nije poznata; na primjer pokušavamo koristiti varijablu `x` prije no
  što smo toj varijabli pridružili neku vrijednost

- **TypeError** - javlja se kada se operacija ili funkcija pokuša
  provesti s krivom vrstom vrijednosti; na primjer `"1" + 1` ili
  `round("tekst")`

- **ValueError** - javlja se kada se operacija ili funkcija pokuša
  provesti s točnom vrstom vrijednosti, ali s vrijednosti s kojom nije
  moguće provesti tu operaciju ili funkciju; na primjer `math.sqrt(-1)`

- **ImportError** - javlja se kada korisnik pokuša uvesti modul koji ne
  postoji (ili ga Python ne zna pronaći, što dođe na isto); na primjer
  **import nisamtu** (pod uvjetom da niste sami napisali Python modul
  koji se zove "nisamtu")

- **IndexError** - javlja se kada pokušamo dohvatiti element popisa koji
  nije prisutan; na primjer osmi znak iz stringa koji se sastoji od
  sedam znakova

- **KeyError** - javlja se kada pokušamo dohvatiti element rječnika koji
  nije prisutan; na primjer element pod nazivom "title" iz rječnika koji
  ne sadrži takav ključ[^2]

Kroz iskustvo rada u Pythonu, postaje sve lakše identificirati probleme
kroz vrste pogreški koje Python javlja. Uz to, kroz presretanje
pogrešaka možemo upravljati pogreškama u programiranju što je katkad
korisno. Ipak, dok su kondicionali i petlje standardan i prihvaćen dio
kontrole toka u programskim jezicima, presretanje pogrešaka nije do te
mjere. Ipak, može biti vrlo korisno i to pogotovo u slučaju kada želimo
presresti korisničke greške kako bi mu javili jasnije poruke i
spriječili "rušenje" programa. Na primjer, sljedeći program računa i
ispisuje drugi korijen iz unesenog broja.

Kada pokrenemo program i upišemo broj "2", program će ispisati:

<div class="pythonp">

<a href="#listing:pogreske_input_raw" data-reference-type="ref"
data-reference="listing:pogreske_input_raw">[listing:pogreske_input_raw]</a>
Program je započeo s radom.

Unesi broj: 9 Drugi korijen: 3.0

Pritisni \<enter\> za kraj

</div>

Prikazani program jednostavno računa drugi korijen iz korisničkog unosa.
Ali što ako korisnik unese nešto što se ne može interpretirati kao broj
ili unese negativan broj? Evo kako bi izgledao loš unos kada bismo ovaj
program pokrenuli u IDLE-u ili u komandnoj liniji.

<div class="pythonp">

<a href="#listing:pogreske_input_raw" data-reference-type="ref"
data-reference="listing:pogreske_input_raw">[listing:pogreske_input_raw]</a>
Program je započeo s radom.

Unesi broj: neću

Traceback (most recent call last): File "C:/code/try_except_a.py", line
7, in \<module\> broj = int(broj) ValueError: invalid literal for int()
with base 10: ’neću’

</div>

U prikazanom slučaju vidimo "sirovu" grešku koju je javio Python.
Međutim, da smo ovaj program pokrenuli duplim klikom, program bi
jednostavno završio prije no što korisnik može pročitati poruku o
grešci! Iz korisniče perspektive "program se srušio". U svakom slučaju,
što želimo postići je: 1) da korisnik uvijek vidi grešku koja se
dogodila i 2) da se korisniku ne prikazuje sirova greška kako ju javlja
programski jezik, već neka poruka specifično namijenjena za naš program.
Kako bismo postigli ovo, Python nam omogućuje korištenje riječi `try`.
Pogledajmo primjer:

Kada izvršimo program vidjet ćemo da se on ne gasi "sam od sebe"
prilikom pogreške, a povratna informacija korisniku nije više interna
poruka od programskog jezika već nešto dizajnirano za ovu specifičnu
namjenu.

<div class="pythonp">

<a href="#listing:pogreske_input_try" data-reference-type="ref"
data-reference="listing:pogreske_input_try">[listing:pogreske_input_try]</a>
Program je započeo s radom.

Unesi broj: neću Iz vrijednosti "neću" nije moguće izračunati drugi
korijen.

Pritisni \<enter\> za kraj

</div>

Slično se ponaša i kada unesemo negativan broj.

<div class="pythonp">

<a href="#listing:pogreske_input_try" data-reference-type="ref"
data-reference="listing:pogreske_input_try">[listing:pogreske_input_try]</a>
Program je započeo s radom.

Unesi broj: -1 Iz vrijednosti "-1" nije moguće izračunati drugi korijen.

Pritisni \<enter\> za kraj

</div>

Ovaj primjer demonstrira korištenje naredbe `try` u praksi.
Najjednostavnije korištenje ove naredbe može se sažeti na sljedeći
način:

<div class="pythonp">

Najjednostavniji oblik pokušajalisting:pokusaj_1 try: \<naredbe koje će
se pokušati izvršiti\> except VrstaGreške: \<ako se dogodi bilo kakva
greška u kôdu napisanom pod try, izvršiti će se kôd napisan ovdje\>

</div>

`except` dio može i ne mora primiti neku vrstu pogreške (poput
ValueError). Ako ne napišemo niti jednu vrstu pogreške tada će se kôd
pod `except` izvršiti u slučaju bilo koje greške. Ako pak specificiramo
neku vrstu greške, kao u primjeru
<a href="#listing:pogreske_input_try" data-reference-type="ref"
data-reference="listing:pogreske_input_try">[listing:pogreske_input_try]</a>,
tada će se kôd napisan pod `except` izvršiti samo u slučaju te vrste
greške. Ne specificirati vrstu greške je dopušteno, ali se u načelu
smatra lošom praksom jer na taj način naredba `try` može "sakriti"
greške za koje nismo pretpostavili da se mogu dogoditi što znatno
otežava traženje problema u programima. Zato je dijelu `except` dobro
specificirati točno koje vrste pogreške hvata. Ako želimo hvatati više
vrsta pogrešaka, možemo ponoviti `except` komponentu naredbe `try`. Kao
što smo vidjeli, ovoj naredbi je moguće dodati i `else` komponentu koja
služi odvajanju kôda koji će se izvršiti samo ako su naredbe u `try`
komponenti uspješno provedene, odnosno suprotan slučaj od onog u kojem
se izvršava `except` dio kôda. Zadnja komponenta naredbe `try` je
komponenta `finally`. Naredbe napisane u ovom dijelu će se uvijek
izvršiti bez obzira da li je kôd pod `try` prouzročio grešku ili ne.

<div class="pythonp">

Širi oblik pokušajalisting:pokusaj_2 try: \<naredbe koje će se pokušati
izvršiti\> except VrstaGreške1: \<ako se dogodi greška vrste
VrstaGreške1 u kôdu napisanom pod try, izvršiti će se kôd napisan
ovdje\> ... except VrstaGreške2: \<ako se dogodi greška vrste
VrstaGreške2 u kôdu napisanom pod try, izvršiti će se kôd napisan
ovdje\> else: \<naredbe koje se izvršavaju samo ako je kôd napisan pod
try uspješno izvršen\> finally: \<naredbe koje se uvijek izvršavaju, bez
obzira da li je došlo do greške ili ne\>

</div>

Ipak, potpuno raspisanu `try` naredbu se rijetko vidi i dapače, primjer
koji prikazuje sve ove komponente u praksi bi bio ili vrlo
specijaliziran ili umjetno osmišljen samo kako bi postojao takav
primjer. Također, neke situacije u kojima se tipično koristila
komponenta `finally` je Python 3 riješio na bolji način. U daleko
najčešćem slučaju, naredba `try` će koristiti samo jednu `except`
komponentu i potencijalno `else` komponentu kao u primjeru
<a href="#listing:pogreske_input_try" data-reference-type="ref"
data-reference="listing:pogreske_input_try">[listing:pogreske_input_try]</a>.

Kao što vidimo, složena izjava `try` ima dosta naprednih mogućnosti.
Ipak, ovaj mehanizam se koristi znatno manje nego kondicionali i petlje.
Dapače, ukoliko je nešto moguće izvesti s izjavom `try`, ali i s
kondicionalima i/ili petljama, kao općenito pravilo se izbjegava `try`
jer za razliku od kondicionala i petlja ima više sitnica na koje treba
paziti i detalja koji mogu poći po krivu.

## Korištenje više mehanizama kontrole toka

Proučimo sljedeći jednostavan primjer:

Iako korisniku javljamo `'Unesi broj: '`, ništa ga ne sprječava da unese
tekst ili bilo što drugo što se ne može interpretirati kao broj. Česta
greška na hrvatskim tipkovnicama je, na primjer, unos "7ž" gdje je slovo
"ž" slučajno utipkano radi smještaja uz tipku enter, a na nekim
tipkovnicama čak i zauzima dio te tipke. Ako se ovo dogodi, program će
se srušiti jer će redak `n = int(n)` javiti grešku i komandna linija će
se odmah ugasiti. Kako bismo spriječili takvo ponašanje i korisniku
javili grešku možemo koristiti izjavu `try`.

Sada smo presreli pogrešku i prikazali korisniku odgovarajuću poruku.
Ipak, nakon pogreške moramo prekinuti izvršavati program jer bi
hipotetski ostatak programa očekivao da je n broj. Kako bismo ovo
spojili s petljom `while` da korisniku ponavljamo pitanje sve dok ne
unese cijeli broj?

<div class="pythonp">

<a href="#listing:input_number_try_while" data-reference-type="ref"
data-reference="listing:input_number_try_while">[listing:input_number_try_while]</a>
Unesi broj: neću neću se ne može interpretirati kao cijeli broj, pokušaj
ponovo. Unesi broj: 17ž 17ž se ne može interpretirati kao cijeli broj,
pokušaj ponovo. Unesi broj: 17

</div>

Prikazani mehanizam možemo koristiti kada želimo osigurati unos cijelog
broja i ponavljati pitanje korisniku sve dok ne unese validan broj. Sada
znamo dovoljno o mehanizmima kontrole toka kako bismo ih iskoristili u
konkretnijim primjerima.

[^1]: U mnogim drugim jezicima se petlja `for` ponaša drugačije, a
    petlja o kojoj je sada riječ se naziva `foreach`, `for_each` ili što
    slično.

[^2]: Rječnici su prikazani kasnije u tekstu.

## Programiranje s kornjačom

"Kornjača" je alat za učenje programiranja koji se koristio u jeziku
Logo još kasnih 1960-ih. Python uključuje ovaj alat kao standardni
modul. Koncept je sljedeći: postoji kornjača koju možemo kretati kroz
dvodimenzionalni prostor s jednostavnim naredbama poput "odi naprijed 50
piksela" ili "skreni lijevo za 45 stupnjeva". Kornjača se najčešće
prikazuje kao strelica, a vrlo je lako s njom početi eksperimentirati i
interaktivno.

<figure id="fig:turtle_idle" data-latex-placement="ht">
<img src="/slike/turtle_idle.png" />
<figcaption>Interaktivan rad s kornjačom</figcaption>
</figure>

Kornjača živi u modulu `turtle`, a prozor u kojem je vizualizacija se
može pokrenuti s naredbom `turtle.showturtle()`. Osnovne naredbe za
kretanje kornjače su `turtle.forward(distance)`, gdje je `distance`
udaljenost za koju će se kornjača pomaknuti u smjeru u kojem je
orijentirana, te `turtle.left(angle)` i `turtle.right(angle)`, gdje je
`angle` broj stupnjeva za koji će kornjača promijeniti orijentaciju u
lijevo ili desno. Kada program pišemo u datoteku, dobro dođe i naredba
`turtle.done()` koja pokreće kornjaču kao aplikaciju koja čeka
korisnički unos. Ovo je korisno i već ako samo želimo spriječiti da se
prozor zatvori čim se program završi, kao što smo to ranije radili
naredbom `input("Pritisni <enter> za kraj")`.

Također, možemo modificirati i razne postavke kornjače kao što su brzina
crtanja, debljina i boja linije i oblik kornjače. U ovom smislu
najvažniji su nam brzina kornjače kako bi lakše mogli vidjeti što se
zbiva i debljina linije, kako bi lakše vidjeli što je kornjača nacrtala.
Brzinu kornjače možemo postaviti s funkcijom `turtle.speed(n)` gdje je
je n broj od jedan do deset, a jedan je najsporije kretanje. Debljinu
linije možemo postaviti s funkcijom `turtle.width(n)` gdje je n broj
piksela.

Imajući to na umu probajte implementirati program u kornjači koji crta
kvadrat. Pokušajte napisati ovaj program prije no što nastavite čitati
skriptu!

Najjednostavnije rješenje ovog problema je kako slijedi:

<figure id="fig:turtle_square" data-latex-placement="H">
<img src="/slike/turtle_square.png" style="width:50.0%" />
<figcaption>Rezultat programa Kornjača i kvadrat 1</figcaption>
</figure>

Ovo rješenje radi što treba, ali je strukturalno loš program. Prvi
problem je što se dvije posve iste naredbe, odnosno naredbe koje se
sastoje od poziva na iste funkcije s istim parametrima, se u paru
ponavljaju četiri puta. Kada krenemo na ovaj način ponavljati naredbe to
je signal da možemo iskoristiti petlju. Također, ulazne vrijednosti za
izvršenje programa se ponavljaju u samim pozivima za funkcije što ih
čini težim za uočiti i mijenjati, a tako je i lakše tako napraviti
grešku u kôdu. Na primjer, kada bismo željeli promijeniti dužinu
stranice, morali bismo to učiniti na četiri različita mjesta u programu,
a riječ je o banalno jednostavnom primjeru. Pogledajmo rješenje koje te
vrijednosti izdvaja ranije kako bi njima bilo lakše baratati te koristi
petlju za izbjegavanje ponavljanja kôda.

Na ovaj način jasno su nam odvojeni podaci i proces samog crtanja, a
proces crtanja ne samo da izbjegava ponavljanje kôda već i omogućuje
laku promjenu broja koraka kornjače. To ne samo da nam olakšava promjene
ovog programa, već nam i otvara nove mogućnosti.

<div class="important">

Ponavljajte petljom i odvojite podatke od logike Izbjegavajte
ponavljanje istih naredbi dupliciranjem. Tome služi petlja. Također,
odvajajte podatke od logike jer ih je tako lakše kasnije saznati i
mijenjati. Navedeno olakšava održavanje i promjene te umanjuje mogućnost
pogrešaka u većim programima.

</div>

U postavkama sada možemo namjestiti crtanje bilo kojeg pravilnog
poligona. Pogledajmo primjere za trokut i heksagon.

<div class="pythonp">

Kornjača i trokut \# ... n_steps = 3 \# broj koraka koji će kornjača
napraviti turn_angle = 120 \# stupanj pod kojim se skreće \# ...

</div>

<figure id="fig:turtle_triangle" data-latex-placement="H">
<img src="/slike/turtle_triangle.png" style="width:50.0%" />
<figcaption>Rezultat programa Kornjača i trokut</figcaption>
</figure>

<div class="pythonp">

Kornjača i heksagon \# ... n_steps = 6 \# broj koraka koji će kornjača
napraviti turn_angle = 60 \# stupanj pod kojim se skreće \# ...

</div>

<figure id="fig:turtle_heksagon" data-latex-placement="H">
<img src="/slike/turtle_hex.png" style="width:50.0%" />
<figcaption>Rezultat programa Kornjača i heksagon</figcaption>
</figure>

Dapače, ukoliko razmislimo i prisjetimo se malo rudimentarne
trigonometrije (ili pronađemo formule *online*), stupanj skretanja
možemo automatski izračunati iz broja stranica čime više ni tu
vrijednost nije potrebno namještati. Dorađeni program, koji se u
potpunosti bazira na poligonima i napustio je koncept kvadrata vidimo
niže.

Program je sada postavljen da crta pravilne poligone bilo kojeg broja
stranica. Ima međutim još jedan problem, unosi su postavljeni tako da
čim je veći broj stranica, tim je veći i poligon ukoliko sami ne
promijenimo dužinu stranice. Navedeno je vidljivo i u ovome tekstu u
razlici u veličini između prikazano trokuta i heksagona, a kako raste
broj stranica, tako raste i veličina. Na slici
<a href="#fig:turtle_big_poly" data-reference-type="ref"
data-reference="fig:turtle_big_poly">5</a> vidimo poligon koji je
pobjegao s ekrana.

<figure id="fig:turtle_big_poly" data-latex-placement="ht">
<img src="/slike/turtle_big_poly.png" style="width:75.0%" />
<figcaption>Interaktivan rad s kornjačom</figcaption>
</figure>

Što ukoliko želimo da nam svi poligoni imaju istu veličinu bez ručnog
podešavanja dužine stranice? Obzirom da su nam ulazne vrijednosti u kôdu
izdvojene, navedeno možemo promijeniti trigonometrijskim izračunima
radije no promjenama u toku programa. Možemo, na primjer, postaviti da
je radijus, a ne dužina stranice, osnovna ulazna vrijednost. Dužinu
stranice možemo zatim izračunati. Pogledajmo kako.

Dodali smo samo formulu za izračun dužine stranice iz radijusa. Na ovaj
način kad crtamo poligone istog radijusa, oni ne rastu s brojem
stranica. Dok ovaj kod prikazuje svrsishodnu upotrebu trigonometrije u
programiranju, za potrebe učenja programiranja nam je ovdje najvažnije
da smo dobrom strukturom, odnosno korištenjem petlje i jasnim odvajanjem
ulaznih podataka od samih naredbi, razvili općenit postupak crtanja
poligona, a krenuli smo od koncepta kvadrata. Sada kad smo razvili
postupak, crtanje poligona bi mogli definirati kao zasebnu funkciju čime
bi omogućili crtanje poligona kroz jednu naredbu. Obzirom da je ovo vrlo
važno za programiranje iole kompleksnijih programa, naučiti ćemo to
kasnije u ovom tekstu, ali pogledajmo prvo još koji primjer koji se
koristi znanjem koje smo već usvojili.

Također, vrijedi spomenuti da smo ovdje prikazali samo najosnovnije
mogućnosti kornjače pa ćemo se na to još vratiti, ali ako netko želi
eksperimentirati s kornjačom više neka se referira na [službenu
dokumentaciju](https://docs.python.org/3.8/library/turt le.html).
Čitanje dokumentacije i traženje odgovora *online* je i dobra vježba jer
se radi o nezaobilaznom koraku prilikom programiranja, a na čitanje
dokumentacije se treba naviknuti (i to pogotovo kada se radi o službenoj
dokumentaciji jer je često pisana tehničkim jezikom) pa je dobro početi
s vježbom.

Također, s kornjačom se mogu raditi kojekakve čudesne i uglavnom
beskorisne stvari. Programiranje radi umjetnosti. Ukoliko smo Python
instalirali prema uputama iz ove skripte i u komandnoj liniji pokrenemo
naredbu `python -m turtledemo` pokrenuti će nam se grafičko sučelje koje
prikazuje napredne primjere i mogućnosti kornjače. Ukoliko, na primjer,
iz padajućeg izbornika "examples" odaberemo primjer "bytedesign" te
kliknemo na "start", dobiti ćemo sliku
<a href="#fig:turtle_examples" data-reference-type="ref"
data-reference="fig:turtle_examples">6</a>.

<figure id="fig:turtle_examples" data-latex-placement="ht">
<img src="/slike/turtle_examples.png" />
<figcaption>Napredni primjeri mogućnosti s kornjačom</figcaption>
</figure>

Ipak, ovi primjeri su uglavnom napredni i koriste mnoge koncepte koje
još nismo objasnili pa u njih nećemo sada dublje ulaziti. Ovdje su
spomenuti jer prikazuju mogućnost programiranja radi kreativnog procesa
radije no pragmatične vrijednosti programa.

## Kalkulator

Probajmo iskoristiti koncepte i mehanizme koje smo do sada upoznali kako
bi isprogramirali jednostavan kalkulator. Krenimo s jasnim nabrajanjem
što taj program treba raditi i koji ulazni podaci su mu za to potrebni.

<div class="important">

Planiranje programa Program valja prvo dobro isplanirati pa tek zatim
implementirati. Dobra praksa je krenuti od rješavanja najjednostavnijeg
mogućeg slučaja kao prototipa pa zatim razmisliti o nadogradnji
mogućnosti i boljoj organizaciji kôda.

</div>

Najjednostavniji slučaj za kalkulator bi mogao zvučati ovako:

1.  korisnik mora odabrati operaciju (npr. zbrajanje ili oduzimanje)

2.  korisnik mora unijeti sve brojeve potrebne za odabranu operaciju

3.  program mora izračunati rezultat ovisno o odabranoj operaciji

4.  program mora prikazati rezultat korisniku

Implementirajte opisani program. Struktura programa je vrlo slična
primjeru <a href="#listing:kviz" data-reference-type="ref"
data-reference="listing:kviz">[listing:kviz]</a>, ali valja razmisliti i
o vrstama vrijednosti[^1]. Pokušajte napisati ovaj program prije no što
nastavite čitati skriptu!

Vrlo jednostavnu, dobro komentiranu i pogrešnu implementaciju ovog
programa vidimo na primjeru
<a href="#listing:calc_naive" data-reference-type="ref"
data-reference="listing:calc_naive">[listing:calc_naive]</a>.

Program smo podijelili u tri sekcije: unos ulaznih podataka, izračun i
ispis rezultata.

Zadaća u "unosu ulaznih podataka" je dobiti potrebne informacije od
korisnika odnosno varijable `operation`, `n1` i `n2`. U našem programu,
korisnik vrijednosti ručno unosi u komandnu liniju. S dodatnim
komponentama, program bi mogao imati i grafičko sučelje što bi samo
značilo zamjenu komandne linije s grafičkim sučeljem za potrebe unosa
ulaznih podataka i prikaz rezultata. Kompleksnost programa bi ovime
znatno porasla i primjer bi zahtijevao puno bolju organizaciju i
apstrakciju kôda na što još nismo spremni. Zadaća dijela "izračun" je
izračunati rezultate i naposljetku u "ispisu rezultata" se korisnika
informira o rezultatima. Ovakva podjela programa je vrlo svrsishodna kad
program krene rasti jer jasno raščlanjujemo kôd prema zadacima koje mora
obaviti.

<div class="important">

Podjela odgovornosti Programe je dobro odvajati u različite dijelove sa
jasnim zadaćama. Korisnički unos (odnosno sučelje), izračun i
izvještavanje su neke zadaće koje će nam često biti svrsishodne.

</div>

Ipak program je pogrešan. Pogledajmo rezultat ovog programa:

<div class="pythonp">

<a href="#listing:calc_naive" data-reference-type="ref"
data-reference="listing:calc_naive">[listing:calc_naive]</a> Unesi prvi
broj: 1 Odaberi operator (+,-): + Unesi drugi broj: 1

Rezultat je: 11

Program je završio s radom, pritisni \<enter\> za kraj.

</div>

Kao što vidimo, rezultat izračuna `1 + 1` je prema našem programu `11`.
U čemu je problem? Greškom smo napravili program koji kada unesemo
operator `+` on zapravo spaja tekst, a ne zbraja brojeve! Naime,
funkcija `input` uvijek vraća `str`. Taj tekst je potrebno pretvoriti u
bojeve prije no što s njima pokušamo raditi aritmetičke operacije. Da
smo pokušali oduzimati, naš program bi se srušio jer tekst ne podržava
operator `-`.

Naš program ima još jedan manji problem: ako korisnik upiše razmak prije
ili poslije operatora isti se neće prepoznati u recima 12 i 14. Upravo
su razmaci prije ili poslije česta greška u korisničkom unosu jer su
teški za vizualno uočiti i često se javljaju uslijed kopiranja teksta.

U svakom slučaju, podatke zaprimljene od korisnika je potrebno
pripremiti. Potrebno je, dakle, pretvoriti tekst u brojeve i maknuti
razmake oko operatora. Koju funkciju možemo iskoristiti za pretvaranje
teksta u broj? Iz poglavlja <a href="#podaci" data-reference-type="ref"
data-reference="podaci">[podaci]</a> znamo da su to `int` i `float`.
Koju od ove dvije funkcije biste odabrali? Ako iskoristimo `float`
dopustiti ćemo upotrebu i cijelih i decimalnih brojeva pa iskoristimo tu
funkciju kako bismo natjerali naš program da zaista računa s brojevima.
S tekstom još nismo detaljno radili, ali ovaj primjer može poslužiti kao
uvod. Iskoristiti ćemo metodu `str.split` kako bismo maknuli "prazan
prostor" koji prethodi ili dolazi nakon operatora. Time ćemo pripremiti
ulazne vrijednosti za daljnji rad. Dorađeni program je vidljiv na
primjeru <a href="#listing:calc_types" data-reference-type="ref"
data-reference="listing:calc_types">[listing:calc_types]</a>

Sada program provodi aritmetičke operacije s brojevima i ignorira prazan
prostor oko operatora. Rezultat je sljedeći:

<div class="pythonp">

<a href="#listing:calc_types" data-reference-type="ref"
data-reference="listing:calc_types">[listing:calc_types]</a> Unesi prvi
broj: 3.14 Odaberi operator (+,-): + Unesi drugi broj: 25

Rezultat je: 28.14

Program je završio s radom, pritisni \<enter\> za kraj.

</div>

Nakon zaprimanja i pripreme korisničkog unosa, program provodi same
izračune. Ova komponenta zapravo obavlja glavnu radnju cijelog programa.
Obzirom da smo već sve potrebne informacije priredili i provjerili, ovaj
dio programa ne mora provjeravati za postojanje i valjanost unosa. Tako
i treba biti. U ovom slučaju, sam izračun je vrlo jednostavan pa smo
mogli i sve odraditi u jednoj komponenti, ali ovo bi nas učilo krivom
pristupu programskoj arhitekturi (iako u ovom primjeru ona ionako nije
najbolje postavljena). U svakom slučaju, zadaća ovog dijela programa je
jednostavno da proizvede varijablu `result` u odnosu na ulazne parametre
(odnosno unos brojeva i operacije). Obzirom da koristimo i `else`
komponentu naredbe `if`, garantiramo da će varijabla `result` postojati
nakon što se provede taj kondicional. Ako `operator` nije prepoznat,
varijabla `result` će se postaviti na vrijednost `None` što i ilustrira
dobru upotrebu te vrste vrijednosti. Vrijednost `0`, na primjer, nije
dovoljna za ovu svrhu jer ona može biti i validan rezultat izračuna.

Zadaća zadnjeg dijela programa je da korisnika obavijesti o rezultatu. U
ovom slučaju, radi se o jednostavnom ispisu u komandnu liniju i zatim
sprječavanja da se prozor zatvori prije no što je korisnik vidio
rezultate. Kao što smo već rekli, ulazi i izlazi su uz dodatan rad mogli
biti realizirani i kroz kakvo grafičko sučelje. Ulazi i izlazi, međutim,
ne moraju nužno biti orijentirani prema ljudskom korisniku. Podaci za
pokretanje programa mogu se čitati iz neke podatkovne datoteke, baze
podataka ili *online* izvora, a izlazi također mogu biti u datoteku,
bazu ili neki web sustav. Upravo zato nam je i korisno odvajati ove
komponente programa.

Ipak, za sada pripremu podataka radimo na najjednostavniji mogući način
koji pretpostavlja da je korisnik apsolutno točno upisao neki broj.
Drugim riječima, ako je korisnik upisao bilo koji znak osim znamenki 0-9
i znaka ".", program će javiti grešku i prekinuti rad. Obzirom da
koristimo vrstu `float`, dopuštamo cijele i decimalne brojeve koji
pretpostavljaju, kao što Python pretpostavlja, decimalnu točku. Da smo
ovdje koristili vrstu vrijednosti `int`, unos decimalnog broja bi
javljao grešku pa je vrsta `float` primjerenija. U svakom slučaju,
decimalan zarez nije dopušten i ako ga korisnik unese dogoditi će se
greška u programu. Već vidimo prvu moguću doradu programa, ali problem
je širi od upotrebe zareza. Ako korisnik unese bilo koji tekst koji
funkcija `float` ne može interpretirati kao decimalan broj, program će
javiti grešku i završiti s izvršavanjem. Iz perspektive korisnika koji
ga je pokrenuo kroz ikonu python datoteke, "srušit će se" bez poruke
zašto. Kako bi izbjegli da se program ruši prilikom pogrešnog unosa
broja, možemo iskoristiti naredbu `try` kako je prikazano u primjeru
<a href="#listing:calc_try" data-reference-type="ref"
data-reference="listing:calc_try">[listing:calc_try]</a>.

U ovom primjeru smo vidjeli i funkciju `quit` koja ne prima parametre i
jednostavno prekida izvršavanje programa. Sav kôd nakon funkcije `quit`
se neće izvršavati ukoliko se izvrši ta funkcija. Obzirom da je u našem
primjeru ta funkcija u naredbi `try`, neće se izvršavati uvijek već samo
kada se dogodi greška koja bi priječila daljnje izvršavanje programa. U
prikazanom slučaju je to kada program nije dobio validne ulaze i ne bi
imalo smisla nastavljati s radom. Primjer možemo vidjeti u akciji na
sljedećem ispisu:

<div class="pythonp">

<a href="#listing:calc_try" data-reference-type="ref"
data-reference="listing:calc_try">[listing:calc_try]</a> Unesi prvi
broj: 3.14 Odaberi operator (+,-): + Unesi drugi broj: neću!

GREŠKA: Oblik broja nije prepoznat! Program završava s radom.

</div>

Kao što vidimo, program se sada ne ruši kad korisnik upiše pogrešan
oblik broja i to čak ni kada korisnik prgavo (kakvi korisnici i jesu)
upiše tekst `'neću!'` umjesto broja. Program nam je sada malo robusniji,
ali ima više mogućih dorada. Jedna važna dorada je mogućnost da provede
više operacija u jednom pokretanju programa. To možemo postići pomoću
onoga što već znamo o petlji `while` koja se ponavlja broj beskonačan
broj puta i prestaje samo kada korisnik zatraži izlazak iz programa.
Rješenje je prikazano u primjeru
<a href="#listing:calc_while" data-reference-type="ref"
data-reference="listing:calc_while">[listing:calc_while]</a>.

Kao što vidimo, cijeli postupak smo prebacili unutar beskonačne `while`
petlje koja time ponavlja cijeli naš dosadašnji program. Program smo
adaptirali tako što se prvo provjerava operacija jer kada korisnik
odabere `'i'` nije ga uopće potrebno pitati za unos brojeva. Priprema
operatora se odvija u retku 16 i dosadašnjoj pripremi smo dodali metodu
`str.lower`. Ta metoda pretvara sva slova u mala i osigurava da naš
program radi i kada je korisnik unio veliko slovo `'I'` kao operaciju.
Ovdje već vidimo neke mogućnosti i specifičnosti u radu s tekstom putem
programiranja. Velika i mala slova su računalu različiti znakovi, a
`'\n'` se referira na znak za novi redak. Detalje ćemo vidjeti u idućem
poglavlju jer detalji rada s tekstom zahtijevaju poglavlje za sebe.

Naš kalkulator je još uvijek vrlo primitivan, zna samo zbrajati i
oduzimati, ali demonstrira nam mnoge različite koncepte u programiranju.
Omogućava ponovljene radnje i otporan je na najčešće korisničke greške.
Korištenje programa sada izgleda ovako:

<div class="pythonp">

<a href="#listing:calc_while" data-reference-type="ref"
data-reference="listing:calc_while">[listing:calc_while]</a> 
---

Odaberi operator (+,-) ili unesi "i" za izlaz: + Unesi prvi broj: 3.14
Unesi drugi broj: 25

Rezultat je: 28.14

---

Odaberi operator (+,-) ili unesi "i" za izlaz: - Unesi prvi broj: 2
Unesi drugi broj: 7

Rezultat je: -5.0

---

Odaberi operator (+,-) ili unesi "i" za izlaz: x

GREŠKA: Odabrana je nepoznata operacija, pokušaj ponovo!

---

Odaberi operator (+,-) ili unesi "i" za izlaz: + Unesi prvi broj: 42
Unesi drugi broj: neću

GREŠKA: Oblik broja nije prepoznat! Pokušaj ponovo.

---

Odaberi operator (+,-) ili unesi "i" za izlaz: I

--- 
Program je završio s radom, pritisni \<enter\> za kraj.

</div>

Ipak, program je prebanalan kako bi bio od koristi kao stvaran
kalkulator. Recimo da želimo zadovoljiti još barem dvije mogućnosti:

1.  lagano dodavanje novih operacija u program, uključujući i onih koje
    zahtijevaju unos samo jednog operatora

2.  korištenje drugih oblika brojeva, poput decimalnih brojeva sa
    zarezom umjesto točke i brojeva koji sadrže razdjelnik tisućica

Mogli bi sada ovaj program raspisati kako bi zadovoljili opisane
mogućnosti, ali ovo zapravo ne bi bila dobra ideja. Naime, naš program
postaje kompleksniji i kompleksniji i u ovom obliku će ga dakle biti sve
teže i teže održavati i nadopunjavati. Ovaj program je također napisan
posve proceduralno: svi reci kôda se izvršavaju jedan za drugim. To je
recept koji slijedimo od retka do retka. Bolje bi bilo prvo naučiti
definirati vlastite funkcije i vrste podataka pa se zatim vratiti na
ovaj problem kad budemo naoružani znanjem kako kôd generalizirati i
apstrahirati.

[^1]: Koju vrstu vrijednosti vraća funkcija `input`?

## Pogodi broj

Implementirajmo još jedan jednostavan program: igru "pogodi broj."
Zamislimo prvo ovu igru kao da je igraju dvije osobe. Jedan igrač tajno
odabire broj u nekom rasponu, na primjer između jedan i sto. Drugi igrač
zatim pokušava pogoditi broj tako što kaže neki broj koji je prvi igrač
mogao odabrati i kaže ga prvom igraču. Prvi igrač tada odgovara s
"Točno!" ukoliko je drugi igrač pogodio broj ili s "Ne, odabrani broj je
veći." ili "Ne, odabrani broj je manji." kako bi dao drugom igraču
dodatne informacije za pogađanje broja.

Kako ovo isprogramirati? Korisno je prvo riječima opisati
najjednostavniji oblik ovog programa.

1.  program mora odabrati slučajan broj u određenom rasponu

2.  program mora obavijestiti korisnika o tome u kojem rasponu se traži
    broj

3.  korisnik mora unijeti neki broj

4.  program mora provjeriti da li je taj broj odabrani broj i zatim:

    1.  ako je korisnik pogodio broj, ispisati mu da je uspješno završio
        igru

    2.  ako korisnik nije pogodio broj, ispisati mu da li je traženi
        broj veći ili manji i zatražiti ga da unese novi broj

5.  koraci 3. i 4. se moraju ponavljati sve dok korisnik ne uspije
    pogoditi broj

Kao što vidimo, u ovom programu potrebna nam je mogućnost odabira nekog
slučajnog broja. Ovo je česta potreba u programiranju pa većina
operativnih sustava i programskih jezika uključuje ovu mogućnost. Za
vježbu, pokušajte sami pronaći kako s Pythonom generirati slučajan
cijeli broj. Ovakve potrebe, naime, ne valja učiti na pamet već se
potrebno moći sam snaći pretraživanjem dokumentacije ili weba.

**Pokušajte sami implementirati opisani program prije no što nastavite
čitati skriptu!**

Kada pokrenemo prikazani program i unosimo brojeve sve dok ne pogodimo
traženi broj ispis izgleda otprilike ovako:

<div class="pythonp">

<a href="#listing:pogodi_broj_1" data-reference-type="ref"
data-reference="listing:pogodi_broj_1">[listing:pogodi_broj_1]</a>
Pogodi broj između 1 i 100. Pogodi broj: 50 Nije točno! Broj je veći.
Pogodi broj: 75 Nije točno! Broj je veći. Pogodi broj: 87 Nije točno!
Broj je veći. Pogodi broj: 95 Nije točno! Broj je veći. Pogodi broj: 97
Nije točno! Broj je manji. Pogodi broj: 96 BRAVO!

</div>

Kao što vidimo, u Pythonu je odabir slučajnih brojeva potpomognut
standardnim modulom `random`. Funkcija za odabir slučajnih cijelih
brojeva zove se `randint` i njeno korištenje za odabir slučajnog broja
između 1 i 100 izgleda ovako: `n = random.randint(1, 100)`. Ova funkcija
uključuje obje granice kao mogući rezultat, odnosno u prijašnjem slučaju
mogu se odabrati i `1` i `100`. Naravno, ovo su detalji koje također
nije potrebno znati na pamet, jednostavno je previše toga i detalji se
mogu razlikovati među programskim jezicima. Sjetite se da ako nas
zanimaju detalji vezani za tu funkciju, to možemo lako dobiti tako što u
Python komandnu liniju uvezemo modul random s `import random`, a zatim
izvršimo `help(random.randint)`.

U svakom slučaju, ovo je relativno jednostavan program koji opet
demonstrira mogućnosti petlje `while`. Vježbe radi, doraditi ćemo ga
kako bi demonstrirali razlike između petlji `for` i `while`. Program
sada korisniku dopušta pogađanje broja bilo koji broj puta. Kako
doraditi program da dopušta samo određen broj pokušaja? Drugim riječima,
ako korisnik prebaci, na primjer, pet ili deset pokušaja, program mu
treba javiti da nije uspio pogoditi broj u dozvoljenom broju pokušaja i
završiti igru.

Pokušajte sami implementirati ovu nadogradnju.

Rješenje koje koristi petlju `while` bi moglo izgledati ovako. Korisniku
smo u ispisu prikazali i broj pokušaja.

Ovo možemo riješiti i petljom `for`. Sada naime, znamo da kod želimo
ponoviti točno n puta (dozvoljen broj pokušaja) što pogoduje korištenju
petlje while. Prikazano je i dobar primjer za korištenje mogućnosti
`for ... else`.

Rješenje petljom `for` ima par linija kôda manje i nekima može biti
elegantnije. U ovom slučaju svejedno je koji pristup odaberemo pa je
najbolje odabrati onaj koji nam je samima najlogičniji. U oba slučaja
program će se ponašati identično i njegovo izvršavanje može proizvesti
sljedeći ispis:

<div class="pythonp">

<a href="#listing:pogodi_broj_2" data-reference-type="ref"
data-reference="listing:pogodi_broj_2">[listing:pogodi_broj_2]</a> i <a href="#listing:pogodi_broj_3" data-reference-type="ref"
data-reference="listing:pogodi_broj_3">[listing:pogodi_broj_3]</a>
Pogodi broj između 1 i 100. Pogodi broj (pokušaj 1/5): 50 Nije točno!
Broj je veći. Pogodi broj (pokušaj 2/5): 75 Nije točno! Broj je veći.
Pogodi broj (pokušaj 3/5): 87 Nije točno! Broj je veći. Pogodi broj
(pokušaj 4/5): 94 Nije točno! Broj je manji. Pogodi broj (pokušaj 5/5):
90 Nije točno! Broj je veći. Nisi uspio pogoditi traženi broj u
dozvoljenom broju pokušaja!

</div>

**Ovaj program je sada više-manje gotov.**

# Tekst na računalu

Prije no što se bacimo na programiranje s tekstom, korisno je razumjeti
kako računalo barata tekstom jer se to razlikuje od teksta zapisanog na
papiru ili kakvoj drugoj materijalnoj podlozi.

## SOS

Kako bi u opasnosti pozvali u pomoć ako vikanje ne pomaže? Recimo da se
radi o brodolomcu na pustom otoku ili brodu u opasnosti. Međunarodni
signal za pomoć se odašilje tako tako što pošaljemo tri kratka impulsa
(na primjer tri kratka zvuka ili tri kratka bljeska džepnom lampom),
zatim tri duga impulsa pa opet tri kratka impulsa. Ovaj signal se naziva
SOS i međunarodno je priznat signal za poziv u pomoć koristeći se
**Morseovom abecedom**. Originalno je razvijen za potrebe brodova u
nevolji, a koristi se od početka 20-og stoljeća. SOS je s vremenom
postao dovoljno poznat da se kasnije počinje koristiti za potrebe
odašiljanja poziva svima koji su dovoljno blizu da ga prime, a i kao
motiv u popularnoj kulturi poput glazbe. Također, SOS nije kratica za
ništa specifično. Odabran je radi distinktivnosti signala čime se
garantira njegova iskoristivost, a time se i olakšalo prihvaćanje
signala kao međunarodnog standarda.

Ovdje nas ne zanima toliko signal SOS koliko Morseova abeceda.
Preciznije ju možemo zvati Morseov **kod**. Taj kod se sastoji od dva
elementa: impulsa i stanke. Impuls može biti kratki ili dugi. Dugi
impuls traje kao tri kratka impulsa. Stanka služi pravljenju razmaka
između riječi i rečenica. Impulsi se mogu poslati bilo čime što se dobro
prenosi na velike udaljenosti. Primjeri uključuju zvuk, svjetlo, strujne
impulse i radio valove. Zvuk i svjetlo je relativno lako proizvesti bez
napredne tehnologije, ali otežavaju standardizaciju i iskoristivost.
Strujni impulsi su sigurniji za prijenos u lošim uvjetima, odnosno kada
postoji buka u komunikacijskom kanalu (npr. zvuk se neće prenijeti u
bučnim situacijama, a svjetlo je uglavnom iskoristivo noću), ali oni
zahtijevaju provedenu žicu. Ova tehnologija postaje najiskoristivija s
radio valovima koji omogućuju bežičnu komunikaciju, a kasnije ju
zamjenjuje prijenos ljudskog glasa putem istog medija. Kod je originalno
razvijen za potrebe električnog telegrafa. Zanimljivo je i da je to
posve digitalna metoda komunikacije budući da je signal ili prisutan ili
nije i to bez obzirom kojom se metodom prenosi.

Ono što nam je ovdje zanimljivo je kako Morseov kod kodira znakove. SOS
se dakle sastoji od tri kratka, tri druga, tri kratka impulsa. Ovo bi
tekstom mogli zapisati kao (...—...). Slovo S je dakle kodirano kao
(...), a slovo O kao (—). Svako slovo prima varijabilan broj impulsa.
Slovo koje se češće koristi u engleskome govoru je zakodirano s manjim
brojem znakova. Slovo E je tako jednostavno zakodirano s (.). e!

Važno je primijetiti da je Morseov kod posve odvojen od bilo kakve
tipografije, odnosno "crteža slova" i pozicioniranja teksta na podlogu.
Kada njime prenesemo slovo "e", to je točno to slovo, ali je posve
odvojeno od prikaza tog slova. Za komunicirati dodatne značajke tog
slova, poput fonta, podebljanja ili nakošenosti, potrebne su nam dodatne
informacije koje u ovom slučaju samo otežavali komunikaciju za razliku
od tiskanog teksta u kojemu je omogućuju i potencijalno olakšavaju.

<div class="important">

Digitalan tekst Pošaljite signal SOS lupkajući o stol. Upravo ste
prenijeli digitalni, ali ne i elektronički tekst. Kako nakositi ili
podebljati slova? Kako promijeniti font? Razmišljanjem o tim pitanjima
doći ćete do razumijevanja razlike digitalnog teksta od teksta kakvim ga
poznajete s papira, pergamene, papirusa ili zida pećine. Takav tekst je
zapisan prikazom, a digitalan tekst se prenosi kodom koji nema nikakve
veze s prikazom teksta za potrebe njegova prenošenja.

</div>

## Kodiranje teksta

Napomenuli smo da SOS kodiramo Morseovim kodom. U ovom smislu, "kod" je
sustav pravila za konverziju informacija iz jednog oblika u drugi za
potrebe komunikacije. U ovom značenju "kodiranje" možemo shvatiti kao
"šifriranje", ali važno je zapamtiti da se u ovom tekstu riječ "kôd"
uglavnom koristi kako bi označila "programski kôd" što je drugo značenje
te riječi. Iako konceptu "kodiranog teksta", kao i riječi "šifra", često
pridodajemo koncept tajnosti, kodirani tekst vrlo često nije tajan.
Dapače, kako bi bio široko korišten, taj sustav pravila mora biti javno
dostupan i standardiziran. U ovom smislu "kodirana komunikacija" se
najčešće provodi između ljudi i strojeva, odnosno informacije kodiramo
kako bismo mogli koristiti strojeve za prijenos istih. Prijevod slova
engleske abecede i brojeva na Morseov kod kao i pravila prijenosa su
vidljiva na sljedećoj slici. Primijetite da točna dužina impulsa nije
propisana, samo odnos između kratkog i dugog signala. U načelu čim brže
možemo poslati dugi signal, tim bolje sve dok se može dekodirati.

Prijevod teksta u neki kod nazivamo **kodiranje** (eng. *encoding*).
Prijevod iz koda u tekst nazivamo **dekodiranje** (eng. *decoding*). Kad
odvedemo ovu ideju dovoljno daleko dolazimo i do ljudskog jezika.

Dapače, zašto tekst zovemo "t e k s t"? Ta riječ ima svoju etimologiju i
potiče od latinskog *textus* što znači "satkan", odnosno koji je nastao
tkanjem. Radi se dakle o prenesenom značenju za potrebe suvremenijeg
koncepta ili korištenja, ali kad bi razmišljali o jeziku do samih
početaka vidjeli bi da je sam ljudski jezik na neki način kôd: to je
standardizirani sustav kodiranja stvari i koncepata radi prenošenja
informacija.

Ipak, ovaj tekst nećemo širiti do problema jezika već ćemo se fokusirati
na stroj koji nam je najvažniji za potrebe ovog gradiva: suvremeno
računalo. To je elektroničko digitalno računalo pa je glavni oblik
kodiranja teksta koji nas ovdje interesira zapisivanje teksta putem
binarnog koda, odnosno putem nula i jedinica jer je to sve što možemo
pohraniti u računalnu memoriju. Pojednostavljeno rečeno: struje ili ima
ili nema i to je upravo što nula i jedan u ovom kontekstu znače.

## Tekst i računalo

Tekst na računalu je neprekinuti niz znakova. Za razliku od Morseovog
načina kodiranja, ne postoji "praznina". Svaka promjena u tekstu je
znak. Razmak je znak. Prelazak u novi redak je znak. Sav ostali "bijeli
prostor" je znak. Velika i mala slova su različiti znakovi. Kada kažemo
"običan tekst" (eng. *plain text*) referiramo se samo na reprezentaciju
znakova u računalnoj memoriji bez ikakvih informacija o tipografiji,
odnosno o obliku slova (tj. fontu), o razmaku između slova, riječi i
redaka, o naslovima, paragrafima i razmaku među njima i bez ikakvog
koncepta "stranice" poput margina, orijentacije i sličnog. Običan tekst
jednostavno ne barata tim konceptima već se samo sastoji od "šifri" za
znakove u memoriji računala. Kako bismo zapisali spomenuto potrebno nam
je još teksta koji opisuje drugi tekst i govori stvari poput "ovaj izraz
je naslov", "ovaj izraz je podebljan", "ovaj izraz je uži od ostatka
teksta i treba ga prikazati drugim fontom". Ovaj koncept nazivamo
"označavanje teksta", a o tome ćemo nešto detaljnije kasnije.

<div class="important">

Zapis i prikaz računalnog teksta Računalni tekst je zapisan kodom, a
prikaz mu se dodjeljuje pravilima. Kada gledamo prikaz običnog teksta na
ekranu, računalo koristi dodatna formalna pravila kako bi svakom znaku
dodijelilo vizualni izričaj.

</div>

Šifra za jedan znak je dakle niz nula i jedinica u memoriji od kojih
određen broj predstavlja neki znak, na primjer slovo "a". Za razliku od
zida pećine ili papira (na koje slova "crtamo"), sam prikaz slova "a" je
nevezan za memorijski zapis ovog slova već je to druga razina kad ovoj
šifri dodijelimo neki proizvoljno odabran font. To slovo u memoriji
dakle nema niti veličinu znaka niti podržava koncepte kao što su
podebljanost ili nakošenost. To je jednostavno šifra za slovo "a", a
najčešće korištena šifra za to slovo je 01100001. U ovom smislu, nula i
jedinica su znamenke binarnog brojevnog sustava i individualnu nulu ili
jedinicu nazivamo bit. Osam bitova nazivamo bajt.

### ASCII

Tekst na računalu je dakle jedan neprekinuti niz znakova od kojih je
svaki kodiran (i.e. šifriran) s određenim brojem bitova. Kada bi znak
kodirali s jednim bitom podržavali bi samo dva znaka koja bi odgovarala
kodovima 0 i 1. Dva bita podržavaju četiri znaka. Broj različitih
kombinacija (*r*) od određenog broja znakova (*n*) je jednostavno
$`n^r`$. Šest bitova, šest nula ili jedinica, podržava dakle 64
različite kombinacije putem kojih možemo zakodirati 64 različitih
znakova, sedam bitova 128, a osam bitova 256. Početak kodiranja znakova
za potrebe računala se temeljio na telegrafskim šiframa i idejama. Tako
1963 nastaje ASCII (American Standard Code for Information Interchange)
koji definira 128 znakova za potrebe teksta na računalu.

Svaki znak je dakle kodiran sa 7 bitova što automatski znači i
memorijsko zauzeće. Od ovih znakova njih 94 su znakovi s vizualnom
reprezentacijom (eng. *printable characters*). To su 26 slova engleske
abecede u malim i velikim varijantama (i.e. 72 slova), 10 arapskih
znamenki, 32 interpunkcijska znaka i 32 kontrolna znaka (od kojih je
većina zastarjela). Svi znakovi osim kontrolnih su prikazani u Tablici
<a href="#tab:ASCII" data-reference-type="ref"
data-reference="tab:ASCII">[tab:ASCII]</a>.

<div class="center">

</div>

Tablica ne sadrži znakove koji nemaju vizualnu reprezentaciju na način
na koji to imaju slova, brojevi i interpunkcija. Među ovim znakovima se
svakako najčešće koristi i najpoznatiji nam je razmak. U suvremenijim
standardima postoje više vrsta razmaka i ova vrsta znakova se naziva
"prazan prostor" (eng. *whitespace*) u koji pripadaju i znakovi za novi
redak kao i tabulator (razmak varijabilne dužine).

Kako bi dobili dojam što su razni kontrolni znakovi, zanimljivo je
spomenuti znakove s kojima i danas označavamo prelazak u novi redak. To
su znakovi *carriage return* i *line feed*. Kada se na ovakve znakove
želimo referirati u tekstu običnim znakovima to tipično činimo kroz  
r ili CR (*carriage return*) i  
n ili LF (*line feed*). Na Windows sustavima se kraj retka označava s
oba ova znaka (  
r  
n), a na UNIX sustavima samo sa  
n. Većina suvislog softvera za rad s običnim tekstom će znati tretirati
oba stila pa se oko ovoga ne trebamo previše zabrinjavati. Ono što je
zgodno znati je da kada stisnemo tipku *enter* odnosno *return* kako bi
prešli u novi redak da je ono što računalo zapravo učini je da umetne
ove znakove u tekst. Kao što smo već ranije rekli, tekstualni zapis
zapravo nema koncepte "redaka" već je jedan neprekinuti niz znakova. On
jednostavno koristi kontrolne znakove koji označavaju "ovdje je prijelaz
u novi redak". Ali sve to nam još uvijek ne govori *što* su ti znakovi.
Odakle potiču? Potiču s pisaće mašine i sličnih tehnologija.

Na posve mehaničkim modelima, valjak na pisaćoj mašini se pomiče kako
tipkamo te ga je na kraju retka potrebno vratiti na početnu poziciju.
Ovo je *carriage return*. Zatim ga je potrebno zarotirati kako bi prešli
u novi redak. Ovo je *line feed*. Ovi koncepti su zakodirani kao znakovi
te ih i danas koristimo na suvremenim računalima za prelazak u novi
redak.

U svakom slučaju, ASCII standard je definirao šifrarnik koji je
propisivao 7-bitne šifre za znakove i tako je podržavao njih 128. Među
ovim šiframa su se nalazila samo slova engleske abecede, a i bez previše
razmišljanja znamo da na svijetu postoji puno puno više od 128
različitih znakova.

Ovakav šifrarnik nazivamo **kodna stranica** (eng. *code page*). To je
dakle šifrarnik putem kojeg računalo prevodi niz nula i jedinica u neki
znak.

### Prošireni ASCII

ASCII standard zapravo nije razvijen za računala već za telegrafiju.
Nedostaju mu koncepti potrebni čak i za engleski jezik kao što su to
posebni znakovi za oblikovanje teksta, više vrsta razmaka i matematički
simboli poput ≠, ≥ i ≈. U 1970-ima su računala standardizirala dužinu
bajta kao 8 bitova. To je otvorilo i put 8-bitnim kodnim stranicama koje
omogućuju duplo više znakova ($`2^8 = 256`$) no što je to omogućavao
ASCII. Ipak, 256 znakova je još uvijek drastično malen broj kada bismo
pokušali napraviti kodnu stranicu koja bi zadovoljavala potrebe više
naroda s različitim abecedama odjednom. Ovo posebno vrijedi kod naroda
koji ne koriste latinično pismo. ASCII tablicu kao i američku proširenu
ASCII tablicu možemo lako naći *online* u različitim oblicima (tablica,
tekst, slika), jedan od kojih je dostupan
[ovdje](https://www.ascii-code.com).

Prva strategija kojom se ovo krenulo rješavati je tako što se razvio
veliki broj kodnih stranica koje su najčešće koristile 128 znakova
propisanih ASCII-em te dodatnih 128 znakova koje su ovisile o jeziku i
računalu. Ove kodne stranice, međutim nisu standard poput ASCII-a, već
su ih razvijale tvrtke koje su razvijale komercijalne računalne sustave.
Među njima su nam vrlo poznata imena poput IBM, Microsoft i Apple.

### Kaos u kodiranju

Na ovaj način je međutim nastao kaos u kodiranju teksta. Najveći problem
je bio to što tekstualna datoteka odnosno običan tekst u računalnoj
memoriji ne sadrži eksplicitan zapis koju kodnu stranicu neki tekst
koristi već računalo to pretpostavlja iz opće prihvaćenih standarda i
lokalnih postavki sustava. Prema
[Wikipediji](https://en.wikipedia.org/wiki/Extended_ASCII), tokom godina
je razvijeno više od 220 DOS i Windows kodnih stranica koje je razvijao
Microsoft i više nego 186 EBCDIC kodnih stranica koje su IBM-ova inačica
kodnih stranica. A to su samo neke od definiranih kodnih stranica. Kada
se slučajno koristila kriva kodna stranica za dekodiranje, neka slova bi
se zamijenila za druge znakove ili za kriva slova!

Radi ovoga još dan danas u određenim uvjetima možemo vidjeti krive
znakove za hrvatska slova, kao što je to slučaj na npr. računima i malim
ekranima na različitim automatima. Dugo godina se radi toga povlačila
navika da se tekst na hrvatskom (na primjer prilikom pisanja
elektroničke pošte) zapisivao bez palatala, odnosno "č" i "ć" su se
pisali kao "c", a "š" kao "s". U suprotnom bi se znakovi prečesto
"raspali" u prijenosu i postali nešto nečitljivo ili jednostavno posve
druga slova.

Drugim riječima, bio je čest slučaj da se kodnu stranicu trebalo
nagađati i da su se znakovi krivo dekodirali. U ovakvom sustavu je bilo
teško raditi pa se pojavila ideja univerzalne kodne stranice. Također,
računala su postajala sve brža, a memorija sve veća pa je i štednja
memorijskog prostora za potrebe teksta postajala sve manji problem. U
tom smislu nastaje UNICODE, pokušaj da se popišu svi znakovi na svijetu.

### UNICODE

Kažu da je za pročitati novine na suvremenom kineskom potrebno znati 2-3
tisuće znakova. Ovo je samo po sebi već znatno više no što to dopuštaju
8-bitne kodne stranice. Kada pridodamo tome da je moguće lako zamijeniti
putem koje je kodne stranice tekst kodiran i tako pogrešno
interpretirati znakove nameće se sljedeće rješenje: popisati sve znakove
na svijetu.

[UNICODE](https://home.unicode.org) (*Universal Coded Character Set*) je
međunarodni standard koji se trudi popisati sve znakove na svijetu. To
je katalog svih znakova na svijetu koji svakom znaku dodjeljuje
jedinstvenu oznaku bez obzira na različiti hardver i softver koji
koristi. UNICODE 12.1 sadrži podatke o 137 994 različitih znakova. Svaki
znak ima svoj kontrolni broj putem kojeg se možemo nedvojbeno referirati
na neki znak.

Koliko bajtova nam je dakle potrebno da bi zakodirali sve UNICODE
znakove za potrebe računala. Kao što već znamo, jedan bajt je osam
bitova. U osam bitova stane $`2^8`$ različitih kombinacija, odnosno na
ovaj način možemo prikazati 256 brojeva pa tako i 256 znakova. U 16
bitova stane 65 536 znaka. Ipak, UNICODE ima više od toliko znakova pa
dva bajta nisu dovoljna. Kada bi koristili 32 bita omogućili bi 4 294
967 296 znakova! E to nam je daleko više nego dovoljno za sve znakove na
svijetu i ostavlja dovoljno prostora za dodavanje novih znakova. Kada bi
svakom UNICODE znaku dodijelili njegovu brojčanu šifru, dobili bi
kodiranje koje za svaki znak koristi 4 bajta. Ova kodna stranica se
naziva UTF-32.

Ovo bi dakle riješilo problem. Ipak, ovakav pristup ima dva
fundamentalna nedostatka:

1.  Svaki tekst zauzima četiri puta više mjesta u memoriji (što utječe i
    na prijenos podataka npr. putem interneta)

2.  Najčešća slova u mnogim tekstovima, poput "e" i ostalih slova
    zajedničkih svim latiničkim pismima, više nisu kompatibilna sa
    starijim, efikasnijim načinom zapisivanja

U praksi se primijetilo da se znakovi iznad šifre 65 536 koriste vrlo
rijetko pa je napravljena i druga kodna stranica za UNICODE koja može
zakodirati samo prvih 65 536 znakova i koristi dva bajta informacija.
Ova kodna stranica se zove UTF-16. Ona dakle za duplo smanjuje potreban
prostor u memoriji po znaku, ali oba problema su još uvijek prisutno.
Iako je prvi problem umanjen za duplo, to je još uvijek više duplo više
memorije no što je potrebno za čuvanje i prijenos teksta zakodiranog u
8-bitnoj kodnoj stranici.

Također, postoji i problem da različite arhitekture hardvera računala
pohranjuju bajtove u različitom redoslijedu pa UTF-32 i UTF-16 moraju
razrješavati ovaj problem koristeći se posebnim početnim znakom. Detalji
nam ovdje nisu potrebni, ali ovaj problem demonstrira kako u nekim
slučajevima postoje i manje očiti problemi kod kodnih stranica.

### UTF-8

UTF-8 je kodna stranica za UNICODE koja rješava probleme UTF-16 i UTF-32
i danas je *de facto* standard za kodiranje teksta, posebno kada se radi
o web stranicama. Naime kod web stranica je kodna stranica formalno
deklarirana i javno su dostupne pa je ovo bilo lako istražiti, kao što
se vidi npr. na
[ovom](https://en.wikipedia.org/wiki/UTF-8#/media/File:Utf8webgrowth.svg)
grafikonu.

UTF-8 rješava primarni problem kodiranja UNICODE-a tako što svakom znaku
dodijeljuje varijabilan broj bajtova. Na taj način je svim znakovima
definiranim u ASCII-u dodijeljen jedan bajt koji odgovara ASCII kodnoj
stranici. Drugim riječima, ako imamo tekst koji ne koristi niti jedan
znak koji nije definiran ASCII-em, tada je UTF-8 kodirani tekst
identičan ASCII kodiranom tekstu.

Za znakove koji nisu u ASCII standardu, UTF-8 koristi više bajtova.
Znakovi iz fonetskih pisama i dodatna interpunkcija tipično zauzimaju
dva bajta. To je i slučaj s hrvatskim slovima č,ć,đ,š i ž. Ostali
znakovi, poput kineskog pisma zauzimaju tri bajta.

Radi ove mogućnosti u ovaj tekst možemo zapisati i ovo:
不鸣则已，一鸣惊人 (U slobodnom prijevodu, "Ptica ne pjeva zato jer zna
odgovore već zato jer zna pjesmu.").

Drugim riječima, **najvažnija kodna stranica danas, koja rješava
probleme razmjene teksta** je **Najčešća slova u mnogim tekstovima,
poput "e" i ostalih slova zajedničkih svim latiničkim pismima, više nisu
kompatibilna sa starijim, efikasnijim načinom zapisivanja** i preporuka
je koristiti ovu kodnu stranicu prilikom pisanja bilo kakvog teksta, bez
obzira da li se radi o običnoj tekstualnoj datoteci, e-mail poruci,
zapisu HTML-a ili Pythona i drugog programskog kôda.

Sada kad bolje razumijemo koncept digitalnog elektroničkog teksta i
obične tekstualne datoteke, pogledajmo kako se s njime radi u Pythonu.

# Rad s tekstom u Pythonu

Digitalan tekst je dakle niz znakova i uz brojeve je najčešća vrsta
vrijednosti. Kada razmislimo, niz znakova nije jednostavna vrsta
vrijednosti jer se može raščlaniti na sastavne dijelove odnosno
znakove[^1]. Ipak, kad radimo s tekstom vrlo često ga promatramo kao
vrijednost koja može sadržavati nula ili više znakova. Tekst od nula
znakova se naziva "praznim tekstom" (eng. *empty string*) i na neki
način odgovara konceptu nule kod brojeva.

U Pythonu se tekst čuva kroz vrstu podataka `str`, što je skraćeno od
engleske riječi *string* odnosno “niska”. Svaka vrijednost koja je
zapisana pod navodnicima se smatra tekstom. Ovo je vrlo važno zapamtiti
jer vrijedi za mnoge računalne tehnologije: ako je nešto pod
navodnicima, to se smatra točno tim tekstualnim znakovima i ne stoji za
nešto drugo. Jedina razlika među tehnologijama je koji se navodnici
dopuštaju za označavanje teksta, a Python i mnogi suvremeni jezici
dopuštaju korištenje bilo apostrofa ili navodnika i korištenje oba znaka
ima isto značenje. Koje znakove ćemo koristiti za označavanje teksta,
najviše ovisi o tome da li sam tekstovni niz već sadrži apostrofe ili
navodnike. Ovo je najjednostavnije objasniti primjerima:

``` python

>>> tekst = "ovo je u navodnicima pa se smatra tekstom" 

>>> tekst = ’ovo je u apostrofima pa se isto smatra tekstom’ 

>>> tekst = "ako je ’ u tekstu moramo koristiti navodnike" 

>>> tekst = ’ako je " u tekstu koristi apostrofe’ 

>>> tekst = "ovaj "tekst" nije validno zapisan" SyntaxError: invalid syntax
```

U primjeru gore su prikazani najčešći načini zapisivanja teksta u Python
kôdu. U ovom slučaju, samo zadnji redak nije valjan jer koristi iste
navodnike unutar teksta kao i za obilježavanje teksta. U sljedećem
primjeru su prikazane neke početničke greške koje su katkad teško
uočljive.

Svaki niz znakova u Python kôdu, kao i općenito u računalnim
tehnologijama, koji je omeđen navodnicima smatra se tekstom odnosno
točno tim slijedom znakova koji ne stoje za nešto drugo. Na primjer,
`print(tekst)` će ispisati vrijednost pridruženu varijabli `tekst` ili
javiti grešku ako varijabla tekst nije definirana, a `print('tekst')`
jednostavno ispisuje tekst `"tekst"`. Također, vrijednost `'1'` se
smatra tekstom, a ne brojem, jer je pod navodnicima. Zbrajanje ove
vrijednosti s brojem javlja grešku jer se pokušavaju zbrojiti tekst i
broj što nije definirana radnja. Drugim riječima, računalu je ovo kao da
smo mu zadali operaciju "broj 1 + znak a" koja nije definirana među ovim
vrstama vrijednosti.

Sada smo se i prvi put formalno sreli s pogreškom. Prilikom
programiranja to je posve normalno i tko god da programira proizvodi i
pogreške. Ako do sada niste vidjeli ni jednu, šanse su da niste
eksperimentirali s vlastitim kôdom. Kako jezik prijavljuje pogreške i
kako možemo time upravljati će biti prikazano u zasebnom poglavlju, ali
recimo za sada da je prilikom javljanja pogreške najvažnije pročitati
zadnju liniju jer je upravo ta linija krajnja poruka korisniku što se
zapravo dogodilo. U primjeru ranije to je
`TypeError: Can't convert 'int' object to str implicitly` što možemo
prevesti kao "Greška u vrsti vrijednosti: int se ne može implicitno
pretvoriti u str". Drugim riječima, `int` vrijednost moramo prvo
eksplicitno pretvoriti u tekst ako ju želimo spajati s tekstom jer
radnja koja se provodi putem operatora `+` nije definirana između vrsti
vrijednosti `int` i `str`. Linije prije zadnje su početnicima manje
važne, često ih ima znatno više no u ovom primjeru i služe pronalaženju
gdje se greška dogodila u kôdu što je posebno korisno kod većih
programa.

Primijetimo također da je prikazan način označavanja teksta primjeren za
kraće tekstove u jednom retku. Što ukoliko želimo definirati tekst koji
se sastoji od više redaka? Osim označavanja teksta jednostrukim
navodnicima ili apostrofima, tekst je moguće označiti i s trostrukim
navodnicima odnosno trostrukim apostrofima. Trik kod ovog načina
označavanja teksta je upravo da između trostrukih znakova možemo
normalno pisati prijelome retka, prazne linije i koristiti navodnike
kako hoćemo. Pogledajmo primjer:

``` python
Slobodan unos dužeg tekstalisting:tekst3 dugi_tekst = """ Ovdje možemo pisati tekst koji može normalno prelaziti u druge retke,ostavljati prazne retke, koristiti "duple navodnike" i ’apostrofe’ unutar tekstajednostavno uvlačiti tekst i slično! """
```

Jedini tekst koji ne smijemo koristiti u prošlom primjeru su tri
navodnika jedan za drugim. Da smo baš morali iskoristiti tri uzastopna
navodnika u tekstu, mogli smo iskoristiti trostruke apostrofe umjesto
trostrukih navodnika. U tom slučaju, naravno, ne bi smjeli koristiti tri
uzastupna navodnika, ali ovo su vrlo rijetki slučajevi.

Vrijedi spomenuti da je Python 3 orijentiran na Unicode tekst (odnosno
vrsta vrijednosti *str* podržava znakove iz svih jezika uključujući i,
na primjer, kinesko pismo i ćirilicu), a ne samo ASCII znakove (odnosno
uglavnom znakove iz engleskog govornog područja)[^2]. Što se naših
posebnih slova tiče, u sljedećem primjeru vidimo da ih možemo koristiti
bez posebnih koncepata:

``` python

>>> tekst = "Python 3 radi bez problema s čžšćđ" 

>>> print(tekst) python radi bez problema s čžšćđ
```

Isto vrijedi i za druga pisma poput ćirilice ili kineskog pisma.

Za razliku od brojeva, najosnovnije radnje s tekstom se provode putem
*metoda*, a ne putem *operatora*. Metoda je funkcija koja je vezana uz
neku određenu vrstu vrijednosti jer radi samo s tom vrstom vrijednosti.
Razlika između metode i funkcije je što se metoda uvijek koristi nakon
točke te prima vrijednost prije točke kao prvi implicitan parametar.
Korištenje metoda je zapravo vrlo intuitivno pa pogledajmo prvo primjere
koji prikazuju najčešće radnje s tekstom.

## Posebni znakovi i izbjegavanje posebnog značenja određenih znakova

## Česte radnje s tekstom

### Dohvat dijelova teksta

Tekst je zapravo niz znakova te iz tog niza možemo dohvatiti
individualne znakove kao i djelove teksta. To činimo koristeći se
pozicijom, odnosno indeksima, individualnih znakova i uglatim zagradama.
Pogledajmo primjer:

``` python

>>> tekst = "Monty Python i značenje života." 

>>> tekst[0] # dohvati prvi znak ’M’ 

>>> tekst[1] # dohvati drugi znak ’o’ 

>>> tekst[0:5] # dohvati znakove 0, 1, 2, 3, 4 ’Monty’ 

>>> tekst[6:12] # dohvati znakove 6, 7, 8, 9, 10, 11 ’Python’ 

>>> tekst[-1] # dohvati zadnji znak ’.’ 

>>> tekst[-2] # dohvati predzadnji znak ’a’ 

>>> tekst[0:tekst.find(’y’)] ’Mont’ # dohvati od prvog znaka pa sve dok se ne pojavi znak y prvi put 
```

Kao što vidimo dijelove tekstualnog niza možemo dohvatiti tako što nakon
tekstualne vrijednosti (odnosno varijable koja se na takvu vrijednost
referira) pišemo uglate zagrade u kojima se možemo koristiti pozicijama
znakova u tekstu. Prvi znak se smatra da je na poziciji 0. Ovo može
djelovati nelogično, ali na taj način neke stvari jednostavno "klikću"
bez da se mora dodavati ili oduzimati 1. Obzirom da je ovaj mehanizam
općenitiji od korištenja za dohvat dijelova stringova, imati ćemo
prilike dobiti dojam o svemu ovome još kasnije.

Ukoliko želimo dohvatiti raspon znakova tada u uglate zagrade pišemo
raspon indeksa gdje prvi i zadnji razdvajamo dvotočkom. Kod raspona
indeksa je pravilo da se prvi uvijek uključuje, a zadnji ne. Rješenje da
je prvi indeks 0 te da se kod raspona zadnji indeks ne uključuje je
dosta često u programskim jezicima.

Indeksima možemo brojati i unazad. -1 znači zadnji znak, -2 predzadnji i
tako dalje. Ovo je zgodna mogućnost jer kada nešto želimo dohvatiti s
kraja teksta, na ovaj način ne moramo znati koliko je tekst dugačak.

Također, neke metode stringova, poput metode `str.find`, vraćaju indekse
kao rezultat pa su vrlo korisne u ovom smislu.

Vrijedi i spomenuti da je dohvat nekog dijela vrijednosti (kod vrsta
vrijednosti koje to podržavaju) putem uglatih zagrada standardan način
"adresiranja" dijelova neke vrijednosti pa ćemo se s ovom mogućnošću još
više puta sresti kroz ovaj tekst i, kao što ćemo vidjeti kod struktura
podataka, riječ je o vrlo važnom konceptu.

### Promjena veličine slova

Vrlo česta radnja s tekstom je promjena iz velikih slova u mala i
obratno. Pogledajmo koje mogućnosti nam dopušta sama vrsta *str*:

``` python

>>> tekst = "cvrči CVRČI 10-ak cvrčaka" 

>>> tekst.lower() # pretvori sva slova u mala slova ’cvrči cvrči 10-ak cvrčaka’ 

>>> tekst.upper() # pretvori sva slova u velika slova ’CVRČI CVRČI 10-AK CVRČAKA’ 

>>> tekst.capitalize() # pretvori prvo slovo u veliko, a ostala u mala ’Cvrči cvrči 10-ak cvrčaka’ 

>>> tekst.title() # pretvori prvo slovo svake riječi u veliko, a ostala u mala ’Cvrči Cvrči 10-Ak Cvrčaka’ 

>>> tekst.swapcase() # velika slova u mala, a mala u velika ’CVRČI cvrči 10-AK CVRČAKA’
```

Kao što vidimo, postoji više metoda za promjenu veličine slova i iz
samih naziva kao i prethodnog primjera je poprilično jasno što rade. Sve
ove metode ignoriraju sve znakove u tekstu za koje "promjena veličine"
nema smisla, poput brojeva i interpunkcije.

Što se samih metoda tiče, glavna razlika od funkcije je što metode
hijerarhijski pripadaju određenim vrstama vrijednosti i što implicitno
primaju vrijednost prije točke kao prvi parametar. Kada izvršimo
`tekst.upper`)) to je isto kao da smo izvršili nepostojeću funkciju
`upper`tekst)). Razlog postojanju metoda je organizacija kôda. Na ovaj
način, metoda `upper` je svrstana pod vrstu vrijednosti `str` što je i
jedina vrsta vrijednosti s kojom ova metoda može raditi. Kada bi `upper`
bila funkcija, imali bi jako velik broj funkcija i za svaku bi morali
pamtiti na koju vrstu vrijednosti se odnos. Na ovaj način se izbjegao
taj problem jer su metode koje rade s određenom vrstom vrijednosti
hijerarhijski organizirane pod tu vrstu vrijednosti.

### Micanje znakova s početka i kraja teksta

Vrlo česta radnja kod pripreme teksta (posebno iz korisničkog unosa) je
micanje znakova s početka (lijeve strane) teksta i/ili kraja (desne
strane) teksta, ali ne i iz sredine. Najčešći slučaj u ovom kontekstu je
brisanje praznog prostora. Pogledajmo primjer:

``` python

>>> tekst = ’ korisnički unos ’ 
>>> tekst.lstrip() # left strip, ukloni prazan prostor s početka ’korisnički unos ’ 
>>> tekst.rstrip() # right strip, ukloni prazan prostor s kraja ’ korisnički unos’ 
>>> tekst.strip() # strip, ukloni prazan prostor s obje strane ’korisnički unos’
```

Metode `lstrip`, `rstrip` i `strip` pozvane bez parametara, dakle, miču
*prazan prostor* s lijeve, desne ili obje strane teksta. Prazan prostor
sačinjavaju različite vrste razmaka (ukjučujući, na primjer, tabulator i
tzv. razmak bez rastavljanja) i znakova za prijelom retka. Ovakvi
znakovi se često neželjeno nađu u tekstu koji je došao iz korisničkog
ručnog unosa, bilo radi pogrešnog unosa ili radi *copy/pasteanja*.
Budući da su ovi znakovi nevidljivi, korisnici ih često ne primijete
tako da u mnogim programima čim radimo s korisničkim unosom preventivno
uklanjamo razmake kako isti ne bi završili u zapisanim podacima.

Što ako želimo na ovaj način izbaciti neke druge znakove, a ne samo
razmake? Pogledajmo kako u sljedećem primjeru.

``` python

>>> tekst = ’.! 2000 .!’ 
>>> tekst.strip(’.’) # ukloni točku s početka i kraja ’! 2000 .!’ 
>>> tekst.strip(’.!’) # ukloni bilo koju kombinaciju točke i uskličnika s početka i kraja ’ 2000 ’ 
>>> tekst.strip(’ .!’) # ukloni kombinacije razmaka, točke i uskličnika s početka i kraja ’2000’
```

Metoda `strip`, dakle, prima jedan parametar koji je niz znakova i zatim
miče sve *kombinacije znakova* uključenih u taj niz s početka i kraja
teksta. Sve što vrijedi za metodu `strip`, vrijedi i za metode `lstrip`
i `rstrip`, a jedina razlika je da li će se znakovi micati s početka,
kraja ili s obje strane.

### Posebni znakovi i izbjegavanje posebnog značenja

U radu s tekstom je često potrebno raditi s posebnim znakovima koje ne
možemo reprezentirati s nekim individualnim vidljivim znakom. Najčešći
takvi slučajevi su vjerojatno znak za novi redak i znak za tabulator.
Kako uključiti ove znakove u stringove? Pogledajmo primjer:

``` python

>>> tekst = ’Ovaj tekstredaka’ 
>>> print(tekst) Ovaj tekst sadrži prijelome redaka 
>>> tekst = ’tekst počinje s tabulatorom’ 
>>> print(tekst) Ovaj tekst počinje s tabulatorom
```

Važan koncept pri radu s posebnim znakovima je korištenje znaka
*backslash*, odnosno "\\. Ovaj znak je u ASCII tablicu uvršten upravo
radi programiranja i to zato jer se rijetko koristi u jeziku. U
suvremenim programskim jezicima ovaj znak se često koristi kako bi
označio da znak nakon njega treba tretirati posebno. U primjeru
<a href="#listing:tekst8" data-reference-type="ref"
data-reference="listing:tekst8">[listing:tekst8]</a> vidimo kako se
koristi kako bi promijenio značenje znaka "n" u "novi red" (znak koji se
na engleskom zove *newline*) i značenje znaka "t" u "tabulator". Ova dva
znaka bi nam inače bilo teško zapisati u tekst budući da se radi o tzv.
nevidljivim znakovima odnosno praznom prostoru u tekstu.

Osim navedenog, *backslash* se koristi kao takozvani *escape character*.
To znači da ga koristimo kako bi negirali značenje nekog znaka koji bi
se inače posebno tretirao. Drugim riječima, ukoliko je znak nakon neki
poseban znak, tada se njegovo posebno značenje ignorira i tretira se kao
normalan znak. Na primjer, \\unosi znak *backslash* u tekst, a \\ unosi
navodnik u tekst koji neće poremetiti normalno korištenje navodnika za
označavanje teksta.

``` python

>>> tekst = "Ovaj tekst sadrži , ï b́ez da ti znakovi imaju posebno značenje" 
>>> print(tekst) Ovaj tekst sadrži   " i ’ bez da ti znakovi imaju posebno značenje
```

### Umetanje dijelova teksta

Vrlo česta i važna radnja s tekstom je umetanje dinamičnih dijelova
teksta u veći statičan tekst. Ovo je nalik popunjavanju tiskanih
formulara koji umjesto nekih dijelova teksta (gdje, na primjer, treba
upisati ime i prezime) imaju prazan prostor za to koji se često
naznačuje s "\_\_\_\_\_\_\_\_\_\_\_\_". Pogledajmo primjer:

``` python

>>> tekst = ’ Bi sam i ’ 
>>> tekst.format(’o’, ’vani’, ’ludo sam se zabavio!’) ’Bio sam vani i ludo sam se zabavio!’ 
>>> tekst.format(’la’, ’na predavanju’, ’bilo mi je dosadno :( !’) ’Bila sam na predavanju i bilo mi je dosadno :( !’
```

U prikazanom primjeru, znakovi "{}" se koriste u smislu
"\_\_\_\_\_\_\_\_\_\_\_\_" u tiskanim formularima, odnosno označavaju
rezervirano mjesto gdje se dodaje tekst. Vitičaste zagrade u tekstu
služe kako bi se putem metode `format` na njihovo mjesto ubacilo neki
tekst. U prethodnom primjeru, koristimo samo dva rezervirana mjesta i
poziv na metodu `format` ubacuje vrijednosti na njihovo mjesto prema
redoslijedu. Ovaj slučaj je praktičan kod kraćih tekstova, ali nije
podoban kad imamo puno mjesta u tekstu na koji želimo ubaciti
vrijednosti jer ih je lako zamijeniti. Metoda `format` nam stoga dopušta
i da imenujemo mjesta za ubacivanje i zatim u njih ubacujemo vrijednosti
prema tim imenima. Pogledajmo primjer:

``` python

>>> tekst = """ Bio sam u mjesto.Tamo sam radnja. Bilo mi je kako jer je vrijeme u mjesto bilo vrijeme. """ 
>>> t = tekst.format(mjesto = ’Zadru’, radnja=’se kupao’, kako=’sjajno’, vrijeme=’lijepo’) 
>>> print(t)Bio sam u Zadru.Tamo sam se kupao. Bilo mi je sjajno jer je vrijeme u Zadru bilo lijepo.
```

U ovom primjeru pojavljuje nam se novi koncept: *imenovani parametri
funkcija* (odnosno metoda). Svi parametri koje smo do sada koristili
slali smo funkcijama prema njihovim pozicijama jer se radilo o
jednostavnim slučajevima koji su uglavnom primali jedan do dva
parametra, a u ovom slučaju šaljemo ih imenovano. Metoda *format* prima
onoliko imenovanih parametara koliko smo ih naveli u tekstu koji se
"formatira". Imena u tekstu koji se formatira moraju, stoga, biti
validna imena za Python varijable!

Prikazani način slaganja teksta možda na prvi pogled djeluje samo kao
zgodan način spajanja različitog teksta, ali u praksi je vrlo često
korisna. Na primjer, na ovaj način možemo stvarati HTML ili XML kao i
stvarati razne izvještaje o radu programa ili njegovim rezultatima.

### Članstvo i zamjena

Postoji naravno još niz radnji koje možemo provoditi nad tekstom.
Dapače, tekst je vrlo kompleksna tvorevina za čiju obradu je moguće
napisati niz knjiga ovisno o vrsti teksta, procesima koje koristimo za
njegovu obradu te našim ciljevima. Pogledajmo zato ovdje samo još neke
česte radnje s tekstom:

``` python

>>> tekst = ’Ne da mi se ovo čitati.’# zamijeni sve znakove "a" sa znakom "x" 
>>> tekst.replace(’a’, ’x’) ’ne dx mi se ovo čitxt’ # može i s duljim nizovima 
>>> tekst.replace(’ne da mi se’, ’želim’) ’želim ovo čitat’# da li neki tekst sadrži znak ili drugi manji tekst 
>>> ’o’ in tekst True 
>>> ’u’ in tekst False 
>>> ’ovo’ in tekst True# prebroji koliko se puta pojavljuje neki tekst u duljem tekstu 
>>> tekst.count(’a’) 2 # pronađi poziciju na kojoj se prvi put pojavljuje neki tekst u duljem tekstu 
>>> tekst.find(’a’) 4
```

[^1]: Dapače, neki jezici razlikuju vrstu podataka "znak" (*char*) od
    vrste podataka "niz znakova" odnosno *string*.

[^2]: Pažnja, ovo vrijedi za Python 3 ne i za Python 2.

# Rad s tekstualnim datotekama

Rad s običnim tekstualnim datotekama važniji je no što se to možda čini
na prvi pogled. Na primjer, svaki program nastaje kao običan tekst,
cijeli WWW se zasniva na običnom tekstu, kao i razmjena podataka među
informacijskim sustavima. Čitanje i pisanje tekstualnih datoteka je
stoga neobično važno ne samo za programiranje već i za sveukupno
računarstvo.

Glavni mehanizam za čitanje i pisanje tekstualnih datoteka u Pythonu je
funkcija `open`. Ovisno o parametrima, ova funkcija pristupa nekoj
datoteci za potrebe čitanja iz nje ili pisanja u nju. Za razliku od
istoimene mogućnosti u programima s grafičkim sučeljem, dakle, funkcija
`open` samo rezervira određenu datoteku za pristup, a ne usnimava
sadržaj datoteke. Radi toga, ova funkcija služi i pisanju u datoteke, a
čak i stvaranju novih tekstualnih datoteka. Bez obzira da li čitali ili
pisali, nakon što se izvrše potrebne radnje s otvorenom datotekom, istu
je potrebno zatvoriti putem metode `close`. Pogledajmo kako zapisati
neki tekst u novu datoteku:

Funkcija `open` prima putanju do datoteke kao prvi parametar, mod rada
kao drugi parametar i dodatne parametre od kojih je vrlo korisna
specifikacija kodne stranice putem opcionalnog parametra `encoding`.
Dapače, preporučeno je uvijek definirati `encoding` prilikom čitanja i
pisanja jer u tom slučaju jasno kontroliramo kodnu stranicu našeg teksta
i time sprječavamo gubitak slova i ostalih znakova. U tom smislu, kodna
stranica "utf-8" je danas *de-facto* standard.

Putanja može biti apsolutna e.g. ("c:/direktorij/datoteka.txt") ili
relativna ("datoteka.txt" ili "direktorij/datoteka.txt"). Ukoliko je
putanja relativna, kao u našem primjeru, smatra se da je relativna od
direktorija u kojem se nalazi .py datoteka koju smo pokrenuli. Na
primjer, putanja "datoteka.txt" se odnosi na datoteku u istom
direktoriju u kojem je i pokrenuta .py datoteka. Putanja
"neki_direktorij/datoteka.txt" se odnosi na datoteku "datoteka.txt" koja
se nalazi u direktoriju "neki_direktorij" koji se pak nalazi u istom
direktoriju u kojem je i pokrenuta .py datoteka. U ranijem primjeru, u
istom direktoriju će nam se pojaviti datoteka "papiga.txt" s tekstom
koji smo naredili zapisati.

Funkicija `open`, može čitati postojeće datoteke, dodavati u postojeće
ili stvarati nove. To kontroliramo putem parametra `mode` koji možemo
shvatiti kao "mod rada" funkcije `open`. Pogledajmo kako dodati neke
retke u "papiga.txt" datototeku.

Korisni modovi za `open` su:

- **r** - čitaj; *default*

- **w** - stvori i piši; ako datoteka postoji, obriši sadržaj

- **x** - stvori i piši; ako datoteka postoji, javi grešku

- **a** - stvori i piši; ako datoteka postoji, nastavi pisati na kraj

Do sada smo samo pisali u datoteku. Čitanje je jednostavno drugi način
operacije funkcije `open`. Čitanje je zapravo zadani (eng. *default*)
način rada ove funkcije, ali u ovom poglavlju smo prvo stvorili novu
datoteku kako bi imali što čitati. Također, parametar `"r"` zapravo ne
treba navoditi jer se podrazumijeva, ali njegovim navođenjem se mod rada
jasnije vidi.

<div class="pythonp">

<a href="#listing:tekst_citanje" data-reference-type="ref"
data-reference="listing:tekst_citanje">[listing:tekst_citanje]</a> This
parrot is no more! He has ceased to be! ’E’s expired and gone to meet
’is maker! ’Is metabolic processes are now ’istory! ’E’s off the twig!
..... THIS IS AN EX-PARROT!!

</div>

Pogledajmo kako se petlja `for` može koristiti u kontekstu čitanja
teksta iz datoteke:

<div class="pythonp">

<a href="#listing:tekst_prebiranje" data-reference-type="ref"
data-reference="listing:tekst_prebiranje">[listing:tekst_prebiranje]</a>
1 This parrot is no more! 2 He has ceased to be! 3 ’E’s expired and gone
to meet ’is maker! 4 ’Is metabolic processes are now ’istory! 5 ’E’s off
the twig! 6 ..... THIS IS AN EX-PARROT!!

</div>

Drugim riječima, po otvorenoj datoteci se može iterirati po recima
teksta. Na ovaj način možemo raditi s datotekama bilo koje veličine pa
čak i onima koje nam ne stanu u memoriju jer u svakom trenutku imamo
samo jedan redak u memoriji, a ne cijeli tekstualni sadržaj neke
datoteke.

## Naredba `with`

Što će se dogoditi s datotekom ako slučajno ne pozovemo naredbu `close`?
Postoji šansa da se u datoteku nije zapisao sav tekst i da ona u
operacijskom sustavu ostane "rezervirana za pristup". Problem s do sada
prikazanim načinom zatvaranja datoteke nije samo u tome da možemo
zaboraviti provesti naredbu `close`, već se može dogoditi da se ona ne
provede radi ranije greške. Pogledajmo primjer:

Kako riješiti da se naredba `close` uvijek izvrši, bez obzira na
potencijalne ranije greške u kôdu? Iz onoga što do sad znamo, mogli
bismo probati s naredbom `try` i ukoliko iskoristimo i komponentu
`finally` u tome bi i uspjeli[^1]. Ipak, ovakvo rješenje se smatra
nezgrapnim i nije namijenjeno korištenje naredbe `try`. Radi ovakvih i
sličnih slučajeva se u noviji Python dodala naredba `with` koja je
postala idiom upravo za otvaranje i zatvaranje datoteka kao i slične
situacije.

Radi elegantnosti izvedbe i vezanu sigurnost, preporuča se koristiti
naredbu `with`. Prikazani način pristupa tekstualnim datotekama je stoga
idiom u novijem Pythonu, ali ne možemo u potpunosti shvatiti kako
funkcionira bez razumijevanja koncepata "otvaranja" i "zatvaranja"
datoteka. Također, postoje slučajevi u kojima je korištenje naredbe
`with` nezgrapno. U tim slučajevima možemo nastaviti koristiti metodu
`close`.

[^1]: Za vježbu razmislite kako bismo naredbom `try` mogli *garantirati*
    izvršavanje pozivanje metode `close` čak i u slučaju ranije pogreške

# Definicija vlastitih funkcija

Do sada smo već koristili mnoge funkcije koje dolaze ugrađene u Python
(npr. `print` ili `sum`) kao i one koje su dostupne kroz module
(`math.floor`).

Funkcije su jedan od osnovnih građevnih elemenata suvremenih programskih
jezika i primarna svrha im je implementacija "jedne radnje", koja se
zatim može koristiti na više mjesta u nekom programu. Navedeno smanjuje
kompleksnost programa i sprječava ponavljanje kôda što samo po sebi čini
programe preglednijim te olakšava testiranje i umanjuje mogućnosti
grešaka u kôdu. Definicija vlastitih funkcija je stoga ne samo uobičajen
nego i praktički nužan postupak prilikom implementacije većih programa.
Pogledajmo jednostavan primjer:

``` python
# "def" služi definiciji novih funkcija
def sum(numbers):
    total = 0
    for n in numbers:
        total += n
    # "return" označava kraj izvršavanja funkcije te vraća vrijednost koja se se smatra rezultatom
    return total
```

Primjer prikazuje definiciju funkcije koja prima jedan parametar koji
mora biti popis brojeva, zbraja sve brojeve te vraća njihov zbroj.
Drugim riječima, ova funkcija oponaša ugrađenu funkciju `sum`. Riječ
`def` označava definiciju funkcije te se nakon nje piše naziv funkcije
koji podliježe pravilima imenovanju varijabli. Nakon naziva funkcije se
u oblim zagradama nabrajaju parametri funkcije. Parametri funkcije su
jednostavno varijable putem kojih korisnik funkciji šalje vrijednosti
potrebne za izračun. Funkcija iz primjera prima jedan parametar koji je
nazvan `numbers`. Nazivi parametara su zapravo nazivi varijabli koje
možemo koristiti unutar tijela funkcije. Tijelo funkcije se podvlači pod
samu liniju koja označava početak definicije funkcije kao što je slučaj
i kod kondicionala i petlji.

## Apstrakcija

U mnogim jezicima funkcija je temelj apstrakcije, a u nekim jezicima i
glavna organizacijska paradigma. Ovakvi jezici se nazivaju *funkcijski
jezici* i u njima je funkcija glavni temelj apstrakcije, a izbjegavaju
se promjene u stanjima i promjenjivi podaci.

Funkcije se u mnogim jezicima vežu uz klase odnosno nove vrste objekata.
Time funkcije najčešće postaju metode tih objekata kao što je, na
primjer, metoda `upper` vezana uz vrstu `str`. Navedeni pristup
programiranju se naziva *objektno orijentirano programiranje*, a jezici
koji se na njemu zasnivaju *objektno orijentirano jezici* i uvod se može
pronaći u poglavlju TODO.

Pogledajmo prvo osnove definicije vlastitih funkcija i detalje oko
postavljanja parametara, pa ćemo zatim prikazati korištenje funkcija u
praktičnom primjeru.

Već smo rekli da funkcija prima nula ili više parametara, na temelju
njih izvršava određen kôd te vraća rezultat. Pogledajmo kako ovo izgleda
u praksi prilikom definicije jednostavne vlastite funkcije.

Prije no što krenemo s primjerima korištenja funkcija u praksi, nužno je
naučiti kako se ponašaju varijable u tijelu funkcije odnosno koncept
"imenskog prostora" te neke detalje oko postavljanja parametara.

Abstrakcija

## Imenski prostor

Kôd koji sačinjava tijelo funkcije se izvršava vlastitom *imenskom
prostoru* odnosno nazivi varijabli se ne miješaju s nazivima varijabli
izvan funkcije. Prije no što krenemo u detalje pogledajmo primjer koji
prikazuje što ovo znači u praksi:

## Identifikacija parametara redoslijedom i imenom

## Posebne vrste parametara

### Niz od n parametara

### Parametri s arbitrarnim imenima

Kako bismo mogli definirati funkciju koja zbraja više od jednog broja
odnosno koja oponaša već postojeću funkciju `sum`?

# Definicija vlastitih funkcija

Do sada smo već koristili mnoge funkcije koje dolaze ugrađene u Python
(npr. `print` ili `sum`) kao i one koje su dostupne kroz module
(`math.floor`).

Funkcije su jedan od osnovnih građevnih elemenata suvremenih programskih
jezika i primarna svrha im je implementacija "jedne radnje", koja može
biti vrlo jednostavna, ali i vrlo kompleksna. Definicija vlastitih
funkcija je stoga uobičajen postupak i služi smanjenju kompleksnosti
koda time što pruža definicije potrebnih radnji koje se zatim mogu
koristiti više puta. Pogledajmo prvo osnove definicije vlastitih
funkcija i detalje oko postavljanja parametara, pa ćemo zatim prikazati
korištenje funkcija u praktičnom primjeru.

Već smo rekli da funkcija prima nula ili više parametara, na temelju
njih izvršava određen kôd te vraća rezultat. Pogledajmo kako ovo izgleda
u praksi prilikom definicije jednostavne vlastite funkcije.

```python
# def služi definiciji novih funkcija
def sum_two(x, y):
    # return označava kraj izvršavanja funkcije kao vrijednost koja se se smatra rezultatom
    return x + y
```

Primjer prikazuje definiciju funkcije koja prima dva parametra, zbraja
ih te vraća njihov zbroj. Drugim riječima, ova funkcija odgovara
operatoru `+`. Riječ `def` označava definiciju funkcije te se nakon nje
piše naziv funkcije koji podliježe pravilima imenovanju varijabli. Nakon
naziva funkcije se u oblim zagradama nabrajaju parametri funkcije.
Parametri funkcije su jednostavno varijable putem kojih korisnik
funkciji šalje vrijednosti potrebne za izračun. Funkcija iz primjera
prima dva parametra, `x` i `y`, koje se unutar tijela funkcije mogu
normalno koristiti kao varijable. Tijelo funkcije se podvlači pod samu
liniju koja označava početak definicije kao i kod npr. kondicionala i
petlji. Prije no što krenemo s primjerima korištenja funkcija u praksi,
nužno je naučiti kako se ponašaju nazivi varijabli te neke detalje oko
postavljanja parametara.

## Imenski prostor

Kôd koji sačinjava tijelo funkcije se izvršava vlastitom *imenskom
prostoru* odnosno nazivi varijabli se ne miješaju s nazivima varijabli
izvan funkcije. Prije no što krenemo u detalje pogledajmo primjer koji
prikazuje što ovo znači u praksi:

## Identifikacija parametara redoslijedom i imenom

## Posebne vrste parametara

### Niz od n parametara

### Parametri s arbitrarnim imenima

Kako bismo mogli definirati funkciju koja zbraja više od jednog broja
odnosno koja oponaša već postojeću funkciju `sum`?

def sum(numbers): total = 0 for n in numbers: total += n return total

# Strukture podataka

*Strukture podataka* valja shvatiti kao *zbirke vrijednosti*, a ova dva
termina se često koriste i na engleskom (*data structure* i
*collection*). Upotrebe ovog koncepta su višestruke. Ponekad se neka
vrijednost po svojoj prirodi sastoji od više pod-vrijednosti. Spomenuli
smo već tekst koji je zapravo "niz znakova", a možemo tome dodati i
kojekakve složene vrijednosti poput datuma (tri cijela broja: dan,
mjesec i godina) ili osobnog imena (dva niza znakova: ime i
prezime[^1]).

Uz to, ponekad želimo provesti istu radnju na više objekata iste vrste.
Na primjer, recimo da želimo promijeniti kodnu stranicu svih tekstualnih
datoteka u nekom direktoriju: Prvo nam je potreban popis svih putanja do
datoteka koje planiramo procesirati (što je najčešće jednostavno popis
tekstualnih nizova), a zatim za svaku putanju usnimavamo datoteku i
zapisujemo tekst u drugu datoteku koja ima drugačiju kodnu stranicu.
Također, kad radimo s računalnim podacima, na primjer podacima o
knjigama ili o računima s blagajni, po prirodi stvari radimo sa
strukturama podataka. Kako bi uopće počeli raditi sa spomenutim
konceptima potrebno nam je prvo usvojiti neke osnove vezane uz strukture
podataka.

Postoje posebne *vrste vrijednosti* koje služe upravo strukturiranju
drugih vrijednosti odnosno koje nam omogućuju da okupljamo vrijednosti
bilo koje vrste u zbirke vrijednosti. Vrlo je korisno proučiti dvije
osnovne vrste struktura u Pythonu: popis (`list`) i rječnik (`dict`).
Učenjem ovih koncepata približavamo se i temeljima razmjene podataka u
mnogim web uslugama. Tome možemo dodati i skup (`set`) koji se nešto
manje koristi od popisa i rječnika, ali je u nekim slučajevima vrlo
korisna struktura.

## Popis

*Popis* je niz objekata u kojem se svaki objekt može identificirati
putem indeksa pozicije na kojoj se nalazi. Već smo vidjeli da je string
zapravo popis znakova, ali ovo je poseban slučaj popisa koji dozvoljava
samo tekstualne znakove kao članove. Najčešće korištena struktura pomoću
koje se implementira popis bilo kojih vrsta vrijednosti u Pythonu je
`list`. Ovako definiran popis se može mijenjati i vjerojatno je najčešće
korištena struktura podataka u Python programima. Pogledajmo kako možemo
stvoriti popis i dohvatiti neki element iz njega.

``` python

>>> boje = ["crvena", "zelena", "plava"] # popis definiramo uglatim zagradama 
>>> print(boje) ["crvena", "zelena", "plava"]# elemente dohvaćamo uglatim zagradama i indeksom pozicije # indeksi počinju od 0, odnosno prvi element popisa se nalazi na indeksu 0 
>>> prva_boja = boje[0] 
>>> print(prva_boja) crvena
```

Primjer je prikazao najjednostavniji način stvaranja popisa. Zarezom
odvojeni objekti unutar uglatih zagrada stvaraju popis. Vrijedi
napomenuti i da unutar popisa, kao i u ostalim zagradama u Pythonu,
možemo dodavati nove retke radi preglednosti. Na primjer:

``` python

>>> boje_a = ["crvena", "zelena", "plava"] # popis definiramo uglatim zagradama# popis boje_b identičan je popisu boje_a, samo je raspisan drugačije 
>>> boje_b = [ "crvena", "zelena", "plava" ]
>>> boje_a == boje_b True
```

Mogućnost pisanja struktura u više redaka je korisna za osiguranje
preglednosti kod većih struktura (na primjer, popisa s 10 i više
elemenata).

Također, većina struktura pruža način kako dohvatiti neki individualni
objekt koji se u njoj nalazi. U mnogim slučajevima to je i poanta
korištenja Uglate zagrade odmah nakon imena neke varijable u Pythonu (i
mnogim drugim jezicima) označavaju upravo to: dohvati objekt(e) iz
strukture podataka putem vrijednosti u uglatim zagradama. Kod popisa je
to indeks, odnosno cijeli broj koji označava poziciju elementa u popisu,
gdje je indeks prvog objekta 0, a zadnji je jednak broju objekata u
popisu -1. Drugim riječima, validni indeksi za popis od četiri objekta
su 0, 1, 2 u 3. Obzirom da su adrese u popisu jasno definiran raspon
brojeva, kao indekse možemo koristiti i negativne brojeve i raspone
brojeva:

``` python

>>> boje = ["crvena", "zelena", "plava", "žuta", "ljubičasta"]# dohvati drugu boju iz popisa, odnosno boju na indeksu 1 
>>> druga_boja = boje[1] 
>>> print(druga_boja) zelena# dohvati zadnju boju iz popisa 
>>> zadnja_boja = boje[-1] 
>>> print(zadnja_boja) ljubičasta# dohvati raspon vrijednosti iz popisa 
>>> neke_boje = boje[1:4] # dohvaća vrijednosti pod indeksima 1, 2 i 3 
>>> print(neke_boje) ["zelena", "plava", "žuta"] # kod raspona indeksa, vrijednost prvog indeksa je uvijek # uključena u rezultat, a zadnja nije# ukoliko ispustimo zadnji indeks u rasponu, to znači "odaberi do kraja" 
>>> sve_osim_prve = boje[1:] 
>>> sve_osim_prve ["zelena", "plava", "žuta", "ljubičasta"]# ukoliko ispustimo prvi indeks u rasponu, to znači "odaberi od početka" 
>>> sve_osim_zadnje = boje[:-1] 
>>> sve_osim_zadnje ["crvena", "zelena", "plava", "žuta"]
```

Jedan od problema sa strukturama podataka je što je riječ o apstraktnim
konceptima za koje je pri prvom susretu teško prikazati praktične
primjere. Ipak, kako bismo se barem približili praksi pogledajmo kako
dobiti popis članova nekog direktorija:

``` python

>>> import os 
>>> os.listdir(’c:/test’) [’dat_a.pdf’, ’dat_b.docx’, ’dat_c.txt’, ’dir_a’, ’dir_b’]
```

Primjer prikazuje kako dobiti popis članova nekog direktorija odnosno
popis stringova koji su imena datoteka i pod-direktorija u nekom
direktoriju. U prikazanom slučaju na disku `c` postoji direktorij `test`
koji sadrži tri datoteke (`dat_a.pdf`, `dat_b.docx` i `dat_c.txt`) i dva
poddirektorija (`dir_a` i `dir_b`). Jednostavno dobiti popis članova
nekog direktorija, kao što vidimo, nije teško. Ipak, dok je samo po sebi
jasno kako bi ovakav popis mogao biti koristan, ima još puno posla kako
bi s ovime mogli učiniti nešo konkretno: razlikovati datoteke od
direktorija, izraditi pune putanje od imena, razlikovati različite vrste
datoteka, pristupati sadržaju datoteke i slično. Drugim riječima,
problem prvog dodira sa strukturama podataka je što su one vrlo važne za
programiranje gotovo bilo čega, ali primjeri koji bi prikazali njihovu
praktičnu uporabu su često preopširni ili prekompleksni za prvi susret.
Ovaj dio skripte će se, stoga, usredotočiti na jednostavne apstraktne
primjere rada sa strukturama podataka, a njihova praktična uporaba će se
prikazati u kasnijim većim primjerima koji rade nešto konkretno ili
zabavno.

### Funkcija `list`

Kao i kod tzv. primitivnih vrsti vrijednosti u Pythonu (`int`, `float`,
`bool`, `str`), nazivi struktura vrijednosti su također i funkcije s
kojima možemo druge objekte pretvarati u tu strukturu. Funkcija `list`
prima jedan parametar i raščlanjuje poslanu vrijednost na sastavne
elemente te vraća rezultat kao popis.

Pogledajmo primjere:

U zadnjoj liniji prijašnjeg primjera vidimo grešku koja se javlja kada
pokušamo pretvoriti u popis nešto što se ne da raščlaniti na sastavne
djelove. U ovom slučaju radi se o cijelom broju. Kao što vidimo, poruka
kaže "objekt vrste int nije iterativan". Sjetimo se, kada je vrijednost
"iterativna", to znači da se po njoj ne može prebirati što je upravo
zahtjev da bi se nešto moglo pretvoriti u popis. Vrijednost moramo moći
"izlistati".

### Promjene popisa

Najjednostavnija promjena popisa je promjena vrijednosti koja se nalazi
na nekom indeksu. Pogledajmo primjer:

``` python

>>> boje = ["crvena", "zelena", "plava"] 
>>> boje[1] = "ljubičasta" # postavi drugi element popisa na vrijednost "ljubičasta" 
>>> print(boje) ["crvena", "ljubičasta", "plava"]
```

Ostale promjene popisa se provode putem metoda koje pruža vrsta
vrijednosti *list*. Ovih metoda nema puno i većina ih provodi relativno
jednostavne i očekivanje radnje. Pogledajmo koje su to:

- *append* - dodaj novi član na kraj popisa

- *clear* - obriši sve članove popisa, odnosno isprazni popis

- *copy* - napravi neovisnu kopiju popisa u memoriji

- *extend* - proširi popis svim članovima drugog popisa

- *insert* - ubaci novi član u popis na određeni indeks

- *pop* - izbaci zadnji član iz popisa ili izbaci član na nekom indeksu

- *remove* - izbaci prvi član koji je pronađen u popisu

- *reverse* - obrni redoslijed članova popisa

- *sort* - sortiraj popis

Pogledajmo primjere:

``` python

>>> boje = ["crvena", "zelena", "plava"]# dodaj vrijednost na kraj popisa 
>>> boje.append("žuta") 
>>> print(boje) ["crvena", "zelena", "plava", "žuta"]# proširi popis svim vrijednostima iz drugog popisa 
>>> druge_boje = ["crna", "bijela"] 
>>> boje.extend(druge_boje) 
>>> print(boje) ["crvena", "zelena", "plava", "žuta", "crna", "bijela"]# ubaci vrijednost na određeni indeks 
>>> boje.insert(2, "zelena") 
>>> print(boje) ["crvena", "zelena", "zelena", "plava", "žuta", "crna", "bijela"]# dohvati i izbaci zadnju vrijednost u popisu 
>>> zadnja_boja = boje.pop() 
>>> print(zadnja_boja) bijela 
>>> print(boje) ["crvena", "zelena", "zelena", "plava", "žuta", "crna"]# dohvati i izbaci vrijednost u popisu na nekom indeksu 
>>> boje = ["crvena", "zelena", "zelena", "plava", "žuta", "crna"] 
>>> peta_boja = boje.pop(4) 
>>> print(peta_boja) žuta 
>>> print(boje) ["crvena", "zelena", "zelena", "plava", "crna"]# izbaci PRVU pronađenu vrijednost 
>>> boje.remove("zelena") 
>>> print(boje) ["crvena", "zelena", "plava", "crna"]# sortiraj popis 
>>> boje.sort() 
>>> print(boje) ["crna", "crvena", "plava", "zelena"]
```

### Informacije o članstvu popisa

Uz navedene metode za promjene popisa, postoje i neke koje služe
informiranju o članovima popisa:

- *index* - dohvati prvi indeks na kojem se nalazi neki objekt ili javi
  grešku ukoliko taj objekt nije u popisu

- *count* - prebroji koliko se puta neki vrijednost pojavljuje u popisu

### Prebiranje i funkcija *range*

Petlja "za svaki", naravno, normalno radi s popisima.

``` python

>>> boje = ["crvena", "zelena", "plava"] 
>>> for boja in boje: print(boja)
```

Rezltat:

``` python
crvena zelena plava
```

Uz navedeno, često je korisno prebirati po **indeksima**, a ne po
vrijednostima popisa. U tu svrhu, vrlo nam je korisna funkcija `range`.
Ta funkcija služi stvaranju niza brojeva od nekog početnog do nekog
završnog. Pogledajmo primjere:

``` python

>>> r = range(2, 10) 
>>> print(r) range(2, 10) # range nije popis! 
>>> print(list(r)) # ali bilo koji range možemo pretvoriti u popis [2, 3, 4, 5, 6, 7, 8, 9]
>>> r = range(0, 5) 
>>> print(list(r)) [0, 1, 2, 3, 4]
>>> r = range(5) # ako pošaljemo samo jedan broj, smatra se da je početni broj 0 
>>> print(list(r)) [0, 1, 2, 3, 4]
>>> boje = ["crvena", "zelena", "zelena", "plava", "crna"] 
>>> broj_boja = len(boje) 
>>> for i in range(broj_boja): print("Na indeksu", i, "nalazi se", boje[i])Na indeksu 0 nalazi se crvena Na indeksu 1 nalazi se zelena Na indeksu 2 nalazi se zelena Na indeksu 3 nalazi se plava Na indeksu 4 nalazi se crna
```

Kao što vidimo, funkcija `range` posebno je korisna za generiranje
validnih indeksa za popis. Kao i kod indeksa popisa, ova funkcija
uključuje prvu vrijednost, a zadnju ne. Na primjer, `range(0, 4)`
generira brojeve 0, 1, 2 i 3. Ukoliko traženi brojevi počinju od 0,
funkcija range se može pozvati sa samo jednim parametrom koji označava
do kojeg broja se generira. Ovo nam omogućuje da ukoliko želimo
generirati sve validne indekse za neki popis to možemo učiniti
jednostavnim izrazom `range(len(neki_popis))`.

Osim definiranja minimuma i maksimuma, `range` prima i opcionalni treći
parametar: korak (eng. *step*). Ovaj parametar je zadan na 1 i definira
pomak između dva broja koja se generiraju funkcijom `range`. Navedeno je
možda teže shvatiti kroz definiciju nego kroz primjer pa pogledajmo
jedan:

<div class="minipage">

``` python

>>> r = range(1, 10) 
>>> print(r) range(1, 10) 
>>> print(list(r)) [1, 2, 3, 4, 5, 6, 7, 8, 9]# range sa zadanim minimumom, maksimumom i korakom 
>>> r = range(1, 10, 2) 
>>> print(r) range(1, 10, 2) 
>>> print(list(r)) [1, 3, 5, 7, 9]
```

</div>

### *list* i *tuple*

Do sada smo radili samo s popisom vrste `list`, ali to nije jedina vrsta
popisa. Glavna distinkcija između popisa u Pythonu ovisi o tome da li je
popis promjenjiv ili nepromjenjiv. `list` je, kao što smo vidjeli iz
primjera, promjenjiv popis. Postoji i nepromjenjivi popis koji se naziva
`tuple`. Dohvaćanje elemenata iz obje vrste popisa je identično, ali
`tuple` se ne definira kroz uglate već kroz oble zagrade, a u mnogim
slučajevima se može pisati i bez zagrada.

Kao što vidimo, razlika između prikazane dvije vrste popisa je u tome
što je `list` moguće mijenjati, a `tuple` ne. Sve što možemo raditi s
popisom vrste `tuple`, dakle, vrijedi i za popise vrste `list`, ali
`list` pruža mogućnost promjena u popisu, a `tuple` ne. Pokušaj
dodavanja nove vrijednosti u `list` je, na primjer, normalan postupak, a
pokušaj dodavanja nove vrijednosti u `tuple` javlja grešku jer je tuple
nepromjenjiv. S druge strane, dohvaćanje vrijednosti putem indeksa
funkcionira identično i za `list` i za `tuple`.

Dok je “popis” relativno jednostavan koncept, kada bismo se dublje
skoncentrirali na popis kao strukturu podataka u odnosu na računalo,
vidjeli bismo da postoje različite implementacije istog koncepta koje se
razlikuju u efikasnosti i mogućnostima. Neke implementacije, na primjer,
su visoko efikasne, ali ne dopuštaju nikakve promjene. Kod
implementacija koje omogućuju promjene, različite radnje mogu biti
različito efikasne (u računalnom žargonu “različito koštaju”) ovisno o
načinu implementacije popisa. Pythonov `list`, na primjer, je visoko
efikasan u dodavanju nove vrijednosti na kraj popisa kao i u izbacivanju
te vrijednosti, ali neefikasan u dodavanju vrijednosti na početak popisa
ili izbacivanja vrijednosti s početka popisa. Da situacija bude još
gora, dodavanje odnosno izbacivanje vrijednosti je tim manje efikasno
čim ima više objekata u popisu nakon objekta koji se dodaje ili
izbacuje.

Ukoliko želimo efikasno dodavati i izbacivati vrijednosti iz sredine
popisa, Python ima uključenu i treću implementaciju popisa koja je
dostupna iz modula `collections` i zove se `deque`. Zašto onda ne bismo
uvijek koristili `deque`? Zato jer za dodatne mogućnosti uvijek postoji
cijena pa je tako popis vrste `deque` manje memorijski efikasan od
popisa vrste `list`. U svakom slučaju, modul `collections`, kao što ime
kaže, donosi dodatne strukture podataka koje su specijaliziranije u
naravi od osnovnih struktura koje se prikazuju u ovom poglavlju i
uglavnom su njihove varijante.

## Broj objekata u strukturi i provjera članstva

Osim spomenutih posebnih metoda koje dozvoljava struktura `list`,
postoje i dva općenita pitanja koja često želimo postaviti bilo kojoj
strukturi podataka. Ta pitanja su:

- Koliko ima vrijednosti u nekoj strukturi?

- Da li neka struktura sadrži neki određeni objekt?

### Broj objekata u strukturi

Broj objekata u nekoj strukturi podataka često se naziva i “duljinom” te
strukture. Python funkcija `len` vraća upravo taj broj.

``` python

>>> boje = ["crvena", "zelena", "plava"] 
>>> n_boja = len(boje) 
>>> print(n_boja) 3
```

`len` je funkcija koja radi na svim vrstama objekata za koje je pitanje
"Koliko ima elemenata (tj. podobjekata) u ovom objektu?" validno. Ako
pitanje nije validno, odnosno objekt koji je poslan kao parametar ga ne
podržava, `len` javlja grešku.

Kao što je za očekivati, poziv funkcije `len` s cijelim brojem kao
parametrom javlja grešku koju možemo čitati kao "cijeli brojevi nemaju
broj elemenata". `len` teksta, međutim, vraća vrijednost jer je kod
teksta to "broj znakova".

### Provjera članstva neke strukture

Također, postoji univerzalan način provjere da li se neka vrijednost
nalazi u određenoj zbirci vrijednosti i to putem operatora `in`.
Pogledajmo primjere:

``` python

>>> if "š" in "Krešimir": print(’"Krešimir" sadrži "š".’)"Krešimir" sadrži "š".
>>> boje = ["crvena", "zelena", "zelena", "plava", "crna"] 
>>> "zelena" in boje True
>>> "žuta" in boje False
```

## Rječnik

Rječnik je skup “ključ: vrijednost“ parova. Za razliku od popisa,
rječnik nema značajan redoslijed objekata, već svaki objekt koji se
pohranjuje kao vrijednost ima vlastiti ključ odnosno “šifru” ili “ime”
po kojem ga se može dohvatiti. Rječnik se definira vitičastim zagradama
i s dvotočkom kao znakom koji razgraničuje ključeve od vrijednosti.
Pogledajmo primjer:

``` python

>>> data = "boja": "plava", "visina": 30 # rječnik s dva elementa # svaki element se sastoji od ključa # i vrijednosti koja mu je pridružena 
>>> print(data["boja"]) plava 
>>> print(data["visina"]) 30
```

Rječnik je vrlo intuitivna struktura za opis nekog predmeta odnosno za
strukturiranje metapodataka. Na primjer, metapodaci ugrađeni u neku
glazbenu datoteku mogli bi se prikazati kao:

``` python
Rječnici i metapodacilisting:dict_metapodaci track_data =  "artist": "Monty Python", "title": "Lumberjack Song", "album": "Monty Python Sings", "year": 1989
```

Osim toga, rječnik je, kao što ime kaže, koristan i za “prevođenje”
vrijednosti. Pogledajmo doslovan primjer. Recimo da dobivamo podatke
poput varijable “track_data” u primjeru niže iz neke vanjske usluge i
želimo prevesti ključeve (odnosno nazive polja) na neke naše nazive.

``` python
```

Prikazan kod ispisuje:

``` python
"album": "Monty Python Sings", 
"godina": 1989, 
"naslov": "Lumberjack Song", 
"umjetnik": "Monty Python"
```

Također, primijetimo da prebiranje po rječniku s petljom `for` prebire
po ključevima. Što ako želimo prebirati po vrijednostima ili po
ključevima i vrijednostima odjednom?

``` python
Prebiranje po vrijednostima rječnikalisting:dict_values for value in track_data.values(): # prebire po vrijednostima print(value)
```

Rezultat:

``` python
1989 Lumberjack Song Monty Python Sings Monty Python
```

Redoslijed vrijednosti po kojima se prebire za razliku od liste nije
konzistentan. U drugom prebiranju, redoslijed ispisanih vrijednosti može
biti drugačiji. Drugim riječima, adresa vrijednosti nije određena
pozicijom već imenom. Radi toga je često korisno i prebirati po
ključevima i vrijednostima odjednom. Pogledajmo kako:

``` python
for key, value in track_data.items(): # prebire po (ključ, vrijednost) parovima print(key, value)
```

Rezultat:

``` python
year 1989 title Lumberjack Song album Monty Python Sings artist Monty Python
```

### Funkcija *dict*

Funkcija `dict` služi stvaranju rječnika. Kao i sve ostale funkcije koje
označavaju vrstu vrijednosti, poziv bez parametara stvara prazan
rječnik.

``` python

>>> d = dict() # isto što i d = 
>>> print(d)
```

Poziv na `dict` s imenovanim parametrima stvara novi rječnik s tim
parametrima kao ključevima.

``` python
Funkcija dict i imenovani parametrilisting:dict_imenovani_parametri d = dict(a=1, b=2) print(d)
```

*dict* može primiti i popis parova, odnosno popis popisa gdje svaki
pod-popis ima dva člana: ključ i vrijednost.

``` python
Funkcija dict i popis parovalisting:dict_parovi popis_parova = [ ["a", 1], ["b", 2], ["c", 1] ] d = dict(popis_parova) print(d) popis_parova = list(d.items()) # popis parova možemo i dohvatiti iz rječnika print(popis_parova)
```

## Skup

Skup je implementacija matematičkog koncepta skupa: zbirka jedinstvenih
vrijednosti bez značajnog redoslijeda. U smislu onoga što već znamo o
Pythonu, skup možemo shvatiti kao samo ključeve rječnika bez pridruženih
vrijednosti.

``` python

>>> s = set() 
>>> s.add(1) 
>>> print(s) 1 
>>> s.add(2) 
>>> print(s) 1, 2 
>>> s.add(2) # skup već sadrži vrijednost 2 pa nema promjene 
>>> print(s) 1, 2
```

Skup je rjeđe korištena struktura od popisa i rječnika, ali je vrlo
korisna u nekim slučajevima.

### Funkcija *set* i stvaranje novih skupova podataka

Kao i u matematici, skup se označava vitičastim zagradama. Razlika od
rječnika je što se skup ne sastoji od "ključ: vrijednost" parova, već od
individualnih elemenata. Nažalost, obzirom da se vitičaste zagrade
koriste i za rječnik i za skup, prazan skup **moramo** definirati pomoću
funkcije *set*. Kada želimo definirati skup postojećih vrijednosti,
možemo koristiti i vitičaste zagrade. Pogledajmo neke primjere
definicije skupova:

``` python

>>> s = # pažnja! prazan rječnik 
>>> print(s)
>>> s = set() # prazan skup 
>>> print(s) set()
>>> s = "a", "b", "c" # skup s članovima 
>>> print(s) "a", "c", "b"
>>> s = set("ana") # napravi skup od elemenata vrijednosti (npr, tekst) 
>>> s "a", "n"
>>> s = set(["ana"]) # napravi skup od elemenata popisa 
>>> s "ana"
>>> d = "a": 1, "b": 2, "c": 1 # definiraj neki rječnik 
>>> set(d) # ključevi rječnika kao skup "a", "c", "b" 
>>> set(d.values()) # sve različite vrijednosti u rječniku 1, 2
```

### Operacije sa skupovima

Za razliku od popisa i rječnika, skup ne pruža način dohvata neke
odabrane vrijednosti iz zbirke. Drugim riječima, vrijednosti u skupu ne
možemo jednoznačno adresirati jer vrijednosti nemaju niti konzistentan
redoslijed (pa ne možemo koristiti poziciju neke vrijednosti kao indeks)
niti se vrijednosti mogu identificirati putem kakvog ključa. Zašto bismo
onda prikupljali vrijednosti u skupove? Skupovi omogućuju matematičke
operacije sa skupovima poput unije, presjeka i razlike, odnosno
operacije koje su vrlo korisne u radu s podacima. Pogledajmo primjere:

``` python

>>> a.intersection(b) # ili a & b "c", "b" 
>>> a & b # isto što i a.intersection(b) "c", "b" 
>>> a.union(b) # ili a | b "a", "d", "c", "b" 
>>> a.difference(b) # ili a - b "a" 
>>> b.difference(a) # ili b - a "d"
```

Također, svojstvo skupa da sadrži samo različite vrijednosti je često
korisno. Sljedeći primjer prikazuje kako ga možemo jednostavno
iskoristiti da prebrojimo sve jedinstvene vrijednosti u nekoj zbirci
vrijednosti.

``` python

>>> boje = ["crvena", "plava", "crvena", "zelena", "plava"] 
>>> skup_boja = set(boje) 
>>> print("N boja:", len(boje)) N boja: 4 
>>> print("N različitih boja:", len(skup_boja)) N različitih boja: 3
```

Prikazane strukture podataka izvrsan su prvi susret s temom i već samo
prikazani koncepti nas opunumoćuju ne samo u programiranju već i u
općenitom radu s podacima kao i u razumijevanju vezane tematike. U
idućem poglavlju je upravo riječ o osnovama korištenja ovih struktura za
obradu podataka.

[^1]: Osobna imena mogu imati još djelova i upravljanje podacima o
    osobnim imenima je vrlo kompleksno, ali najjednostavniji slučaj nam
    je ovdje dovoljno dobar primjer.

# Uvod u programiranje s podacima

Strukture podataka su sastavan dio programiranja bez kojih nije moguće
zamisliti mnoge algoritme. Između ostalog, strukture podataka omogućuju
rad s podacima za potrebe analitike ili upravljanja. Dapače, jedna od
popularnijih namjena Pythona je upravo rad s podacima poput onih iz baza
podataka ili dohvaćenih kroz sučelja za razmjenu podataka.

U nastavku teksta slijede prvi koraci u razumijevanju obrade podataka u
odnosu na ranije opisane strukture, odnosno prvi koraci za korištenje
popisa (`list`, `tuple`) i rječnika (`dict`) za potrebe obrade podataka.
Spomenute strukture, uz bogate mogućnosti rada s tekstom te ostale
značajke Pythona, nam pružaju vrlo kvalitetnu platformu za rad s
podacima bilo koje vrste. Za razliku od specijaliziranih rješenja, lako
se prilagoditi kojekakvim specifičnostima podatkovnih zapisa s kojima
radimo te osmišljati rješenja za neočekivane probleme. Također, u nekim
slučajevima je vrlo korisno odraditi pripremu podataka u Pythonu (na
primjer dohvat i potrebne transformacije), a zatim podatke prebaciti u
specijaliziraniji statistički softver u kojem je lakše provesti
kompleksnije analitičke postupke.

Prilikom analitičkog rada s podacima, često se koriste dodatni Python
moduli koji donose nove strukture i mogućnosti (popularni su npr. Numpy
i Pandas). Ipak, za razumijevanje rada sa strukturiranim podacima, vrlo
je korisno osnovne koncepte usvojiti kroz jednostavne vrste vrijednosti
i strukture podataka pa tek zatim krenuti koristiti strukture fokusirane
na efikasnost ili gotova specijalizirana rješenja.

Prije no što krenemo u samo programiranje, pogledajmo neke strukturirane
podatke. Najčešća struktura s kojom se srećemo i koja nije striktno
vezana za računala je tablica. Pogledajmo pojednostavljen primjer
bibliografskih metapodataka u tabličnom obliku.

<div id="table:primjer">

| **Naslov** | **Autor** | **Godina** | **Izdavač** | **ISBN** |
|:---|:---|:---|:---|:---|
| Good Omens | Terry Pratchett & Neil Gaiman | 1990 | Gollancz | 0-575-04800-X |
| Interesting times | Terry Pratchett | 1994 | Gollancz | 0-575-05800-5 |
| Neverwhere | Neil Gaiman | 1996 | BBC Books | 0-7472-6668-9 |

Primjer jednostavne tablice

</div>

Započnimo jednostavnim pitanjem: "Kako postaviti tablične podatke u
oblik iskoristiv za programiranje?".

Rješenju možemo, naravno, pristupiti na više načina, a razumijevanje
mogućih rješenja i transformacija među njima je najvažniji početni korak
u radu sa strukturiranim podacima u Pythonu. Ovakav pristup nam pomaže
usvojiti strukture podataka za reprezentaciju samih podataka, a zatim i
kako se koristiti tim istim strukturama za potrebu transformiracije,
odabira i grupiranja podataka.

## Tablica kao popis popisa

Prikazana tablica se sastoji od tri podatkovne jedinice (ovdje vrste
"knjiga") svaka od kojih je opisana s pet svojstava (naslov, autor,
godina, izdavač, ISBN) svako od kojih prima vrijednost. Sve vrijednosti
su u ovom početnom slučaju jednostavne, odnosno nemaju internu
strukturu[^1]. U prijašnjim rečenicama se namjerno ne koriste izrazi
"redak" i "stupac". Navedeno predstavlja općenito viđenje podataka koje
želimo postići ovom skriptom te povezati s programskim konceptima. Ipak,
krenimo prvo s poznatim konceptima svojstvenima tablici, a razlog
općenitijoj terminologiji gore će postati vidljiv kroz primjere odnosno
strukture podataka koje ćemo koristiti za kodifikaciju informacija na
različitim razinama.

Razmislimo o izjavi "U prikazanoj tablici svaki redak je knjiga, a
autori se nalaze u drugom stupcu". Jedan način na koji možemo definirati
tablicu je popis redaka[^2]. Redak možemo definirati kao popis
vrijednosti u dogovorenom redoslijedu koji je zadan naslovima
stupaca[^3]. Kako bi znali koja vrijednost se nalazi u kojem stupcu
potrebno nam je "zaglavlje" tablice odnosno popis naziva stupaca. Kad
nam je definirano zaglavlje, na isti način možemo definirati i neki
redak u tablici.

Pogledajmo primjer:

``` python
zaglavlje = ['Naslov', 'Autor', 'Godina', 'Izdavač', 'ISBN']
redak = ['Interesting times',  'Terry Pratchett',  1994, 'Gollancz', '0-575-05800-5']
``` 

Tablica nam je onda jednostavno popis redaka:

``` python
zaglavlje = ['Naslov', 'Autor', 'Godina', 'Izdavač', 'ISBN']
tablica = [
    ['Good Omens',  'Terry Pratchett & Neil Gaiman',  1990, 'Gollancz', '0-575-04800-X'],
    ['Interesting times',  'Terry Pratchett',  1994, 'Gollancz', '0-575-05800-5'],
    ['Neverwhere',  'Neil Gaiman',  1996, 'BBC Books', '0-7472-6668-9']
]
``` 

Na ovaj način možemo početi raditi s ovim podacima. Ova struktura nam
već, na primjer, dopušta odgovor na jednostavna pitanja poput "Koliko
ima knjiga u našim podacima?" s izrazom `len(tablica)`. Ovo je dobar
trenutak i da se zapitamo zašto zaglavlje držimo izdvojeno. Mogli smo ga
uključiti kao što je uobičajeno u raznom softveru kao "prvi redak u
tablici":

``` python
tablica = [
    ['Naslov', 'Autor', 'Godina', 'Izdavač', 'ISBN']
    ['Good Omens',  'Terry Pratchett & Neil Gaiman',  1990, 'Gollancz', '0-575-04800-X'],
    ['Interesting times',  'Terry Pratchett',  1994, 'Gollancz', '0-575-05800-5'],
    ['Neverwhere',  'Neil Gaiman',  1996, 'BBC Books', '0-7472-6668-9']
]
``` 
Ipak, ovakav pristup je problematičan. Uključili smo zaglavlje, odnosno
dio sheme podataka, u same podatke! Zaglavlje ne predstavlja "jednu
knjigu". Kada razmislimo o tome što sada znači rezultat izraza
`len(tablica)` greška postaje očita. Drugim riječima, valja jasno
odvajati "shemu podataka" ili "metapodatke" od samih "podataka o nečemu"
jer ćemo tako imati znantno manje problema u kasnijoj obradi i pohrani
ovakvih podataka.

Kako funkcionira adresiranje u ovakvoj strukturi? Jednostavno, indeks u
glavnom popisu ("tablici") je broj retka, a indeks u svakom pod-popisu
("retku") je broj stupca. Pročitajmo, na primjer, drugi redak i
vrijednost svojstva "Godina" tog retka.

``` python
drugi_redak = tablica[1]  # prvi redak je na indeksu 0!
godina = drugi_redak[2]   # treći stupac

# ili jednostavno
godina = tablica[1][2]
# odnosno dohvati element na indeksu 1 i zatim dohvati element na 
# indeksu 2 u dohvaćenom elementu
``` 

Ako se prisjetimo nekih dodatnih radnji s popisima, sjetit ćemo se i da
je moguće dohvatiti indeks neke poznate vrijednosti u popisu. Pogledajmo
kako iskoristiti ovaj trik u kontekstu prikazanih struktura.

``` python
# dohvati indeks za godinu putem indeksa naziva u zaglavlju
i_godina = header.index('Godina')
# dohvati element na indeksu 1 i zatim dohvati element na istom indeksu na kojem 
# se nalazi 'Godina' u zaglavlju
godina = tablica[1][i_godina]
``` 

## Tablica kao rječnik popisa

Do sada smo, kao i u npr. Excelu, vrijednosti identificirali putem
indeksa retka i indeksa stupca. Veliki problem s identifikacijom putem
indeksa je to što su promjenjivi. Ako se, na primjer, referiramo na
jedinicu u retku pod indeksom 5, ta jedinica će se promijeniti nakon
sortiranja tablice! Drugim riječima, indeksi ne identificiraju
jednoznačno neku jedinicu ili svojstvo, već trenutačnu poziciju te
jedinice odnosno svojstva u odabranoj strukturi podataka. U tipičnim
tablicama se redoslijed stupaca relativno rijetko mijenja pa su indeksi
svojstava često stabilni, ali reci se često dodaju i sortiraju pa
indeksi redaka nisu dobar identifikator individualnih zapisa.

Što ako želimo tablicu strukturirati tako da retke, odnosno individulne
zapise, možemo dohvaćati preko neke stabilne šifre? Iskoristimo za
primjer polje ISBN i postavimo tablicu tako da je struktura koja čuva
retke rječnik te u kojem su ključevi ISBN vrijednosti, a reci, isto što
i prije, odnosno popis vrijednosti kod kojeg je redoslijed zadan
zaglavljem.

``` python
zaglavlje = ['Naslov', 'Autor', 'Godina', 'Izdavač', 'ISBN']
tablica = {
    '0-575-04800-X': ['Good Omens',  'Terry Pratchett & Neil Gaiman',  1990, 'Gollancz', '0-575-04800-X'],
    '0-575-05800-5': ['Interesting times',  'Terry Pratchett',  1994, 'Gollancz', '0-575-05800-5'],
    '0-7472-6668-9': ['Neverwhere',  'Neil Gaiman',  1996, 'BBC Books', '0-7472-6668-9']
}
``` 

Individualna podatkovna jedinica nam je ostala identična kao i u prvoj
strukturi tabličnih podataka (popis vrijednosti), ali struktura koja
sabire podatkovne jedinice se promijenila kako bi omogućila direktno
adresiranje putem nekog jedinstvenog identifikatora.

Kako adresirati podatke u ovakvoj strukturi podataka možemo vidjeti u
primjeru
<a href="#listing:rjecnik_popisa_dohvat" data-reference-type="ref"
data-reference="listing:rjecnik_popisa_dohvat">[listing:rjecnik_popisa_dohvat]</a>.

``` python
# dohvati redak pomoću ISBN-a
redak_za_isbn = tablica['0-575-05800-5']  
# dohvati treći "stupac"
godina = redak_za_isbn[2] 

# ili jednostavno
godina = tablica['0-575-05800-5'][2] 
``` 

Što ako imamo podatke kao popis popisa, a želimo rječnik popisa? Upravo
ćemo podatke zapakirane kao popis popisa često dobivati prilikom
komunikacije s relacijskim bazama ili usnimavanja podataka izvezenih iz
relacijskih baza ili softvera koji funkcionira na razini tablica poput
Excela i SPSS-a. Proceduru za pretvaranje iz jedne strukturu u drugu
možemo vidjeti u primjeru
<a href="#listing:pp_u_rp1" data-reference-type="ref"
data-reference="listing:pp_u_rp1">[listing:pp_u_rp1]</a>.

``` python
zaglavlje = ['Naslov', 'Autor', 'Godina', 'Izdavač', 'ISBN']
tablica = [
    ['Good Omens',  'Terry Pratchett & Neil Gaiman',  1990, 'Gollancz', '0-575-04800-X'],
    ['Interesting times',  'Terry Pratchett',  1994, 'Gollancz', '0-575-05800-5'],
    ['Neverwhere',  'Neil Gaiman',  1996, 'BBC Books', '0-7472-6668-9']
]

# napravi prazan rječnik u koji će se dodavati podaci
tablica_rjecnik = {}

for redak in tablica:
    # dohvati vrijednost koju koristimo kao ključ
    isbn = redak[4]
    # postavi redak u tablica_rjecnik kao vrijednost
    tablica_rjecnik[isbn] = redak

godina = tablica_rjecnik['0-575-05800-5'][2] 
```

Što ako ne postoji vrijednost koja se može koristiti kao šifra u
tablici? Najjednostavnija strategija izrade jedinstvene šifre je
dodjelom tekućeg broja. Ova strategija je prikazana u primjeru
<a href="#listing:pp_u_rp2" data-reference-type="ref"
data-reference="listing:pp_u_rp2">[listing:pp_u_rp2]</a> :

``` python
# tablica je ista kao i u prošlom primjeru

# napravi prazan rječnik u koji će se dodavati podaci
tablica_rjecnik = {}
# postavi šifru na neku početnu vrijednost
sifra = 0

for redak in tablica:
    # povećaj šifru za jedan (čime svaki redak garantirano dobiva jedinstven broj za šifru)
    sifra += 1
    # postavi redak u tablica_rjecnik kao vrijednost
    tablica_rjecnik[sifra] = redak
    
# pažnja: broj 1 u sljedećem izrazu izrazu nije indeks već šifra!
godina = tablica_rjecnik[1][2] 
``` 

Ovako dodijeljene šifre inicijalno su jednake indeksima redaka u ulaznoj
tablici, ali nisu osjetljive na promjene u sortiranju. Drugim riječima,
imaju prednost da ako zapamtimo neki skup šifri poput {3, 7} kao, na
primjer, rezultat pretrage, taj popis šifri je garantirano trajno
validan jer identifikacija redaka ne ovisi o trenutačnom poretku
tablice. Dapače, ako nam je tablica rječnik, redoslijed redaka
jednostavno više ne postoji! [^4].

Također, vrijedi i dobro razmisliti koju vrijednost koristiti kao šifru.
ISBN, na primjer, nam često ne zadovoljava potrebe za šifru jer jedno
djelo može imati više ISBN identifikatora ovisno o digitalnoj ili
papirnatoj inačici, tvrdom i mekom uvezu te ISBN 10 i 13 varijantama.
Drugim riječima, može postojati takav ISBN broj koji mi ne koristimo kao
ključ, a koji identificira knjigu "Neverwhere" u nekom njezinom obliku.
Možda i želimo da jedan naš "redak" sadrži sve ISBN-ove koje se prema
našim kriterijima odnose na isti entitet odnosno, u ovom slučaju, djelo.
Ako je tako, tada bi također dodijelili svoje šifre kao u prijašnjem
primjeru.

## Tablica kao rječnik rječnika

U prošloj seriji primjera, riješili smo se redoslijeda redaka za potrebe
identifikacije i dodijelili svoje šifre. Fokusirajmo se sada na redak.
On nam je dosada bio popis vrijednosti, odnosno popis "stupaca". Svaki
od ovih stupaca međutim, već ima svoje ime. Možemo li se unutar retka
referencirati na vrijednosti putem naziva vrijednosti, a ne putem
indeksa "stupca"? Dapače, vrijeme je da se odmaknemo od koncepta
"stupca" i krenemo pričati o atributima, odnosno svojstvima.

Postavimo redak kao rječnik u kojem su ključevi nazivi svojstava (i.e.
"stupaca u tablici"), a vrijednosti u rječniku su upravo vrijednosti tih
svojstava.

``` python
redak = {
   'Naslov': 'Interesting times', 
   'Autor': 'Terry Pratchett',
   'Godina': 1994,
   'Izdavač': 'Gollancz',
   'ISBN': '0-575-05800-5'
}

godina = redak['Godina']
``` 

"Tablica" ovakvih predmeta može biti bilo popis ovakvih rječnika ili
rječnik ovakvih rječnika. Upravo nam je rječnik rječnika posebno korisna
struktura. Recimo da smo sve retke postavili kao u primjeru gore i zatim
ih postavili kao vrijednosti u rječnik gdje su ključevi ISBN
identifikatori, tada bi godinu neke knjige mogli adresirati kao u
sljedećem primjeru:

``` python
tablica_rjecnik = {
    '0-575-05800-5': {
       'Naslov': 'Interesting times', 
       'Autor': 'Terry Pratchett',
       'Godina': 1994,
       'Izdavač': 'Gollancz',
       'ISBN': '0-575-05800-5'
    },
    # ... ostali reci ispušteni iz primjera
}

godina = tablica_rjecnik['0-575-05800-5']['Godina'] 
``` 

Kao što vidimo, u ovoj strukturi se na sve referiramo preko šifri
odnosno naziva radije nego preko redoslijeda što je često prirodnije i
manje podložno greškama. Ovaj oblik je također puno bliži načinu na koji
se danas razmijenjuju podaci na webu, odnosno formatu JSON koji je
nastao upravo kako bi ovakve strukture mogli razmijenjivati među
sustavima.

Naravno, čest je slučaj da podatke primamo u tabličnoj strukturi (na
primjer, prilikom usnimavanja iz razgraničenog teksta ili pri dohvatu iz
relacijskih baza podataka) pa ako želimo raditi s podacima u ovom
obliku, moramo ih prvo restrukturirati. Pogledajmo prvo kako pretvoriti
individualan popis vrijednosti u rječnik vrijednosti.

``` python
# ulazni podaci
zaglavlje = ['Naslov', 'Autor', 'Godina', 'Izdavač', 'ISBN']
redak = ['Good Omens',  'Terry Pratchett & Neil Gaiman',  1990, 'Gollancz', '0-575-04800-X']

# izradi prazan rječnik koji ćemo popuniti ulaznim podacima
redak_rjecnik = {}

# zaglavlje i redak po definiciji imaju jednak broj vrijednosti
# vrijednost na indeksu "i" u retku odgovara svojstvu na indeksu "i" u zaglavlju
for i in range(len(header)):
    naziv = zaglavlje[i]  # dohvati naziv
    vrijednost = redak[i]  # dohvati vrijednost
    redak_rjecnik[naziv]  = vrijednost  # postavi vrijednost pod specifičan naziv u rječnik
``` 

Kao što vidimo, ne trebaju nam nikakvi novi koncepti s kojima već nismo
radili. U ovom istom primjeru mogli smo istim tim konceptima i
preimenovati i/ili ispustiti neke atribute. Evo varijante koja ujedno i
preimenuje atribute:

``` python
# ulazni podaci
zaglavlje = ['Naslov', 'Autor', 'Godina', 'Izdavač', 'ISBN']
redak = ['Good Omens',  'Terry Pratchett & Neil Gaiman',  1990, 'Gollancz', '0-575-04800-X']

# rječnik preimenovanja atributa
prevedi = {
    'Naslov': 'title',
    'Autor': 'author',
    'Godina': 'year',
    'Izdavač': 'publisher',
    'ISBN': 'ISBN'  # ovdje nema promjene u nazivu 
}

# izradi prazan rječnik koji ćemo popuniti ulaznim podacima
redak_rjecnik = {}  

# zaglavlje i redak po definiciji imaju jednak broj vrijednosti
# vrijednost na indeksu "i" u retku odgovara svojstvu na indeksu "i" u zaglavlju 
for i in range(len(header)):
    naziv = zaglavlje[i]    # dohvati naziv
    naziv = prevedi[naziv]  # prevedi naziv
    vrijednost = redak[i]   # dohvati vrijednost
    redak_rjecnik[naziv]  = vrijednost  # postavi vrijednost pod specifičan naziv u rječnik
``` 

Pogledajmo sad kako ovo primijeniti na cijelu tablicu. Primjer niže
jednostavno spaja primjere
<a href="#listing:pp_u_rp2" data-reference-type="ref"
data-reference="listing:pp_u_rp2">[listing:pp_u_rp2]</a> i
<a href="#listing:popis_u_rjecnik" data-reference-type="ref"
data-reference="listing:popis_u_rjecnik">[listing:popis_u_rjecnik]</a>.

``` python
# ulazni podaci
zaglavlje = ['Naslov', 'Autor', 'Godina', 'Izdavač', 'ISBN']
tablica = [
    ['Good Omens',  'Terry Pratchett & Neil Gaiman',  1990, 'Gollancz', '0-575-04800-X'],
    ['Interesting times',  'Terry Pratchett',  1994, 'Gollancz', '0-575-05800-5'],
    ['Neverwhere',  'Neil Gaiman',  1996, 'BBC Books', '0-7472-6668-9']
]

# rječnik preimenovanja atributa
prevedi = {'Naslov': 'title', 'Autor': 'author', 'Godina': 'year', 
'Izdavač': 'publisher', 'ISBN': 'ISBN'}

# izradi prazan rječnik za sve podatke
podaci = {}
# postavi brojač za šifre na 0
sifra = 0
# zaglavlje i redak po definiciji imaju jednak broj vrijednosti
# vrijednost na indeksu "i" u retku odgovara svojstvu na indeksu "i" u zaglavlju 
for redak in tablica:
    # izradi prazan rječnik koji ćemo popuniti ulaznim podacima
    redak_rjecnik = {}  
    for i in range(len(header)):
        # postavi vrijednost pod prevedeni naziv u rječnik
        prevedeni_naziv = prevedi[zaglavlje[i]]
        redak_rjecnik[prevedeni_naziv] = redak[i] 
    podaci[sifra] = redak_rjecnik
    sifra += 1
``` 

Sada kada možemo raditi s podacima na ovoj razini, relativno je lako
doraditi gore prikazan proces da, na primjer, ispušta neke atribute
i/ili jedinice koje nas ne zanimaju ili pak priprema vrijednosti
određenih atributa i slično.

## Tablica vs. strukturirani podaci

Kako napredujemo mogućnostima u reprezentaciji tabličnih podataka,
možemo vidjeti da se sve više udaljavamo od koncepta tablice. Ovo i
želimo jer je struktura tablice često previše ograničavajuća, a i pomalo
neprecizna. "Tablica" je koncept koji se koristi šire od strukture
podataka, te je pitanje da li dopušta na primjer, koncepte poput
"spojenih ćelija" ili ugniježdenih struktura (na primjer popis
vrijednosti ili tablica kao vrijednost u "ćeliji").

Usredotočimo se stoga na redak. Ako ne razmišljamo o tome što on
predstavlja u kontekstu tablice već u kontekstu strukturiranih podataka,
možemo ga nazvati podatkovna jedinica, entitet, zapis ili što slično.
Naši podaci su skup tih jedinica, a jedinice dijele zajedničku
strukturu.

Vrijednosti nekih svojstava podatkovne jedinice također mogu biti
strukture vrijednosti, što tu podatkovnu jedinicu čini sve manje nalik
na redak u tablici. Promotrimo u našem primjeru vrijednosti za atribut
"autor". "Terry Pratchett & Neil Gaiman" nije neobična vrijednost budući
da neko djelo može imati više autora. To nam samo po sebi već govori da
je vrijednost atributa "autori" zapravo struktura vrijednosti i to popis
autora (odnosno stringova).

Pogledajmo kako postaviti naš bibliografski zapis za neku knjigu kako bi
dopuštao koautorstvo.

``` python
zapis = {
   'Naslov': 'Good Omens', 
   'Autor': ['Terry Pratchett', 'Neil Gaiman'],  # atribut Autor sad dopušta više vrijednosti!
   'Godina': 1990,
   'Izdavač': 'Gollancz',
   'ISBN': '0-575-05800-5'
}
# funkcija len sad računa broj imena autora, a ne broj slova u polju autori
broj_autora = len(zapis['Autor'])
# također, možemo dohvatiti npr. prvog autora
prvi_autor = zapis['Autor'][0]
```

Jednostavno rečeno, ako postavimo atribut "Autor" da može primati više
vrijednosti, tada u podacima dopuštamo koautorstvo i omogućavamo
odgovore na pitanja poput "Koliko autora je potpisano na neku
publikaciju?" i "Na koliko je publikacija neki autor potpisan?".
Također, individualna podatkovna jedinica nam sada ima ugniježđene
strukture (vrijednosti nekih svojstava su strukture vrijednosti, a ne
jedinične vrijednost) pa se više ne može zapisati kao redak u
tablicu![^5]

Ovu ideju je ne samo moguće već i preporučeno odvesti dalje. Na primjer,
kada razmislimo o individualnom imenu autora primijetiti ćemo da se ono
(najčešće) sastoji od imena i prezimena. Čim smo utvrdili da neka
vrijednost ima svoje dijelove, utvrdili smo da je vrijednost složena te,
shodno tome, da je struktura podataka primjeren način za reprezentaciju
ovakvih vrijednosti. Na primjer, osobno ime možemo prikazati kao:

``` python
osoba = {
    'ime': 'Terry', 
    'prezime': 'Pratchett'
}
```

Kako ovu ideju iskoristiti u našim podacima?

``` python
zapis = {
    'Naslov': 'Good Omens', 
    'Autor': [
        {'ime': 'Terry', 'prezime': 'Pratchett'},
        {'ime': 'Neil',  'prezime': 'Gaiman'},
    ],  
    'Godina': 1990,
    'Izdavač': 'Gollancz',
    'ISBN': '0-575-05800-5'
}

# još uvjek možemo sve što i prije
broj_autora = len(zapis['Autor'])
prvi_autor = zapis['Autor'][0]
# ali i više
prezime_prvog_autora = zapis['Autor'][0]['prezime']
```

Kao što vidimo, ovakvo strukturiranje nam omogućava nove radnje s
podacima jer se sada možemo referirati na individualne dijelove osobnih
imena. Sada nam je, na primjer, lakše generirati stringove u obliku "Ime
Prezime", "Prezime, Ime" ili "Prezime, I." za različite potrebe.

Zbirka ovakvih podatkovnih jedinica su naši "strukturirani podaci" s
kojima nam sada postaje idealno za raditi u programskom okruženju. Kako
ćemo konkretno postaviti podatke (popis popisa, rječnik rječnika, itd.)
ovisi o zadatku, odnosno o tome kako nam je najlakše pristupiti rješenju
nekog problema.

[^1]: Pored toga što sam tekst već možemo shvatiti kao strukturu,
    odnosno niz znakova.

[^2]: Svaki redak je jedna "podatkovna jedinica" odnosno "instanca
    entiteta".

[^3]: Svaki stupac označava svojstvo.

[^4]: Naravno, uvijek ga možemo stvoriti po potrebi

[^5]: Strukturu podataka možemo zapisati kao **text** u ćeliju, ali ne
    možemo adresirati unutar tog teksta, što poražava svrhu. Također,
    neke relacijske baze poput PostgreSQLa od nedavno dopuštaju pohranu
    strukturiranih vrijednosti unutar ćelije i adresiranje unutar
    ćelije, što ih čini hibridnim radije no relacijskim bazama.# python_101
