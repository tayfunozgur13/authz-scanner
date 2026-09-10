# AuthZ Scanner Presentation Plan

Bu dosya 34 slaytlik teknik sunumun calisma taslagidir.

Amac:

- Slayt basliklarini tek yerde toplamak
- Ekrana koyulacak kisa icerigi ayirmak
- Konusma notlarini teknik olarak hazir tutmak
- En son sunum dosyasi hazirlanirken karar verilen sayfalari buradan almak

Not:

- Slaytlar cok metinle doldurulmayacak.
- Teknik detaylar daha cok konusma notlarinda tutulacak.
- Demo sirasinda repo, config, terminal ve HTML report ekranlari destekleyici kanit olarak kullanilacak.

---

## Proposed Slide Structure

1. AuthZ Scanner
2. Motivation
3. Authentication vs Authorization
4. API Authorization Vulnerability Classes
5. Project Objective
6. High-Level Architecture
7. Repository Structure
8. Demo API Lab
9. Vulnerable vs Hardened API Design
10. Domain and Role Model
11. JWT Authentication Flow
12. Why Config-Driven Design
13. YAML Configuration Model
14. Identity and Ownership Mapping
15. Scanner Execution Flow
16. Core Components
17. HTTP Executor and Response Handling
18. BOLA Testing Module
19. BFLA Testing Module
20. Property Authorization and Mass Assignment
21. Excessive Data Exposure
22. Response Body Matchers
23. Unauthenticated Access Testing
24. Finding and Evidence Model
25. Severity, Risk Score and Business Impact
26. Reporting Layer
27. Safety Features
28. OpenAPI Starter Config and Config Doctor
29. Demo Results
30. Vulnerable vs Hardened Comparison
31. Test Coverage
32. Limitations
33. Future Work
34. Conclusion

---

## Narrative Flow Review

Bu sunumda tekrar hissini azaltmak icin slaytlarin rolu su sekilde ayrildi:

- Slide 1-5: Problem, motivasyon ve proje hedefi
- Slide 6-10: Genel mimari ve demo API lab ortami
- Slide 11-17: Scanner'in teknik calisma modeli
- Slide 18-23: Guvenlik test modulleri
- Slide 24-28: Finding, evidence, reporting ve guvenli kullanim mekanizmalari
- Slide 29-34: Demo sonuc, test coverage, limitler, gelecek isler ve kapanis

Sunum yaparken dikkat:

- Slide 6'da sadece buyuk resmi anlat; detayli execution flow Slide 15'te gelecek.
- Slide 8-9'da vulnerable/hardened mantigini kur; sonuc karsilastirmasini Slide 29-30'a birak.
- Slide 13'te manuel YAML'dan OpenAPI starter config'e gecis nedenini acikla; Slide 28'de bu akisin nasil guvenli hale getirildigini detaylandir.
- Slide 21-22'de status code dogru olsa bile response body'nin guvenlik problemi uretebilecegini vurgula.
- Slide 32'de limitleri soylemekten cekinme; bu kisim projenin profesyonel degerlendirmesini guclendirir.

## Review Status

- [x] Slide 1-5: Giris, problem ve hedef akisi kontrol edildi.
- [x] Slide 6-10: Mimari ve demo API lab akisi kontrol edildi.
- [x] Slide 11-17: Scanner teknik calisma modeli kontrol edildi.
- [x] Slide 18-23: Test modulleri kontrol edildi.
- [x] Slide 24-28: Finding, evidence, reporting ve safety bolumu kontrol edildi.
- [x] Slide 29-34: Demo sonuc, test coverage, limitler ve kapanis kontrol edildi.
- [x] Demo sonuc sayisi guncellendi: default vulnerable scan `10 findings`, hardened scan `0 findings`.
- [x] Unauthenticated access anlatimi duzeltildi: modul calisiyor, ancak mevcut demo endpointleri dogru 401 dondugu icin default scan'de finding uretmiyor.

---

## Slide 1 - AuthZ Scanner

### On-Slide Content

```text
AuthZ Scanner
Config-Driven API Authorization Security Scanner

Python tabanli, raporlanabilir ve tekrar calistirilabilir API authorization test araci
```

### Speaker Notes

Bu slaytta projeyi sadece bir demo API olarak degil, API authorization testlerini otomatiklestiren bir guvenlik araci olarak tanitacagim.

Projenin ana fikri, manuel olarak yapilan authorization kontrollerini tekrar calistirilabilir, config tabanli ve raporlanabilir bir scanner akisina donusturmek.

### Visual Suggestion

Proje adi, kisa alt baslik ve sade mimari ikonlari.

---

## Slide 2 - Motivation

### On-Slide Content

```text
Authorization bugs are common, critical, and often missed during manual API testing.

Goal:
Make API authorization testing repeatable, configurable, and reportable.
```

### Speaker Notes

Bu projeyi yapma motivasyonum, API guvenliginde authorization problemlerinin hem kritik hem de manuel testlerde kolay gozden kacabilir olmasi.

Bir kullanicinin sisteme giris yapabilmesi tek basina yeterli degil. Giris yaptiktan sonra hangi kaynaga, hangi rol ile ve hangi islem icin erisebildigi ayrica dogrulanmali.

Bu proje, bu dogrulamayi sistematik hale getirmeyi hedefliyor.

### Visual Suggestion

Manuel testten otomatik scanner akisina gecisi gosteren basit ok diyagrami.

---

## Slide 3 - Authentication vs Authorization

### On-Slide Content

```text
Authentication:
Who are you?

Authorization:
What are you allowed to access or modify?
```

### Speaker Notes

Authentication kullanicinin kim oldugunu dogrular. Ornegin login olmak, JWT almak veya session olusturmak authentication tarafidir.

Authorization ise bu kimligin neye izinli oldugunu belirler. Kullanici kendi siparisini gorebilir ama baska bir kullanicinin siparisini gormemelidir. Normal kullanici admin endpointlerine erisememelidir.

Bu projenin asil odagi authentication degil, authentication sonrasi authorization kontrolleridir.

### Visual Suggestion

Iki kolonlu karsilastirma: Authentication vs Authorization.

---

## Slide 4 - API Authorization Vulnerability Classes

### On-Slide Content

```text
BOLA
BFLA
Mass Assignment
Excessive Data Exposure
Unauthenticated Access
Response Body Mismatch
```

### Speaker Notes

Scanner birden fazla authorization problem sinifini test ediyor.

BOLA object seviyesinde yetki kontrolunu test eder. BFLA fonksiyon veya endpoint seviyesinde role kontrolunu test eder.

Mass assignment request body ile server-controlled alanlarin manipule edilmesini test eder. Excessive data exposure response icinde gereksiz hassas alan donup donmedigine bakar.

Unauthenticated access protected endpointlerin token olmadan erisilebilir olup olmadigini kontrol eder. Response body mismatch ise response govdesinin config icinde tanimlanan guvenlik kontratina uyup uymadigini test eder.

### Visual Suggestion

Zafiyet siniflarini kartlar halinde gosteren sade grid.

---

## Slide 5 - Project Objective

### On-Slide Content

```text
Build a scanner that can:

- authenticate multiple identities
- test role and ownership rules
- compare expected vs observed API behavior
- generate pentest-style reports
- support vulnerable vs hardened comparison
```

### Speaker Notes

Projenin hedefi sadece endpointlere istek atmak degil. Farkli identity ve rollerle API davranisini test edip beklenen guvenli davranisla gercek cevabi karsilastirmak.

Eger fark varsa scanner finding uretir. Bu finding sadece teknik hata olarak kalmaz; evidence, business impact, severity, risk score, remediation ve cURL reproduction ile raporlanir.

### Visual Suggestion

Scanner hedeflerini bes maddelik sade liste olarak goster.

---

## Slide 6 - High-Level Architecture

### On-Slide Content

```text
YAML Config
    ↓
Identity Manager
    ↓
Scanner Modules
    ↓
HTTP Executor
    ↓
Finding + Evidence
    ↓
JSON / Markdown / HTML Reports
```

### Speaker Notes

Scanner'in ana akisi config dosyasindan baslar. YAML config icinde hedef API, auth bilgileri, kullanici kimlikleri, roller, endpointler ve beklenen davranislar tanimlanir.

Identity manager kullanicilar icin login olur ve token/session bilgilerini hazirlar.

Bu slaytta amac tum detaylari anlatmak degil, scanner'in katmanli akis mantigini gostermektir. Modullerin nasil calistigi ve finding/evidence'in nasil olustugu ilerleyen teknik slaytlarda acilacak.

Son adimda JSON, Markdown veya HTML rapor uretilir.

### Visual Suggestion

Dikey pipeline diyagrami.

---

## Slide 7 - Repository Structure

### On-Slide Content

```text
apps/
  vulnerable_api/
  hardened_api/

scanner/
  core/
  modules/
  reporting/
  discovery/

config/
tests/
reports/
```

### Speaker Notes

Repo yapisi bilerek katmanli tasarlandi.

`apps` altinda demo API lab bulunuyor. `scanner/core` scanner'in ortak motorunu, `scanner/modules` test modullerini, `scanner/reporting` rapor uretimini, `scanner/discovery` ise OpenAPI starter config uretimini iceriyor.

`config` klasoru YAML test tanimlarini tutuyor. `tests` otomatik testleri, `reports` ise uretilen scan ciktilarini tutuyor.

### Visual Suggestion

VS Code/Cursor file structure screenshot.

---

## Slide 8 - Demo API Lab

### On-Slide Content

```text
vulnerable_api:
intentionally weak authorization behavior

hardened_api:
secure implementation of the same API surface
```

### Speaker Notes

Scanner'i dogrulamak icin kontrollu bir lab ortami kurduk.

Vulnerable API bilerek zayif authorization davranislari iceriyor. Hardened API ise ayni endpointlerin guvenli uygulanmis hali.

Bu sayede scanner'in hem aciklari buldugunu hem de guvenli implementation'da false positive uretmedigini gosterebiliyoruz.

### Visual Suggestion

Vulnerable ve hardened API'yi yan yana gosteren iki kutulu diyagram.

---

## Slide 9 - Vulnerable vs Hardened API Design

### On-Slide Content

```text
Same endpoints
Same roles
Same domain model
Different authorization behavior
```

### Speaker Notes

Iki API'nin endpointleri, roller ve domain modeli ayni olacak sekilde tasarlandi. Bu slaytta asil vurgu test yuzeyinin ayni, guvenlik davranisinin farkli olmasidir.

Bu karar scanner'in davranisini daha net test etmemizi sagladi. Ayni endpoint seti uzerinden hem zafiyetli davranisi hem de guvenli implementasyonu gosterebiliyoruz.

Asil sonuc karsilastirmasi sunumun sonunda Slide 29 ve Slide 30'da gosterilecek.

### Visual Suggestion

Same surface, different behavior seklinde karsilastirma.

---

## Slide 10 - Domain and Role Model

### On-Slide Content

```text
Domain:
Users, Orders, Order Items, Invoices, Organizations, Support Tickets

Roles:
customer, support, manager, admin
```

### Speaker Notes

Proje baslangicta daha basit bir user-order modeliyle basladi. Sonra daha gercekci pentest senaryolari icin domain genisletildi.

Orders ve order items BOLA icin temel ownership senaryolari sagliyor. Invoices ve organizations tenant isolation testleri icin kullaniliyor. Support tickets ise customer, support, manager ve admin rollerini daha anlamli hale getiriyor.

Bu rol modeli sayesinde sadece kullanici-kaynak iliskisi degil, role-based workflow ve data exposure senaryolari da test edilebiliyor.

### Visual Suggestion

Domain entity listesi ve role hiyerarsisi.

---

## Slide 11 - JWT Authentication Flow

### On-Slide Content

```text
Login Request
    ↓
Access Token
    ↓
Authenticated Identity
    ↓
Authorized API Requests
```

### Speaker Notes

Scanner authorization testi yapmadan once hedef API'ye farkli identity'lerle authenticate olur.

Demo API'lerde temel akis JWT uzerinden ilerliyor. Scanner config icindeki identity bilgilerini kullanarak login endpointine istek gonderir, response icinden access token'i alir ve sonraki test requestlerinde bu token'i kullanir.

Bu noktada JWT bizim icin asil test konusu degil, authorization testlerini calistirabilmek icin gerekli kimlik tasima mekanizmasidir. Yani scanner once "kim bu kullanici?" sorusunu cozer, sonra "bu kullanici hangi kaynaga veya fonksiyona erisebilir?" sorusunu test eder.

Projede bearer token disinda cookie/session, static token, custom auth header ve refresh token destekleri de eklendi. Bunun sebebi scanner'in sadece bizim demo API'ye degil, farkli authentication yapilarina sahip API'lere de uyarlanabilmesidir.

### Visual Suggestion

Login endpointinden token alinip protected endpointlere giden basit akıs diyagrami.

---

## Slide 12 - Why Config-Driven Design

### On-Slide Content

```text
Scanner is not coupled to API internals.

It tests behavior through HTTP:

identity + role + resource + expected behavior
```

### Speaker Notes

Bu projedeki en onemli mimari karar scanner'i API'nin ic koduna baglamamakti.

Scanner veritabanina baglanmaz, SQLAlchemy modellerini import etmez ve API fonksiyonlarini dogrudan cagirmak yerine HTTP istekleri uzerinden davranisi gozlemler.

Authorization testinde asil ihtiyacimiz API'nin ic implementasyonu degil, hangi identity'nin hangi resource'a veya fonksiyona erismemesi gerektigidir.

Bu nedenle kurallar YAML config icine tasindi. Yeni bir API test edileceginde scanner kodunu degistirmek yerine yeni config dosyasi hazirlanir.

Bu yaklasim araci daha portable hale getirir ve pentest senaryolarinin koddan ayrilmasini saglar.

### Visual Suggestion

Solda API internal code, sagda HTTP behavior scanner karsilastirmasi.

---

## Slide 13 - YAML Configuration Model

### On-Slide Content

```text
Config defines:

- target API
- authentication flow
- identities and roles
- resource ownership rules
- expected status codes
- response matchers
- severity and business impact

Evolution:
manual YAML → OpenAPI starter config → human review
```

### Speaker Notes

YAML config scanner'in test planidir.

Config icinde hedef API'nin base URL bilgisi, login endpointi, token extraction ayarlari, kullanici identity'leri, roller ve test edilecek endpointler tanimlanir.

BOLA testlerinde resource list endpointi, id field ve owner field gibi bilgiler verilir. BFLA testlerinde hangi role sahip kullanicinin hangi fonksiyona erismemesi gerektigi tanimlanir.

Property authorization tarafinda forbidden fields, mass assignment payloadlari ve response body matcher kurallari config icinden gelir.

Bu yapi sayesinde test senaryolari kodun icine hardcoded yazilmaz. Scanner motoru genel kalir, hedef API'ye ozel bilgi configte tutulur.

Projede baslangicta YAML configleri manuel hazirladik. Bu bilincli bir tercihti cunku once authorization kurallarini dogru modellemek gerekiyordu. Hangi kullanici hangi resource'a erismemeli, hangi role hangi endpoint kapali olmali, hangi response field hassas kabul edilmeli gibi kararlar manuel olarak netlestirildi.

Daha sonra projenin sadece demo API'ye degil baska API'lere de uyarlanmasi hedeflendigi icin manuel YAML uretiminin zaman maliyeti ortaya cikti. Endpoint sayisi arttikca her path, method ve test adayini elle yazmak verimsiz hale gelebilirdi.

Bu nedenle OpenAPI dokumanindan starter config ureten bir yapi eklendi. Ancak generated config final scan policy olarak kabul edilmiyor. OpenAPI endpointleri ve schema bilgilerini gosterebilir ama business authorization kurallarini her zaman bilemez. Bu yuzden human review adimi hala gerekli tutuldu.

### Visual Suggestion

Manual YAML'dan OpenAPI starter config'e ve oradan human review'a giden kucuk evrim diyagrami.

---

## Slide 14 - Identity and Ownership Mapping

### On-Slide Content

```text
Identity:
userA, userB, admin1, support1, manager1

Role:
customer, support, manager, admin

Ownership:
resource.owner_id == profile.id
```

### Speaker Notes

Authorization testlerinde sadece endpoint bilmek yeterli degildir. Scanner'in farkli identity'ler arasindaki iliskiyi de bilmesi gerekir.

Ornegin BOLA testinde once customer rolunde iki farkli kullanici gerekir. Scanner userA'nin sahip oldugu bir resource ID bulur, sonra userB ile ayni resource'a erismeyi dener.

Bu eslesme profile endpointinden donen subject id ile resource response icindeki owner field uzerinden yapilir.

Boylece scanner userA ve userB gibi demo isimlerine bagimli kalmaz. Asil mantik ayni role sahip farkli subject'ler arasinda ownership boundary test etmektir.

Bu karar, scanner'in baska API'lere uyarlanabilmesi icin onemlidir.

### Visual Suggestion

userA -> own order, userB -> same order attack request diyagrami.

---

## Slide 15 - Scanner Execution Flow

### On-Slide Content

```text
1. Load config
2. Authenticate identities
3. Run enabled modules
4. Send HTTP requests
5. Compare expected vs observed behavior
6. Build findings and evidence
7. Generate reports
```

### Speaker Notes

Scanner calistiginda once YAML config parse edilir ve Pydantic modelleriyle dogrulanir.

Sonra identity manager her kullanici icin authentication islemini yapar. Bu asamadan sonra scanner modulleri devreye girer.

Her modul kendi test mantigina gore HTTP requestleri olusturur. HTTP executor requestleri gonderir ve response sonucunu standart bir result modeline cevirir.

Response geldikten sonra scanner expected behavior ile observed behavior'i karsilastirir. Uyumsuzluk varsa finding olusur.

Finding icinde evidence, severity, risk score, business impact ve remediation gibi raporlama icin gerekli bilgiler tutulur.

### Visual Suggestion

Numaralandirilmis execution pipeline.

---

## Slide 16 - Core Components

### On-Slide Content

```text
scanner/core

config.py
identity.py
executor.py
result.py
evidence.py
finding.py
risk.py
destructive.py
config_doctor.py
```

### Speaker Notes

`scanner/core` scanner'in ortak altyapisini icerir.

`config.py` YAML yapisini Pydantic modelleriyle temsil eder. `identity.py` login, token extraction, cookie/session ve refresh token gibi authentication detaylarini yonetir.

`executor.py` HTTP requestleri gonderir. `result.py` response sonucunu normalize eder. `evidence.py` her bulgu icin request-response kanitini tutar.

`finding.py` zafiyet bulgusunun ana modelidir. `risk.py` severity ve risk score hesaplama mantigini icerir.

`destructive.py` veri degistiren testleri varsayilan olarak skip etmeyi saglar. `config_doctor.py` ise config dosyasini scan baslamadan once kontrol eder.

### Visual Suggestion

Core component listesi veya kutucuk diyagrami.

---

## Slide 17 - HTTP Executor and Response Handling

### On-Slide Content

```text
HTTP Executor:

- sends authenticated requests
- attaches token/cookie/header
- parses JSON responses
- stores response text fallback
- supports token refresh
```

### Speaker Notes

HTTP executor scanner'in hedef API ile konusan katmanidir.

Test modulleri dogrudan HTTP client detaylariyla ugrasmadan executor uzerinden request gonderir. Executor identity bilgisine gore gerekli authorization header, cookie veya custom auth degerlerini requeste ekler.

Response JSON ise parse edilir. JSON degilse response text olarak saklanir. Bu sayede hem JSON API'ler hem de text/error response'lar evidence icinde tutulabilir.

Refresh token destegi sayesinde access token suresi doldugunda scanner belirli status kodlari uzerinden token yenilemeyi deneyebilir.

Bu katman test modulleri ile HTTP detaylarini birbirinden ayirdigi icin scanner'in genislemesi kolaylasir.

### Visual Suggestion

Scanner module -> HTTP executor -> API -> normalized response diyagrami.

---

## Slide 18 - BOLA Testing Module

### On-Slide Content

```text
BOLA test flow:

1. Select two identities with the same role
2. Find a resource owned by identity A
3. Request the same resource as identity B
4. Compare observed status with expected status
5. Create finding if access is allowed
```

### Speaker Notes

BOLA, yani Broken Object Level Authorization, API guvenliginde en kritik authorization problemlerinden biridir.

Bu modulde amac, bir kullanicinin baska bir kullaniciya ait objeye sadece ID degistirerek erisip erisemedigini test etmektir.

Scanner once ayni role sahip iki identity secer. Ornegin customer rolunde userA ve userB. Sonra userA'nin sahip oldugu bir resource bulunur. Bu resource bir order, invoice veya support ticket olabilir.

Daha sonra scanner ayni resource ID ile userB adina request gonderir. Guvenli davranista API'nin 403 veya 404 gibi bir cevap donmesi beklenir. Eger API 200 donerse bu, userB'nin userA'ya ait objeye erisebildigi anlamina gelir ve BOLA finding olusur.

Bu testte onemli nokta scanner'in demo isimlere bagli olmamasidir. Esas mantik, ayni role sahip farkli subject'ler arasinda ownership boundary test etmektir.

### Visual Suggestion

userA owns order-1; userB requests order-1; expected 403, observed 200 diyagrami.

---

## Slide 19 - BFLA Testing Module

### On-Slide Content

```text
BFLA test flow:

1. Select a low-privilege identity
2. Target a privileged endpoint or function
3. Send request as the low-privilege identity
4. Compare expected vs observed status
5. Report role/function-level bypass
```

### Speaker Notes

BFLA, yani Broken Function Level Authorization, object ownership'ten farkli bir problemi test eder.

BOLA'da soru "bu obje kime ait?" iken BFLA'da soru "bu fonksiyonu hangi rol calistirabilir?" seklindedir.

Ornegin normal bir customer kullanicisi `/admin/users` endpointine erisememelidir. Benzer sekilde support rolu her support islemini yapabilir gibi dusunulmemelidir; bazi islemler manager veya admin rolune ayrilmis olabilir.

Scanner config icinde role ve endpoint bilgisi verilir. Sonra scanner bu role sahip identity ile ilgili endpointi cagirir. Beklenen cevap 403 iken API 200 donerse BFLA finding olusur.

Bu modul projeye role-based authorization davranisini test etmek icin eklendi. Cunku gercek API'lerde aciklar sadece resource ID degistirmekten degil, yanlis korunmus fonksiyonlardan da kaynaklanir.

### Visual Suggestion

customer -> /admin/users request; expected denied, observed allowed seklinde akis.

---

## Slide 20 - Property Authorization and Mass Assignment

### On-Slide Content

```text
Property authorization checks:

- server-controlled fields
- role changes
- ownership changes
- status manipulation
- pricing / total manipulation

Example:
{ "role": "admin" }
{ "status": "approved", "total_amount": "0.01" }
```

### Speaker Notes

Authorization problemleri her zaman URL path veya endpoint seviyesinde ortaya cikmaz. Bazen sorun request body icindeki alanlardan gelir.

Mass assignment senaryosunda client, normalde server tarafindan kontrol edilmesi gereken alanlari request body icine ekler. Ornegin `role`, `owner_id`, `status`, `total_amount` gibi alanlar kullanici tarafindan manipule edilmeye calisilabilir.

Scanner bu modulu kullanarak birden fazla payload dener. API bu alanlari kabul eder ve response veya verification request sonucunda forbidden effect gorulurse finding olusur.

Projede bunun icin order create senaryolari ve user role promotion senaryosu eklendi. Ornegin customer kendi rolunu admin yapmaya calisabilir veya siparisi dusuk tutarla approved/refunded state'inde olusturmayi deneyebilir.

Bu modulu eklememizin sebebi, field-level authorization eksikliklerini yakalamakti. Cunku endpoint korumasi dogru olsa bile request body icindeki tehlikeli alanlar filtrelenmiyorsa ciddi is mantigi aciklari olusabilir.

### Visual Suggestion

Request body icinde forbidden field -> API accepts -> forbidden effect detected diyagrami.

---

## Slide 21 - Excessive Data Exposure

### On-Slide Content

```text
Status code may be correct,
but response body may still be unsafe.

Checks for fields such as:

- password_hash
- token
- refresh_token
- api_key
- internal_notes
```

### Speaker Notes

Excessive Data Exposure modulu, API response icinde client'in almamasi gereken alanlar donuyor mu sorusunu test eder.

Bu zafiyette status code her zaman hatali olmak zorunda degildir. Ornegin `/users/me` endpointinin 200 donmesi normaldir. Ama response icinde `password_hash`, `token`, `api_key` gibi hassas alanlar varsa bu yine guvenlik problemidir.

Ayni sekilde support ticket response'u customer icin 200 donebilir, cunku kullanici kendi ticket detayini goruyor olabilir. Fakat response icinde `internal_notes` varsa musteriye internal operasyonel bilgi sizdirilmis olur.

Bu yuzden bazi findingslerde expected status ve observed status ayni gorunebilir. Finding'in nedeni status code degil, response body icindeki hassas veridir.

Bu modul raporlama acisindan da onemliydi cunku pentest raporunda sadece HTTP status degil, hangi field'in sizdigi evidence olarak gosteriliyor.

### Visual Suggestion

200 OK response icinde kirmizi isaretlenmis sensitive fields.

---

## Slide 22 - Response Body Matchers

### On-Slide Content

```text
Response contract checks:

- body_should_contain
- body_should_not_contain
- field_should_equal
- field_should_not_equal

Finding:
Response Body Mismatch
```

### Speaker Notes

Response Body Matcher sonradan eklenen daha gelismis response kontrol katmanidir.

Excessive data exposure daha cok forbidden field isimlerini ararken, response body matcher daha genel bir security contract tanimlamayi saglar.

Config icinde response icinde belli metinlerin olmasi veya olmamasi, belirli field'larin belirli degerlere esit olmasi veya olmamasi tanimlanabilir.

Ornegin customer-facing support ticket response icinde `internal_notes` metni hic gecmemeli. Ya da bir field belirli bir state'e esit olmamali.

Bu ozelligi eklememizin sebebi scanner'in sadece status-code-only bir arac gibi kalmamasi. Gercek API testlerinde bazen authorization problemi response icindeki kucuk bir veri farkindan anlasilir.

Matcher ihlali olursa scanner `Response Body Mismatch` finding uretir. Bu finding de digerleri gibi evidence, severity, risk score, business impact, remediation ve cURL reproduction ile rapora girer.

### Visual Suggestion

YAML matcher snippet'i ve yaninda failed matcher -> finding akis diyagrami.

---

## Slide 23 - Unauthenticated Access Testing

### On-Slide Content

```text
Unauthenticated access checks:

1. Send request without token/session
2. Target protected endpoint
3. Expect 401 or 403
4. Report if endpoint allows access
```

### Speaker Notes

Unauthenticated access testleri authorization modullerinin tamamlayici parcasidir.

Authorization testlerinden once temel olarak protected endpointlerin authentication gerektirip gerektirmedigini de kontrol etmek gerekir.

Bu modul token, cookie veya session bilgisi gondermeden protected endpointlere request atar. Ornegin `/users/me` veya `/admin/users` gibi endpointler token olmadan 401 veya 403 donmelidir.

Eger API token olmadan 200 donerse bu artik role veya ownership problemi degil, daha temel bir broken authentication problemidir.

Bu modulu eklememizin sebebi scanner'in sadece authenticated identity'ler arasindaki authorization farklarini degil, anonymous access riskini de raporlayabilmesidir.

### Visual Suggestion

anonymous request -> protected endpoint -> expected 401/403 seklinde basit diyagram.

---

## Slide 24 - Finding and Evidence Model

### On-Slide Content

```text
Finding:

- vulnerability class
- endpoint and method
- identity
- expected vs observed behavior
- evidence
- remediation
```

### Speaker Notes

Scanner bir zafiyet yakaladiginda bunu sadece terminalde basit bir hata olarak gostermiyor. Her problem standart bir finding modeline donusturuluyor.

Finding icinde zafiyet sinifi, endpoint, HTTP method, test edilen identity, severity, risk score, business impact, remediation ve evidence bilgileri tutuluyor.

Evidence modeli ise request-response kanitidir. Hangi identity ile hangi request gonderildi, beklenen status neydi, observed status ne oldu, request body ve response body neydi gibi bilgiler evidence icinde saklanir.

Bu ayrim onemli cunku pentest raporunda bir bulgunun tekrar uretilebilir olmasi gerekir. Sadece "BOLA bulundu" demek yeterli degil; hangi istekle ve hangi cevapla bulundugu gosterilmelidir.

Bu nedenle raporlarda appendix ve cURL reproduction bilgileri de uretiliyor.

### Visual Suggestion

Finding object -> Evidence list -> Report appendix diyagrami.

---

## Slide 25 - Severity, Risk Score and Business Impact

### On-Slide Content

```text
Each finding includes:

- severity
- numeric risk score
- business impact
- OWASP API category
- remediation guidance
```

### Speaker Notes

Projede bulgular sadece teknik olarak siniflandirilmiyor; risk ve is etkisiyle birlikte raporlaniyor.

Severity degeri `low`, `medium`, `high`, `critical` olabilir. Risk score ise 0-100 arasinda sayisal bir degerdir.

Scanner bazi durumlarda severity'yi otomatik infer edebilir. Ornegin privilege escalation veya admin/refund gibi kritik endpointler daha yuksek risk alir. Ama config icinden test veya payload seviyesinde severity ve risk score override etmek de mumkundur.

Business impact alani pentest raporu icin ozellikle onemlidir. Teknik olarak ayni gibi gorunen iki bulgunun is etkisi farkli olabilir. Ornegin bir order detayinin okunmasi ile tenant disi invoice okunmasi ayni riskte degildir.

Bu alanlar raporu sadece teknik scanner ciktisi olmaktan cikarip pentest-style rapora yaklastirir.

### Visual Suggestion

Bir finding karti uzerinde severity, risk score ve business impact bolumleri.

---

## Slide 26 - Reporting Layer

### On-Slide Content

```text
Report formats:

- JSON
- Markdown
- HTML

Report includes:
summary, findings, evidence, cURL, appendix
```

### Speaker Notes

Scanner sonucunda uc farkli rapor formati uretilebiliyor.

JSON rapor otomasyon, entegrasyon veya daha sonra programatik analiz icin uygun. Markdown rapor teknik dokumantasyon veya metin tabanli pentest raporu icin kullanilabilir.

HTML rapor ise sunum ve okunabilirlik acisindan en guclu formattir. Summary, findings by class, findings by severity, detailed findings, evidence, cURL reproduction ve appendix kisimlarini icerir.

En son HTML raporda evidence ve appendix kisimlari katlanabilir hale getirildi. Bu sayede bulgu sayisi arttiginda rapor okunabilir kalir ama teknik kanitlar kaybolmaz.

Raporlama katmani ayrica sensitive data redaction yapar. Token, password, password_hash, api_key gibi hassas degerler raporda maskelenir.

### Visual Suggestion

HTML report screenshot veya JSON/Markdown/HTML cikti ikonlari.

---

## Slide 27 - Safety Features

### On-Slide Content

```text
Safety controls:

- destructive test guard
- reset recommendation
- config doctor
- sensitive data redaction
- explicit include-destructive flag
```

### Speaker Notes

Scanner gercek API'lere uyarlanabilecek sekilde tasarlandigi icin guvenli calisma mekanizmalari da eklendi.

Destructive test guard veri degistiren testlerin varsayilan olarak calismasini engeller. PUT, POST, PATCH, DELETE veya role/status degistiren payloadlar destructive olarak isaretlenebilir.

Bu testler default scan'de skipped olur. Kullanici bilerek `--include-destructive` kullanirsa calisir.

`reset_recommended` alani, testin demo veriyi degistirebilecegini raporda gosterir. Scanner otomatik reset yapmaz, cunku gercek dis API'lerde gizli state reset davranisi tehlikeli olabilir.

Config doctor ise scan baslamadan once config dosyasinin calistirilabilir olup olmadigini kontrol eder. Bu da yanlis config nedeniyle hatali sonuc alma riskini azaltir.

### Visual Suggestion

Safety checklist: destructive guard, doctor, redaction, reset recommendation.

---

## Slide 28 - OpenAPI Starter Config and Config Doctor

### On-Slide Content

```text
Manual YAML:
accurate but time-consuming

OpenAPI starter config:
automates endpoint discovery

Human review:
keeps authorization decisions safe

Config doctor:
validates before scanning
```

### Speaker Notes

Projede configler baslangicta manuel hazirlandi. Bunun sebebi authorization kurallarinin once net sekilde modellenmesi gerektigiydi.

Manuel YAML bize kontrol sagladi ama baska API'lere uyarlanabilirlik hedefi buyuyunce endpointleri ve test adaylarini tek tek yazmak zaman maliyeti olusturdu.

Bu nedenle OpenAPI dokumanindan starter config ureten bir yapi eklendi. Bu yapi endpointleri, methodlari, path parametrelerini ve potansiyel test adaylarini cikarabilir.

Ancak burada bilincli olarak tam otomatik final config uretmiyoruz. OpenAPI genellikle business authorization kurallarini bilmez. Hangi rol hangi kaynaga erisebilir, hangi field hassastir veya hangi mutation destructive sayilir gibi kararlar pentester review gerektirir.

Bu yuzden generated config `review_required`, `review_notes` ve TODO placeholderlariyla gelir. Pentester bunlari tamamladiktan sonra config doctor ile dosyanin scan'e hazir olup olmadigini kontrol eder.

Config doctor login endpoint, token extraction, profile endpoint, identity coverage, path placeholderlari, resource list shape ve matcher/payload eksikleri gibi problemleri scan oncesi raporlar.

Bu akis manuel kontrol ile otomasyonu dengelemek icin eklendi.

### Visual Suggestion

Manual YAML -> OpenAPI starter -> Human review -> Config doctor -> Scanner pipeline diyagrami.

---

## Slide 29 - Demo Results

### On-Slide Content

```text
Demo scan results:

Vulnerable API:
10 findings

Hardened API:
0 findings

Default scan:
destructive tests skipped

Result changed:
19 → 10 findings after destructive tests were moved behind an explicit flag
```

### Speaker Notes

Demo sonucunda vulnerable API uzerinde scanner beklenen sekilde bulgular uretir.

Bu default scan'de bulgular BOLA, BFLA, excessive data exposure ve response body mismatch gibi farkli test siniflarindan gelir. Unauthenticated access testleri de calisir, ancak demo endpointleri token olmadan dogru sekilde 401 dondugu icin bu modulde finding olusmaz.

Hardened API uzerinde ise ayni scanner mantigi ve benzer config ile 0 finding sonucu beklenir. Bu, guvenli implementation'in scanner tarafindan false positive uretilmeden dogrulanabildigini gosterir.

Default scan'de destructive testler calistirilmaz. Bu nedenle veri degistiren testler skipped olarak raporlanir. Bu da aracinin guvenli varsayilan davranisini gosterir.

Daha once sunum notlarinda veya README'de vulnerable scan icin 19 finding bilgisi geciyordu. Bu sayi, veri degistiren destructive testlerin de scan kapsaminda sayildigi eski durumu temsil ediyordu.

Sonra projeye destructive test guard eklendi. Bu degisiklikle POST, PUT, PATCH, DELETE veya role/status degistiren payloadlar varsayilan scan'de calistirilmamaya baslandi. Bu testler artik raporda skipped olarak gorunur ve yalnizca kullanici bilerek `--include-destructive` verdiginde calisir.

Bu nedenle default vulnerable scan sonucu 19'dan 10 finding'e indi. Bu bir zafiyet silinmesi degil, scanner'in daha guvenli varsayilan davranisa gecmesidir.

### Visual Suggestion

Vulnerable HTML report summary screenshot ve hardened 0 finding terminal/report screenshot.

---

## Slide 30 - Vulnerable vs Hardened Comparison

### On-Slide Content

```text
Same test engine
Same scanner modules
Same security expectations

Different target behavior:

vulnerable → findings
hardened → no findings
```

### Speaker Notes

Bu projede vulnerable ve hardened API'ler icin ayri scanner motorlari yazilmadi.

Ayni test motoru, ayni moduller ve ayni expected behavior mantigi iki hedefe de uygulanir. Hedef sadece config uzerinden degisir.

Bu tasarim guvenlik testinin tarafsizligini artirir. Scanner vulnerable API icin ozel olarak acik bulmaya programlanmis degildir; sadece beklenen davranis ile gercek cevabi karsilastirir.

Vulnerable API'de authorization kontrolleri eksik oldugu icin findings olusur. Hardened API'de ownership, role, tenant ve response filtering kontrolleri dogru uygulandigi icin finding olusmaz.

Sunumda bu slayt projenin dogrulama mantigini guclu gosterir.

### Visual Suggestion

Yan yana iki sonuc karti: vulnerable 10 findings, hardened 0 findings.

---

## Slide 31 - Test Coverage

### On-Slide Content

```text
Automated tests cover:

- API behavior
- authentication flows
- scanner modules
- config loading
- config doctor
- reporting
- destructive guard
- OpenAPI discovery
```

### Speaker Notes

Projede sadece scanner kodu yazilmadi, davranisin korunmasi icin otomatik testler de eklendi.

Testler vulnerable ve hardened API davranislarini, JWT/cookie/refresh auth akislarini, BOLA/BFLA/property authorization modullerini, unauthenticated access testlerini, response body matchers'i, reporting katmanini ve config doctor'u kapsar.

Son durumda test suite 152 testten olusuyor ve tamamı geciyor.

Bu, projeyi sunarken onemli bir guven noktasi. Cunku arac sadece calisiyor gibi gorunen bir demo degil, otomatik testlerle dogrulanan bir kod tabanina sahip.

### Visual Suggestion

Test output screenshot veya `152 passed` sonucunu gosteren sade terminal gorseli.

---

## Slide 32 - Limitations

### On-Slide Content

```text
Current limitations:

- final authorization rules still require human review
- OpenAPI cannot infer business logic completely
- workflow/state transition testing is limited
- ID discovery strategies are basic
- OAuth2 enterprise flows are future work
```

### Speaker Notes

Projeyi sunarken limitleri acik soylemek onemli. Bu projeyi daha guvenilir gosterir, cunku authorization testing tamamen otomatik cozulebilen bir problem degildir.

OpenAPI endpointleri ve schema'lari gosterebilir ama business authorization kurallarini tam olarak bilemez. Bu nedenle generated config mutlaka pentester tarafindan review edilmelidir.

Mevcut scanner BOLA, BFLA, property authorization, data exposure ve response matcher gibi onemli testleri destekliyor. Ancak daha gelismis workflow/state transition testleri, IDOR enumeration stratejileri ve enterprise OAuth2 akislarinin daha fazla gelistirilmeye ihtiyaci var.

Bu limitler projenin eksik oldugu anlamina degil, bundan sonra hangi yonde profesyonel araca donusebilecegini gosterir.

### Visual Suggestion

Limitations vs Future Improvements iki kolonlu sade tablo.

---

## Slide 33 - Future Work

### On-Slide Content

```text
Future improvements:

- scan profiles
- advanced response diffing
- workflow/state transition tests
- IDOR enumeration strategies
- OAuth2 client credentials
- CI/CD security gates
- richer OpenAPI analysis
```

### Speaker Notes

Bu projeye ileride eklenebilecek en mantikli gelistirmelerden biri scan profiles olur. Boylece quick, full, non-destructive veya destructive gibi farkli scan modlari tanimlanabilir.

Advanced response diffing ile owner response ve attacker response arasindaki farklar daha detayli analiz edilebilir.

Workflow/state transition testleri, sadece tek endpoint degil, birden fazla adimdan olusan is akisi authorization problemlerini yakalamayi saglar.

IDOR enumeration stratejileri ile sadece list endpointinden alinan ID'ler degil, known IDs, numeric range veya leaked id gibi farkli kaynaklar test edilebilir.

OAuth2 client credentials ve daha zengin OpenAPI analizi de scanner'in kurumsal API'lere uyarlanabilirligini artirir.

### Visual Suggestion

Roadmap seklinde yatay zaman cizgisi.

---

## Slide 34 - Conclusion

### On-Slide Content

```text
AuthZ Scanner turns manual authorization checks into:

- repeatable tests
- configurable scan logic
- reusable API security workflows
- pentest-style reports
- vulnerable vs hardened validation
```

### Speaker Notes

Bu proje sonucunda API authorization testlerini daha sistematik, tekrar calistirilabilir ve raporlanabilir hale getiren Python tabanli bir scanner gelistirildi.

Scanner yalnizca demo API'ye bagli degil; HTTP ve YAML config uzerinden calistigi icin farkli REST API'lere uyarlanabilecek sekilde tasarlandi.

Vulnerable ve hardened API lab sayesinde hem zafiyetli davranislar hem de guvenli cozumler ayni proje icinde gosterilebildi.

Sonucta proje sadece bir API demo'su degil; config-driven scanner motoru, test modulleri, evidence modeli, risk scoring, business impact, reporting, config doctor ve safety guard gibi parcalari olan bir API security automation calismasi haline geldi.

### Visual Suggestion

Final architecture summary veya repo + report + scanner pipeline'i birlestiren kapanis gorseli.
