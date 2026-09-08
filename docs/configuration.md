# Scanner Configuration

AuthZ Scanner hedef API'ye ozel bilgileri YAML config dosyasindan okur. Scanner modulleri demo API endpointlerini koda gommez; yeni bir API icin yeni bir config dosyasi hazirlanir.

## Top-Level Alanlar

```yaml
target:
  name: vulnerable
  base_url: http://127.0.0.1:8001

auth:
  login_path: /auth/login
  token_field: access_token

profile:
  path: /users/me
  id_field: id

identities: {}
bola:
  tests: []
bfla:
  tests: []
property_auth:
  tests: []
```

| Alan | Aciklama |
|---|---|
| `target` | Taranacak API'nin adi ve base URL bilgisi. |
| `auth` | Scanner'in test kimlikleriyle login olmak icin kullanacagi endpoint ve token alan adi. |
| `profile` | Login olan kimligin subject/user id bilgisini almak icin kullanilan endpoint. |
| `identities` | Scanner'in kullanacagi test kullanicilari. |
| `bola` | Object-level authorization testleri. |
| `bfla` | Function-level authorization testleri. |
| `property_auth` | Field/property-level authorization testleri. |

## Target

```yaml
target:
  name: external-api
  base_url: https://api.example.test
```

`name`, rapor dosyalarinda ve terminal ciktisinda kullanilir. `base_url`, scanner'in tum requestleri icin temel adrestir.

## Auth

```yaml
auth:
  login_path: /session
  token_field: token
  login_method: POST
  token_path: data.access.token
  auth_header_name: Authorization
  auth_scheme: Bearer
  login_body:
    username: "{email}"
    password: "{password}"
```

Scanner her identity icin `login_path` endpointine login istegi gonderir. Varsayilan davranis eski haliyle uyumludur: `POST` istegiyle `email` ve `password` gonderilir, cevap JSON icinde `token_field` alanindan bearer token okunur.

Basit login request varsayilani:

```json
{
  "email": "user@example.test",
  "password": "secret"
}
```

Gercek API farkli body veya token formati kullaniyorsa `login_body` ve `token_path` kullanilabilir:

```yaml
auth:
  login_path: /session
  token_field: access_token
  token_path: data.tokens.access
  login_body:
    username: "{email}"
    secret: "{password}"
    tenant: "{tenant}"

identities:
  owner:
    email: owner@example.test
    password: owner-secret
    role: user
    auth_values:
      tenant: tenant-a
```

`token_path`, nested JSON icinden token okumak icindir. Ornegin `data.tokens.access` su response icinden `abc123` degerini okur:

```json
{
  "data": {
    "tokens": {
      "access": "abc123"
    }
  }
}
```

Farkli header yapilari icin:

```yaml
auth:
  auth_header_name: X-API-Key
  auth_scheme: ""
```

Bu durumda scanner `X-API-Key: <token>` header'i gonderir. `auth_scheme: Bearer` kullanilirsa `Authorization: Bearer <token>` formati uretilir.

## Profile

```yaml
profile:
  path: /me
  id_field: subject_id
```

Scanner BOLA ve property authorization testlerinde login olan kullanicinin kaynak sahipligi iliskisini anlamak icin profil endpointinden subject id okur.

## Identities

```yaml
identities:
  owner:
    email: owner@example.test
    password: owner-secret
    role: user
    access_token: static-token-if-login-is-not-needed
  attacker:
    email: attacker@example.test
    password: attacker-secret
    role: user
  admin:
    email: admin@example.test
    password: admin-secret
    role: admin
```

Identity anahtar isimleri serbesttir. Scanner sabit olarak `userA` veya `admin1` beklemez. Test modulleri role alanina gore uygun identity secer.

`access_token` verilirse scanner o identity icin login endpointini cagirmadan dogrudan bu token'i kullanir. Bu, disaridan alinmis tokenlarla veya API key tabanli testlerde kullanislidir.

## BOLA Tests

```yaml
bola:
  tests:
    - name: users_cannot_read_each_others_resources
      role: user
      owner_field: owner_id
      resource:
        list_method: GET
        list_path: /resources
        id_field: id
      attack:
        method: GET
        path_template: /resources/{id}
      expected_status: 403
      business_impact: Unauthorized access may expose another customer's resource data.
```

BOLA testinde scanner ayni role sahip iki identity secer. Ilk identity ile resource listesi alinir, `owner_field` degeri profil id ile eslesen kaynak bulunur. Sonra ikinci identity ayni kaynaga erismeyi dener.

`business_impact`, bulgu uretilirse rapora yazilacak is etkisini tanimlar. Bu alan opsiyoneldir. Verilmezse scanner zafiyet sinifina gore genel bir fallback impact kullanir.

`path_template` icinde `{id}` kaynak id ile doldurulur. Ek path parametreleri icin `path_params` kullanilabilir:

```yaml
attack:
  method: GET
  path_template: /resources/{id}/children/{child_id}
  path_params:
    child_id: children.0.id
```

## BFLA Tests

Resource'a bagli privileged action:

```yaml
bfla:
  tests:
    - name: users_cannot_approve_resources
      role: user
      resource:
        list_method: GET
        list_path: /resources
        id_field: id
        owner_field: owner_id
      attack:
        method: POST
        path_template: /resources/{id}/approve
      expected_status: 403
      business_impact: Unauthorized approval may bypass operational review workflows.
```

Dogudan fonksiyon testi:

```yaml
bfla:
  tests:
    - name: users_cannot_list_admin_users
      role: user
      attack:
        method: GET
        path_template: /admin/users
      expected_status: 403
      business_impact: Unauthorized admin access may expose user inventory and account metadata.
```

BFLA testlerinde scanner verilen role sahip bir identity ile normalde yetkili role ait olmasi gereken fonksiyonu cagirmayi dener.

## Property Authorization Tests

### Excessive Data Exposure

```yaml
property_auth:
  tests:
    - name: profile_must_not_expose_sensitive_fields
      type: excessive_data_exposure
      role: user
      request:
        method: GET
        path_template: /me
      forbidden_fields:
        - password_hash
        - api_key
        - refresh_token
      business_impact: Sensitive fields may leak into clients, logs, or third-party monitoring systems.
```

Scanner response body icinde yasakli alan adlarini recursive olarak arar. Alan bulunursa finding uretir; raporda degerler `[REDACTED]` olarak maskelenir.

### Mass Assignment

```yaml
property_auth:
  tests:
    - name: create_resource_must_not_accept_server_controlled_fields
      type: mass_assignment
      role: user
      request:
        method: POST
        path_template: /resources
      payloads:
        - name: force_approved_state
          json_body:
            state: approved
          forbidden_effects:
            state: approved
          business_impact: Users may force a trusted state without the required approval process.
```

Scanner payload icindeki server-controlled alanlari gonderir. Response veya verification response icinde `forbidden_effects` degerleri gorulurse finding uretir.

Mass assignment testlerinde `business_impact` test seviyesinde veya payload seviyesinde verilebilir. Payload seviyesindeki impact daha spesifiktir ve raporda onu kullanir.

Kaynak id gerektiren update endpointleri icin `resource` tanimlanabilir:

```yaml
property_auth:
  tests:
    - name: update_resource_must_not_accept_server_controlled_fields
      type: mass_assignment
      role: user
      resource:
        list_method: GET
        list_path: /resources
        id_field: id
        owner_field: owner_id
      request:
        method: PUT
        path_template: /resources/{id}
      payloads:
        - name: force_approved_state
          json_body:
            state: approved
          forbidden_effects:
            state: approved
```

Bu durumda scanner once `resource.list_path` endpointinden test kimligine ait bir kaynak secer, sonra `{id}` alanini bu kaynagin `id_field` degeriyle doldurur.

### Privilege Escalation

```yaml
property_auth:
  tests:
    - name: users_cannot_promote_themselves
      type: privilege_escalation
      role: user
      request:
        method: PUT
        path_template: /users/{subject_id}
      payloads:
        - name: promote_to_admin
          json_body:
            role: admin
          verification:
            method: GET
            path_template: /me
          forbidden_effects:
            role: admin
          business_impact: A regular user may gain administrative access.
```

`{subject_id}`, profil endpointinden okunan id ile doldurulur. Verification request varsa scanner asil payload'dan sonra bu endpointi cagirir ve etkinin gercekten olusup olusmadigini kontrol eder.

## Yeni API'ye Uyarlama Akisi

1. API'nin login endpointini ve token response alanini belirle.
2. Profil endpointinden kullanici id alanini belirle.
3. En az iki ayni role sahip identity ve gerekiyorsa bir privileged identity hazirla.
4. BOLA icin ownership iceren resource list endpointlerini sec.
5. BFLA icin dusuk yetkili kullanicinin erismemesi gereken fonksiyonlari sec.
6. Property authorization icin hassas response alanlarini ve server-controlled payload alanlarini tanimla.
7. Her kritik test veya payload icin endpoint'e ozel business impact metni yaz.
8. Scanner'i once tek hedefe, sonra varsa hardened/staging hedefe karsi calistir.

## Config Doctor

Scan baslatmadan once config dosyasini dogrulamak icin:

```bash
python -m scanner.main config doctor --config config/vulnerable.yaml
```

Bu komut YAML yapisini, zorunlu alanlari, identity-role eslesmelerini,
path placeholder'larini, `review_required` isaretlerini, auth/profile
ayarlarini ve BOLA/BFLA resource list endpointlerinin temel response seklini
kontrol eder. Attack endpointleri cagrilmaz; doctor komutu mutation yapan
testleri calistirmadan once guvenli bir on kontrol saglar.

Sadece statik config kontrolu yapmak icin:

```bash
python -m scanner.main config doctor --config config/vulnerable.yaml --offline
```

Eski flag bicimi de desteklenir:

```bash
python -m scanner.main --config config/vulnerable.yaml --doctor
```

## OpenAPI'den Starter Config Uretme

Yeni bir API'de tum YAML dosyasini sifirdan yazmak yerine OpenAPI dokumanindan ilk taslak config uretilebilir:

```bash
python -m scanner.discovery.openapi \
  --openapi http://127.0.0.1:8001/openapi.json \
  --base-url http://127.0.0.1:8001 \
  --output config/generated-from-openapi.yaml \
  --compare-with config/vulnerable.yaml
```

`--openapi`, lokal bir JSON dosyasi veya HTTP URL olabilir.

`--output`, uretilecek YAML dosyasidir.

`--compare-with`, opsiyoneldir. Mevcut manuel config ile OpenAPI'den uretilen config'i method/path bazinda karsilastirir.

Uretilen config bilincli olarak final config degildir. Her otomatik aday su alanlarla gelir:

```yaml
review_required: true
review_notes:
  - Generated from OpenAPI path GET /orders/{order_id}.
  - Confirm owner_field and resource.id_field against the real response body.
```

Bu yaklasim su nedenle kullanilir:

- OpenAPI endpointleri ve request/response semalarini gosterir.
- Fakat hangi kullanici hangi kaynaga erisebilir sorusu is kuralidir.
- Business impact de API'nin gercek baglamina baglidir.

Bu yuzden generator hizli bir baslangic dosyasi verir; pentester `TODO_*`, `review_required` ve `review_notes` alanlarini kontrol ederek dosyayi calistirilabilir hale getirir.

### Starter Config Review Checklist

OpenAPI'den uretilen config baska bir API'ye uyarlanirken su kontroller yapilmalidir:

1. `identities` alanindaki placeholder hesaplari yetkili test hesaplariyla degistir.

   Scanner authorization davranisini karsilastirmak icin birden fazla kimlige ihtiyac duyar. En az iki ayni role sahip hesap ve gerekiyorsa bir privileged hesap tanimlanmalidir.

2. `auth.login_path` ve `auth.token_field` alanlarini dogrula.

   OpenAPI login endpointini ve token alanini tahmin edebilir, fakat gercek response yapisi `access_token`, `token`, `data.token` veya baska bir formatta olabilir.

3. `profile.path` ve `profile.id_field` alanlarini dogrula.

   BOLA ve privilege escalation testleri login olan kullanicinin subject id bilgisini kullanir. Bu id alaninin response body icindeki gercek alanla eslesmesi gerekir.

4. BOLA testlerindeki `owner_field` degerlerini gercek response body'ye gore kontrol et.

   Ownership alani her API'de ayni degildir. `owner_id`, `user_id`, `customer_id`, `account_id`, `tenant_id` veya domain'e ozel baska bir alan olabilir.

5. Resource `id_field` degerlerini dogrula.

   Scanner saldiri endpointine yerlestirecegi kaynak id'sini list response icinden okur. Bu alan `id`, `uuid`, `resource_id` veya API'ye ozel baska bir alan olabilir.

6. Non-GET endpointlerde gerekli `json_body` alanlarini tamamla.

   OpenAPI endpointi ve riskli alanlari gosterebilir, fakat calisabilir bir PUT/PATCH/POST istegi icin gerekli tum alanlari her zaman guvenli sekilde tamamlayamaz.

7. Mass assignment payloadlarini hedef API'nin kabul edecegi valid body formatina getir.

   Generator riskli alanlari aday olarak secer. Pentester bu alanlari endpointin normal request formatiyla birlestirerek gercekci payloadlar hazirlamalidir.

8. Business impact metinlerini uygulamanin gercek is baglamina gore ozellestir.

   Otomatik impact metinleri baslangic icindir. Kaliteli pentest raporunda finansal kayip, veri gizliligi, operasyonel etki veya yetki genislemesi gibi API'ye ozel etkiler yazilmalidir.

9. Ekstra generated adaylari tutup tutmayacagina karar ver.

   OpenAPI generator bazen manuel config'te olmayan ama test edilmeye deger endpointler onerebilir. Bunlar silinmeden once gercek risk acisindan incelenmelidir.

10. Manuel inceleme bitene kadar `review_required: true` alanini koru.

    Test dogrulandiktan sonra bu alan `false` yapilabilir veya inceleme izi olarak config icinde birakilabilir.

Demo vulnerable API icin uretilen ornek dosya:

```text
config/generated-from-openapi.yaml
```

## Notlar

- Scanner JWT decode etmez; token'i yalnizca bearer token olarak kullanir.
- Authorization kurallari is kuralina bagli oldugu icin tamamen otomatik belirlenmez.
- Business impact de is baglamina baglidir. Scanner genel fallback metinler uretir, fakat kaliteli pentest raporu icin config'te API'ye ozel impact yazilmalidir.
- Config icindeki demo endpointler degistirilebilir; scanner modulleri demo API'ye dogrudan bagimli degildir.
