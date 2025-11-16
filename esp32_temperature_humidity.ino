#include <WiFi.h>
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include <LittleFS.h>
#include <DHT.h>
#include "driver/rtc_io.h"
#include <time.h>
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"

const char* ssid = "*****";
const char* password = "*****";

const char* device_id  = "esp32-dht01";
const char* key_id     = "esp32-dht01-key"; 
const char* mqtt_server = "raspberrypi.local";
const int   mqtt_port   = 8883;
const char* client_id   = device_id;

WiFiClientSecure espClient;
PubSubClient client(espClient);

#define DHTPIN   4
#define DHTTYPE  DHT11
#define DHT_PWR  25 
DHT dht(DHTPIN, DHTTYPE);

#define uS_TO_S_FACTOR 1000000ULL
#define TIME_TO_SLEEP  60

String readFile(const char* path) {
  if (!LittleFS.exists(path)) { Serial.printf("Missing %s\n", path); return ""; }
  File f = LittleFS.open(path, "r"); if (!f) { Serial.printf("Open fail %s\n", path); return ""; }
  String s = f.readString(); f.close(); return s;
}

void setup_wifi() {
  Serial.printf("Connecting to %s", ssid);
  WiFi.begin(ssid, password);
  for (int i = 0; i < 40 && WiFi.status() != WL_CONNECTED; i++) { delay(250); Serial.print("."); }
  if (WiFi.status() == WL_CONNECTED)
    Serial.printf("\nWiFi IP: %s\n", WiFi.localIP().toString().c_str());
  else
    Serial.println("\nWiFi failed");
}

void safe_sleep() {
  Serial.printf("💤 Sleep %d s\n", TIME_TO_SLEEP);
  gpio_hold_en((gpio_num_t)DHT_PWR);
  gpio_deep_sleep_hold_en();
  esp_deep_sleep((uint64_t)TIME_TO_SLEEP * uS_TO_S_FACTOR);
}

bool ensureTime(uint32_t timeout_ms = 2000) {
  time_t now = time(nullptr);
  if (now > 1609459200) return true;
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  uint32_t start = millis();
  while ((millis() - start) < timeout_ms) {
    now = time(nullptr);
    if (now > 1609459200) return true;
    delay(100);
  }
  return false;
}

String nowISO8601() {
  time_t now = time(nullptr);
  struct tm tm_utc;
  gmtime_r(&now, &tm_utc);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
  return String(buf);
}

String signPayload(const String& message, const String& keyPEM) {
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  const char *pers = "rsa_sign";
  int ret;

  ret = mbedtls_ctr_drbg_seed(
      &ctr_drbg,
      mbedtls_entropy_func,
      &entropy,
      (const unsigned char*)pers,
      strlen(pers)
  );

  if (ret != 0) {
    Serial.printf("DRBG seed failed: -0x%04X\n", -ret);
    return "";
  }

  ret = mbedtls_pk_parse_key(
      &pk,
      (const unsigned char*)keyPEM.c_str(),
      keyPEM.length() + 1,
      NULL,
      0,
      mbedtls_ctr_drbg_random,
      &ctr_drbg
  );

  if (ret != 0) {
    Serial.printf("Key parse failed: -0x%04X\n", -ret);
    return "";
  }

  unsigned char hash[32];
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);

  mbedtls_sha256_starts(&sha, 0);
  mbedtls_sha256_update(&sha,
      (const unsigned char*)message.c_str(),
      message.length());
  mbedtls_sha256_finish(&sha, hash);

  mbedtls_sha256_free(&sha);

  unsigned char sig[512];
  size_t sig_len = 0;

  ret = mbedtls_pk_sign(
      &pk,
      MBEDTLS_MD_SHA256,
      hash,
      sizeof(hash),
      sig,
      sizeof(sig),
      &sig_len,
      mbedtls_ctr_drbg_random,
      &ctr_drbg
  );

  if (ret != 0) {
    Serial.printf("Sign failed: -0x%04X\n", -ret);
    return "";
  }

  unsigned char b64[1024];
  size_t b64_len = 0;
  mbedtls_base64_encode(b64, sizeof(b64), &b64_len, sig, sig_len);

  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  return String((char*)b64);
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("Booting...");

  gpio_deep_sleep_hold_dis();
  gpio_hold_dis((gpio_num_t)DHT_PWR);

  if (!LittleFS.begin(true)) { Serial.println("LittleFS mount fail"); safe_sleep(); }

  pinMode(DHT_PWR, OUTPUT);
  digitalWrite(DHT_PWR, LOW);

  setup_wifi();

  String caCert     = readFile("/mosq_ca.crt");
  String clientCert = readFile("/mosq_client.crt");
  String clientKey  = readFile("/mosq_client.key");
  if (caCert.isEmpty() || clientCert.isEmpty() || clientKey.isEmpty()) {
    Serial.println("Missing certs");
    safe_sleep();
  }
  espClient.setCACert(caCert.c_str());
  espClient.setCertificate(clientCert.c_str());
  espClient.setPrivateKey(clientKey.c_str());
  client.setServer(mqtt_server, mqtt_port);
  client.setBufferSize(1024);
  espClient.setHandshakeTimeout(30);

  bool haveTime = ensureTime(2000);
  if (!haveTime) {
    Serial.println("NTP time not synced; using RTC/millis if available");
  }

  digitalWrite(DHT_PWR, HIGH);
  delay(3000); 
  dht.begin();
  dht.readTemperature();
  delay(1000);
  dht.readHumidity();
  delay(1000);
  float h = dht.readHumidity();
  float t = dht.readTemperature();

  digitalWrite(DHT_PWR, LOW);

  if (isnan(h) || isnan(t)) {
    Serial.println("DHT read failed");
    safe_sleep();
  }

  if (!client.connected()) {
    Serial.print("Connecting to MQTT...");
    if (!client.connect(client_id)) {
      Serial.printf("rc=%d\n", client.state());
      safe_sleep();
    }
    Serial.println("connected");
  }

  time_t epoch = time(nullptr);
  String iso = nowISO8601();

  String msg = String("{\"device_id\":\"") + device_id +
               "\",\"ts\":\"" + iso + "\",\"ts_epoch\":" + String((long)epoch) +
               ",\"temperature\":" + String(t, 2) +
               ",\"humidity\":" + String(h, 2) + "}";


  String signature = signPayload(msg, clientKey);
  if (signature == "") {
    Serial.println("Signing failed");
    safe_sleep();
  }

  String fullPayload = String("{\"device_id\":\"") + device_id + 
                       "\",\"ts\":\"" + iso + "\",\"ts_epoch\":" + String((long)epoch) +
                       ",\"temperature\":" + String(t, 2) +
                       ",\"humidity\":" + String(h, 2) +
                       ",\"sig\":\"" + signature + "\"" +
                       ",\"key_id\":\"" + key_id + "\"}";

  if (client.publish("esp32/sensors/dht", fullPayload.c_str())) {
    Serial.printf("Published: %s\n", fullPayload.c_str());
  } else {
    Serial.println("Publish failed");
  }

  client.disconnect();
  delay(200);
  safe_sleep();
}

void loop() {}