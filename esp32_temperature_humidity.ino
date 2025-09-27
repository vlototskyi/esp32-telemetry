#include <WiFi.h>
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include <LittleFS.h>
#include <DHT.h>
#include "driver/rtc_io.h"
#include <time.h>

const char* ssid = "*****";
const char* password = "*****";

const char* device_id  = "esp32-dht01";
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
  if (now > 1609459200) {
    return true;
  }
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

  char payload[360];
  snprintf(payload, sizeof(payload),
           "{\"device_id\":\"%s\",\"ts\":\"%s\",\"ts_epoch\":%ld,"
           "\"temperature\":%.2f,\"humidity\":%.2f}",
           device_id, iso.c_str(), (long)epoch, t, h);

  if (client.publish("esp32/sensors/dht", payload)) {
    Serial.printf("Published: %s\n", payload);
    client.loop();
    delay(200);
  } else {
    Serial.println("Publish failed");
  }
  client.disconnect();
  delay(100);

  safe_sleep();
}

void loop() { /* unused */ }