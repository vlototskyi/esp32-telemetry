#include <WiFi.h>
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include <LittleFS.h>
#include <time.h>
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"

const char* ssid = "*****";
const char* password = "*****";

const char* device_id  = "esp32-sound01";
const char* key_id     = "esp32-sound01-key";
const char* mqtt_server = "raspberrypi.local";
const int   mqtt_port   = 8883;
const char* client_id   = device_id;

WiFiClientSecure espClient;
PubSubClient client(espClient);

#define SOUND_PIN 34
#define uS_TO_S_FACTOR 1000000ULL
#define TIME_TO_SLEEP  60

const int MEAS_WINDOW_MS = 3000;
const int SEGMENT_MS     = 50;
const int SAMPLE_US      = 200;
const int SAMPLES_PER_SEG = (SEGMENT_MS * 1000) / SAMPLE_US;

static const char* FLOOR_FILE = "/sound_floor.txt";
const float FLOOR_ALPHA = 0.05f;
const int   SPAN        = 400;

String readFile(const char* path) {
  if (!LittleFS.exists(path)) return "";
  File f = LittleFS.open(path, "r"); if (!f) return "";
  String s = f.readString(); f.close(); return s;
}
bool writeFile(const char* path, const String& data) {
  File f = LittleFS.open(path, "w"); if (!f) return false;
  f.print(data); f.close(); return true;
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

static inline int16_t readCentered() {
  return (int16_t)analogRead(SOUND_PIN) - 2048;
}

void measureWindow(int &rms_avg_out, int &rms_peak_out) {
  const uint32_t start_ms = millis();
  uint64_t total_sumSq = 0;
  uint32_t total_samples = 0;
  int rms_peak = 0;

  while ((millis() - start_ms) < (uint32_t)MEAS_WINDOW_MS) {
    uint64_t seg_sumSq = 0;
    for (int i = 0; i < SAMPLES_PER_SEG; i++) {
      int16_t v = readCentered();
      seg_sumSq += (int32_t)v * (int32_t)v;
      delayMicroseconds(SAMPLE_US);
    }
    total_sumSq   += seg_sumSq;
    total_samples += SAMPLES_PER_SEG;
    int seg_rms = (int)sqrt((double)seg_sumSq / SAMPLES_PER_SEG);
    if (seg_rms > rms_peak) rms_peak = seg_rms;
  }
  int rms_avg = (total_samples > 0)
                  ? (int)sqrt((double)total_sumSq / total_samples)
                  : 0;
  rms_avg_out  = rms_avg;
  rms_peak_out = rms_peak;
}

int loadFloor() {
  String s = readFile(FLOOR_FILE);
  if (s.length() == 0) return -1;
  return s.toInt();
}
void saveFloor(int floorRMS) { writeFile(FLOOR_FILE, String(floorRMS)); }

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
  esp_deep_sleep((uint64_t)TIME_TO_SLEEP * uS_TO_S_FACTOR);
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("Booting...");

  if (!LittleFS.begin(true)) { Serial.println("LittleFS mount fail"); safe_sleep(); }

  uint64_t pre_sumSq = 0;
  const int CAL_SAMPLES = 600;
  for (int i = 0; i < CAL_SAMPLES; i++) {
    int16_t v = readCentered();
    pre_sumSq += (int32_t)v * (int32_t)v;
    delayMicroseconds(SAMPLE_US);
  }
  int preRMS = (int)sqrt((double)pre_sumSq / CAL_SAMPLES);

  int floorRMS = loadFloor();
  if (floorRMS < 0) {
    floorRMS = preRMS;
  } else {
    if (preRMS < floorRMS)
      floorRMS = (int)((1.0f - FLOOR_ALPHA) * floorRMS + FLOOR_ALPHA * preRMS);
    else {
      float alphaUp = FLOOR_ALPHA * 0.5f;
      floorRMS = (int)((1.0f - alphaUp) * floorRMS + alphaUp * preRMS);
    }
  }
  floorRMS = constrain(floorRMS, 0, 2048);
  saveFloor(floorRMS);

  int rms_avg = 0, rms_peak = 0;
  measureWindow(rms_avg, rms_peak);

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

  ensureTime(2000);

  int delta_avg  = max(0, rms_avg  - floorRMS);
  int delta_peak = max(0, rms_peak - floorRMS);
  int percent_avg  = min(100, (delta_avg  * 100) / SPAN);
  int percent_peak = min(100, (delta_peak * 100) / SPAN);

  Serial.printf("🎤 floor=%d, rms_avg=%d, rms_peak=%d, pct_avg=%d%%, pct_peak=%d%%\n",
                floorRMS, rms_avg, rms_peak, percent_avg, percent_peak);

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
               ",\"sound_floor\":" + String(floorRMS) +
               ",\"sound_rms_avg\":" + String(rms_avg) +
               ",\"sound_rms_peak\":" + String(rms_peak) +
               ",\"sound_delta_avg\":" + String(delta_avg) +
               ",\"sound_delta_peak\":" + String(delta_peak) +
               ",\"sound_percent_avg\":" + String(percent_avg) +
               ",\"sound_percent_peak\":" + String(percent_peak) +
               ",\"win_ms\":" + String(MEAS_WINDOW_MS) +
               ",\"seg_ms\":" + String(SEGMENT_MS) + "}";

  String signature = signPayload(msg, clientKey);
  if (signature == "") {
    Serial.println("Signing failed");
    safe_sleep();
  }

  String fullPayload = String("{\"device_id\":\"") + device_id +
                       "\",\"ts\":\"" + iso + "\",\"ts_epoch\":" + String((long)epoch) +
                       ",\"sound_floor\":" + String(floorRMS) +
                       ",\"sound_rms_avg\":" + String(rms_avg) +
                       ",\"sound_rms_peak\":" + String(rms_peak) +
                       ",\"sound_delta_avg\":" + String(delta_avg) +
                       ",\"sound_delta_peak\":" + String(delta_peak) +
                       ",\"sound_percent_avg\":" + String(percent_avg) +
                       ",\"sound_percent_peak\":" + String(percent_peak) +
                       ",\"win_ms\":" + String(MEAS_WINDOW_MS) +
                       ",\"seg_ms\":" + String(SEGMENT_MS) +
                       ",\"sig\":\"" + signature + "\"" +
                       ",\"key_id\":\"" + key_id + "\"}";

  if (client.publish("esp32/sensors/sound", fullPayload.c_str())) {
    Serial.printf("Published: %s\n", fullPayload.c_str());
  } else {
    Serial.println("Publish failed");
  }

  client.disconnect();
  delay(100);
  safe_sleep();
}

void loop() { /* unused */ }