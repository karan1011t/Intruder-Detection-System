#include <Arduino.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <LittleFS.h>
#include <ArduinoJson.h>

// 1. PIN & CONFIG CONSTANTS
#define PIR_PIN 13
#define TRIG_PIN 5
#define ECHO_PIN 18
#define BUZZER_PIN 25
#define STATUS_LED 26
#define ALERT_LED 27

const char* AP_SSID = "IntruderSystem";
const char* AP_PASS = "12345678";

const int DISTANCE_THRESHOLD_CM = 100;
const unsigned long ALARM_DURATION_MS = 10000;
const unsigned long PIR_DEBOUNCE_MS = 2000;
const unsigned long ULTRASONIC_INTERVAL_MS = 500;
const int MAX_LOG_ENTRIES = 500;
const char* LOG_FILE = "/logs.csv";

// 2. STATE STRUCT
struct SystemState {
    bool motion = false;
    long distance = 999;
    bool systemEnabled = true;
    bool pirEnabled = true;
    bool ultrasonicEnabled = true;
    bool alarmEnabled = true;
    bool buzzerEnabled = true;
    String threat = "NONE";
    unsigned long uptime = 0;
    int eventCount = 0;
    unsigned long lastIntrusionTs = 0;
} state;

// GLOBALS
AsyncWebServer server(80);
bool fsMounted = false;
int logCount = 0;

unsigned long lastPirTime = 0;
unsigned long lastUltrasonicTime = 0;
unsigned long alarmTriggerTime = 0;
bool alarmActive = false;
String lastThreat = "NONE";

long usReadings[3] = {999, 999, 999};
int usIndex = 0;

bool restartPending = false;
unsigned long restartTriggerTime = 0;

// 6. LOGGING MODULE
void trimLogs() {
    if (!LittleFS.exists(LOG_FILE)) return;
    File oldFile = LittleFS.open(LOG_FILE, "r");
    File newFile = LittleFS.open("/logs.tmp", "w");
    if (oldFile && newFile) {
        // Copy header
        if (oldFile.available()) {
            newFile.println(oldFile.readStringUntil('\n'));
        }
        // Skip oldest data line
        if (oldFile.available()) {
            oldFile.readStringUntil('\n');
        }
        // Copy the rest
        while (oldFile.available()) {
            newFile.println(oldFile.readStringUntil('\n'));
        }
        oldFile.close();
        newFile.close();
        LittleFS.remove(LOG_FILE);
        LittleFS.rename("/logs.tmp", LOG_FILE);
        logCount--;
    }
}

void logEvent(const char* eventType, const char* value) {
    if (!fsMounted) return;
    
    bool isNewFile = false;
    if (!LittleFS.exists(LOG_FILE)) {
        isNewFile = true;
    } else {
        File info = LittleFS.open(LOG_FILE, "r");
        if (info && info.size() == 0) isNewFile = true;
        if (info) info.close();
    }
    
    File f = LittleFS.open(LOG_FILE, FILE_APPEND);
    if (!f) return;
    
    // Requirements #3: Save headers only once
    if (isNewFile) {
        f.println("Event_ID,Date_Time,Zone,PIR_Status,Ultrasonic_Distance_cm,Threat_Type,Threat_Level,Risk_Score,Alarm_Status,Alert_Status,Response_Time_sec,System_Health,Device_ID,Insight,Operator_Action,Network_Status");
    }
    
    // Requirements #4: Generate Event_ID automatically
    int eventId = state.eventCount + 1;
    
    // Calculate Risk Score
    int riskScore = 0;
    if (state.threat == "HIGH") riskScore = 90;
    else if (state.threat == "LOW") riskScore = 30;
    
    // Requirements #5: Create an Insight field based on sensor values and threat level
    String insight = "Normal Operations";
    if (strcmp(eventType, "THREAT_DETECTED") == 0) {
         if (state.threat == "HIGH") insight = "Critical: Multi-sensor breach confirmed";
         else if (state.threat == "LOW") insight = "Warning: Perimeter activity detected";
    } else if (strcmp(eventType, "ALARM_TRIGGERED") == 0) {
         insight = "Action Required: Alarm activated";
    } else if (strcmp(eventType, "ALARM_STOPPED") == 0) {
         insight = "System Reset: Alarm suppressed";
    } else {
         insight = value; // Fallback to provided value
    }
    
    time_t now;
    time(&now);
    struct tm timeinfo;
    localtime_r(&now, &timeinfo);
    
    char timeStr[32];
    if (timeinfo.tm_year < 120) {
        snprintf(timeStr, sizeof(timeStr), "%lu", millis() / 1000);
    } else {
        // ddmmyy and time hours minns seconds
        strftime(timeStr, sizeof(timeStr), "%d/%m/%y %H:%M:%S", &timeinfo);
    }

    char logLine[384];
    snprintf(logLine, sizeof(logLine), 
        "%d,%s,%s,%d,%ld,%s,%s,%d,%d,%d,%lu,%s,%s,%s,%s,%s\n",
        eventId,                                // Event_ID
        timeStr,                                // Date_Time
        "Zone-Alpha",                           // Zone
        state.motion ? 1 : 0,                   // PIR_Status
        state.distance,                         // Ultrasonic_Distance_cm
        "Ground",                               // Threat_Type
        state.threat.c_str(),                   // Threat_Level
        riskScore,                              // Risk_Score
        alarmActive ? 1 : 0,                    // Alarm_Status
        (state.threat != "NONE") ? 1 : 0,       // Alert_Status
        alarmActive ? ((millis() - alarmTriggerTime) / 1000) : 0, // Response_Time_sec
        ESP.getFreeHeap() > 20000 ? "NOMINAL" : "DEGRADED", // System_Health
        "GARUDA-01",                            // Device_ID
        insight.c_str(),                        // Insight
        eventType,                              // Operator_Action (using eventType as proxy)
        "ONLINE_AP"                             // Network_Status
    );
    
    f.print(logLine);
    f.close();
    
    logCount++;
    state.eventCount++;
    
    if (logCount > MAX_LOG_ENTRIES) {
        trimLogs();
    }
}

void countInitialLogs() {
    if (!LittleFS.exists(LOG_FILE)) return;
    File f = LittleFS.open(LOG_FILE, "r");
    if (f.available()) {
        f.readStringUntil('\n'); // skip header
    }
    while (f.available()) {
        f.readStringUntil('\n');
        logCount++;
    }
    f.close();
}

// SETUP
void setup() {
    Serial.begin(115200);
    delay(10);

    pinMode(PIR_PIN, INPUT);
    pinMode(TRIG_PIN, OUTPUT);
    pinMode(ECHO_PIN, INPUT);
    pinMode(BUZZER_PIN, OUTPUT);
    pinMode(STATUS_LED, OUTPUT);
    pinMode(ALERT_LED, OUTPUT);

    digitalWrite(TRIG_PIN, LOW);
    digitalWrite(BUZZER_PIN, LOW);
    digitalWrite(ALERT_LED, LOW);
    
    fsMounted = LittleFS.begin(true); // formatOnFail = true
    if (!fsMounted) {
        Serial.println("ERROR: LittleFS mount failed! Continuing in degraded mode.");
    } else {
        countInitialLogs();
    }

    WiFi.softAP(AP_SSID, AP_PASS);
    Serial.print("AP IP Address: ");
    Serial.println(WiFi.softAPIP());

    // 7. REST API HANDLERS
    server.on("/status", HTTP_GET, [](AsyncWebServerRequest *request){
        JsonDocument doc;
        doc["motion"] = state.motion;
        doc["distance"] = state.distance;
        doc["alarm"] = alarmActive;
        doc["system"] = state.systemEnabled;
        doc["pirEnabled"] = state.pirEnabled;
        doc["ultrasonicEnabled"] = state.ultrasonicEnabled;
        doc["alarmEnabled"] = state.alarmEnabled;
        doc["buzzerEnabled"] = state.buzzerEnabled;
        doc["threat"] = state.threat;
        doc["uptime"] = millis() / 1000;
        doc["eventCount"] = state.eventCount;
        doc["lastIntrusionTs"] = state.lastIntrusionTs;
        
        String buf;
        serializeJson(doc, buf);
        request->send(200, "application/json", buf);
    });

    server.on("/control", HTTP_POST, [](AsyncWebServerRequest *request){}, NULL, [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total){
        JsonDocument doc;
        DeserializationError err = deserializeJson(doc, (const char*)data, len);
        if (!err) {
            String resBuf;
            JsonDocument resDoc;
            resDoc["status"] = "ok";
            serializeJson(resDoc, resBuf);
            
            if (doc["system"].is<bool>()) state.systemEnabled = doc["system"];
            if (doc["pir"].is<bool>()) state.pirEnabled = doc["pir"];
            if (doc["ultrasonic"].is<bool>()) state.ultrasonicEnabled = doc["ultrasonic"];
            if (doc["alarmEnabled"].is<bool>()) state.alarmEnabled = doc["alarmEnabled"];
            if (doc["buzzerEnabled"].is<bool>()) state.buzzerEnabled = doc["buzzerEnabled"];
            if (doc["alarm"].is<bool>()) {
                bool trigger = doc["alarm"];
                if (trigger && !alarmActive) {
                    alarmActive = true;
                    alarmTriggerTime = millis();
                } else if (!trigger) {
                    alarmActive = false;
                }
            }
            request->send(200, "application/json", resBuf);
        } else {
            request->send(400, "application/json", "{\"error\":\"Invalid JSON\"}");
        }
    });

    server.on("/logs", HTTP_GET, [](AsyncWebServerRequest *request){
        JsonDocument doc;
        JsonArray arr = doc.to<JsonArray>();

        if (fsMounted && LittleFS.exists(LOG_FILE)) {
            File f = LittleFS.open(LOG_FILE, "r");
            std::vector<String> lines;
            if (f.available()) f.readStringUntil('\n'); // skip header
            while (f.available()) {
                String line = f.readStringUntil('\n');
                if (line.length() > 0) {
                    lines.push_back(line);
                }
            }
            f.close();
            
            int startIdx = (lines.size() > 100) ? lines.size() - 100 : 0;
            for (int i = lines.size() - 1; i >= startIdx; i--) {
                // Parse new CSV structure to JSON for legacy API dashboard
                // CSV: Event_ID,Date_Time,Zone,PIR_Status,Ultrasonic_Distance,Threat_Type,Threat_Level,Risk_Score,Alarm_Status,Alert_Status,Response_Time,System_Health,Device_ID,Insight,Operator_Action,Network_Status
                int c1 = lines[i].indexOf(',');
                int c2 = lines[i].indexOf(',', c1 + 1);
                
                if (c1 > 0 && c2 > 0) {
                    JsonObject obj = arr.add<JsonObject>();
                    obj["eventId"] = lines[i].substring(0, c1).toInt();
                    obj["timestamp"] = lines[i].substring(c1 + 1, c2); // Use string now for Date_Time
                    
                    // Best effort mapping of the complex CSV fields for typical dashboard list backwards compatibility:
                    // Extract Operator Action (14th field) and Insight (13th field) roughly:
                    int lastComma = lines[i].lastIndexOf(','); // before Network_Status
                    int secondLastComma = lines[i].lastIndexOf(',', lastComma - 1); // before Operator_Action
                    int thirdLastComma = lines[i].lastIndexOf(',', secondLastComma - 1); // before Insight
                    
                    if (secondLastComma > 0 && lastComma > 0) {
                        obj["type"] = lines[i].substring(secondLastComma + 1, lastComma);
                    }
                    if (thirdLastComma > 0 && secondLastComma > 0) {
                        obj["value"] = lines[i].substring(thirdLastComma + 1, secondLastComma); // Insight
                    }
                }
            }
        }
        
        String buf;
        serializeJson(doc, buf);
        request->send(200, "application/json", buf);
    });

    server.on("/export", HTTP_GET, [](AsyncWebServerRequest *request){
        if (fsMounted && LittleFS.exists(LOG_FILE)) {
            request->send(LittleFS, LOG_FILE, "text/csv", true);
        } else {
            request->send(404, "text/plain", "Log file not found or FS offline");
        }
    });

    server.on("/clearlogs", HTTP_POST, [](AsyncWebServerRequest *request){
        if (fsMounted) {
            LittleFS.remove(LOG_FILE);
            logCount = 0;
            state.eventCount++;
            request->send(200, "application/json", "{\"status\":\"cleared\"}");
        } else {
            request->send(500, "application/json", "{\"error\":\"FS offline\"}");
        }
    });

    server.on("/restart", HTTP_POST, [](AsyncWebServerRequest *request){
        request->send(200, "application/json", "{\"status\":\"restarting\"}");
        restartPending = true;
        restartTriggerTime = millis();
    });

    server.on("/synctime", HTTP_POST, [](AsyncWebServerRequest *request){}, NULL, [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total){
        JsonDocument doc;
        DeserializationError err = deserializeJson(doc, (const char*)data, len);
        if (!err && doc["time"].is<unsigned long>()) {
            struct timeval tv;
            tv.tv_sec = doc["time"].as<unsigned long>();
            tv.tv_usec = 0;
            settimeofday(&tv, NULL);
            request->send(200, "application/json", "{\"status\":\"ok\"}");
        } else {
            request->send(400, "application/json", "{\"error\":\"invalid\"}");
        }
    });

    // 8. WEB SERVER STATIC DIRECTORY ROUTING
    if (fsMounted) {
        server.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
            request->send(LittleFS, "/index.html", "text/html");
        });
        server.serveStatic("/", LittleFS, "/");
    }

    server.onNotFound([](AsyncWebServerRequest *request) {
        if (request->method() == HTTP_OPTIONS) {
            request->send(200);
        } else {
            request->send(404, "text/plain", "Not Found");
        }
    });

    server.begin();
    Serial.printf("Free heap after server start: %u\n", ESP.getFreeHeap());
}

// MAIN LOOP
void loop() {
    unsigned long currentMillis = millis();

    if (restartPending && (currentMillis - restartTriggerTime > 500)) {
        ESP.restart();
    }

    // Status LED Pulse
    digitalWrite(STATUS_LED, state.systemEnabled ? ((currentMillis / 1000) % 2 == 0) : LOW);

    // 3. SENSOR MODULE
    state.motion = false;
    if (state.systemEnabled && state.pirEnabled) {
        if (digitalRead(PIR_PIN) == HIGH && (currentMillis - lastPirTime > PIR_DEBOUNCE_MS)) {
            state.motion = true;
            lastPirTime = currentMillis;
        }
    }

    if (currentMillis - lastUltrasonicTime > ULTRASONIC_INTERVAL_MS) {
        lastUltrasonicTime = currentMillis;
        digitalWrite(TRIG_PIN, HIGH);
        delayMicroseconds(10);
        digitalWrite(TRIG_PIN, LOW);
        
        long dur = pulseIn(ECHO_PIN, HIGH, 30000); // 30ms timeout = ~5.1m range limit (non-blocking practical cap)
        long dist = (dur == 0) ? -1 : (dur / 2) / 29.1;

        usReadings[usIndex] = dist;
        usIndex = (usIndex + 1) % 3;

        long sum = 0; 
        int valid = 0;
        for (int i = 0; i < 3; i++) {
            if (usReadings[i] > 0) { 
                sum += usReadings[i]; 
                valid++; 
            }
        }
        state.distance = (valid > 0) ? (sum / valid) : 999;
    }

    // 4. DETECTION LOGIC
    bool usActive = (state.systemEnabled && state.ultrasonicEnabled && state.distance > 0 && state.distance < DISTANCE_THRESHOLD_CM);
    if (!state.systemEnabled) {
        state.threat = "NONE";
    } else if (state.motion && usActive) {
        state.threat = "HIGH";
    } else if (state.motion) {
        state.threat = "HIGH";
    } else if (usActive) {
        state.threat = "LOW";
    } else {
        state.threat = "NONE";
    }

    if (state.threat != lastThreat) {
        if (state.threat == "HIGH" || state.threat == "LOW") {
            logEvent("THREAT_DETECTED", state.threat.c_str());
        }
        lastThreat = state.threat;
    }

    if (state.threat == "HIGH" && !alarmActive && state.alarmEnabled) {
        alarmActive = true;
        alarmTriggerTime = currentMillis;
        state.lastIntrusionTs = currentMillis / 1000;
        logEvent("ALARM_TRIGGERED", "Motion / Proximity Breach");
    }

    // 5. ALARM MODULE
    if (alarmActive) {
        if (currentMillis - alarmTriggerTime > ALARM_DURATION_MS) {
            alarmActive = false;
            digitalWrite(BUZZER_PIN, LOW);
            digitalWrite(ALERT_LED, LOW);
            logEvent("ALARM_STOPPED", "Timeout Reached");
        } else {
            bool strobe = ((currentMillis / 250) % 2 == 0);
            digitalWrite(BUZZER_PIN, (strobe && state.buzzerEnabled) ? HIGH : LOW);
            digitalWrite(ALERT_LED, strobe ? HIGH : LOW);
        }
    } else {
        digitalWrite(BUZZER_PIN, LOW);
        digitalWrite(ALERT_LED, LOW);
    }
}