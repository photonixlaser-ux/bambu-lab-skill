#!/usr/bin/env python3
"""
Minimaler MQTT-Client für Bambu Lab ohne externe Abhängigkeiten
Nutzung von reinem Python socket + ssl
"""

import socket
import ssl
import json
import struct
import sys
import time
from datetime import datetime

# Konfiguration
HOST = "192.168.30.103"
PORT = 8883
SERIAL = "03919A3A2200009"
ACCESS_CODE = "33576961"
MODEL = "A1"

class SimpleMQTT:
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.sock = None
        self.ssl_sock = None
        self.connected = False
        self.last_message = None
        
    def connect(self, timeout=5):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            self.ssl_sock = context.wrap_socket(self.sock, server_hostname=self.host)
            self.ssl_sock.connect((self.host, self.port))
            
            # MQTT CONNECT Packet
            self._send_connect()
            
            # Warte auf CONNACK
            response = self.ssl_sock.recv(4)
            if len(response) >= 4 and response[3] == 0:
                self.connected = True
                return True
            return False
        except Exception as e:
            print(f"Verbindungsfehler: {e}")
            return False
    
    def _send_connect(self):
        # MQTT CONNECT Packet
        protocol_name = b'\x00\x04MQTT'
        protocol_level = b'\x04'  # MQTT v3.1.1
        
        # Connect flags: username, password, clean session
        flags = 0xC2  # username(1) + password(1) + clean(1)
        
        keep_alive = struct.pack('!H', 60)
        
        # Client ID (use serial as client id)
        client_id = self.username.encode()
        client_id_len = struct.pack('!H', len(client_id))
        
        # Username
        username = self.username.encode()
        username_len = struct.pack('!H', len(username))
        
        # Password
        password = self.password.encode()
        password_len = struct.pack('!H', len(password))
        
        # Payload
        payload = client_id_len + client_id + username_len + username + password_len + password
        
        # Variable header
        var_header = protocol_name + protocol_level + bytes([flags]) + keep_alive
        
        # Fixed header
        remaining_len = len(var_header) + len(payload)
        fixed_header = bytes([0x10, remaining_len])
        
        packet = fixed_header + var_header + payload
        self.ssl_sock.send(packet)
    
    def subscribe(self, topic):
        if not self.connected:
            return False
        
        topic_bytes = topic.encode()
        topic_len = struct.pack('!H', len(topic_bytes))
        
        # Packet ID
        packet_id = struct.pack('!H', 1)
        
        # QoS 0
        payload = topic_len + topic_bytes + bytes([0])
        
        remaining_len = len(packet_id) + len(payload)
        fixed_header = bytes([0x82, remaining_len])
        
        packet = fixed_header + packet_id + payload
        self.ssl_sock.send(packet)
        return True
    
    def read_message(self, timeout=3):
        if not self.connected:
            return None
        
        self.ssl_sock.settimeout(timeout)
        try:
            # Read fixed header
            header = self.ssl_sock.recv(1)
            if not header:
                return None
            
            packet_type = header[0] >> 4
            
            # Read remaining length
            remaining_len = 0
            multiplier = 1
            while True:
                byte = self.ssl_sock.recv(1)
                if not byte:
                    return None
                value = byte[0]
                remaining_len += (value & 127) * multiplier
                multiplier *= 128
                if (value & 128) == 0:
                    break
            
            # Read payload
            if remaining_len > 0:
                payload = b''
                while len(payload) < remaining_len:
                    chunk = self.ssl_sock.recv(remaining_len - len(payload))
                    if not chunk:
                        break
                    payload += chunk
                
                # PUBLISH packet (type 3)
                if packet_type == 3:
                    # Parse topic
                    topic_len = struct.unpack('!H', payload[:2])[0]
                    topic = payload[2:2+topic_len].decode()
                    message = payload[2+topic_len:]
                    return topic, message
                    
        except socket.timeout:
            return None
        except Exception as e:
            return None
        
        return None
    
    def disconnect(self):
        if self.ssl_sock:
            try:
                self.ssl_sock.send(bytes([0xE0, 0x00]))
                self.ssl_sock.close()
            except:
                pass
        self.connected = False


def get_printer_status():
    client = SimpleMQTT(HOST, PORT, SERIAL, ACCESS_CODE)
    
    if not client.connect():
        return None
    
    # Subscribe to report topic
    topic = f"device/{SERIAL}/report"
    client.subscribe(topic)
    
    # Wait for message
    result = None
    start = time.time()
    while time.time() - start < 5:
        msg = client.read_message(timeout=1)
        if msg:
            t, payload = msg
            try:
                data = json.loads(payload.decode())
                result = data
                break
            except:
                pass
    
    client.disconnect()
    return result


def print_status(data):
    if not data:
        print("❌ Keine Verbindung zum Drucker möglich")
        print("   Prüfe: Ist der Drucker im LAN-Mode?")
        return
    
    p = data.get("print", {})
    
    state = p.get("gcode_state", "UNKNOWN")
    state_icons = {
        "IDLE": "🟡 Bereit",
        "RUNNING": "🟢 Druckt",
        "PAUSE": "⏸️  Pausiert",
        "FINISH": "✅ Fertig",
        "FAILED": "❌ Fehlgeschlagen"
    }
    state_text = state_icons.get(state, state)
    
    percent = p.get("mc_percent", 0)
    remaining = p.get("mc_remaining_time", 0)
    hours = remaining // 3600
    mins = (remaining % 3600) // 60
    
    bed = p.get("bed_temper", 0)
    nozzle = p.get("nozzle_temper", 0)
    layer = p.get("layer_num", 0)
    total_layer = p.get("total_layer_num", 0)
    filename = p.get("filename", "-")
    error = p.get("print_error", 0)
    
    print("=" * 40)
    print(f"    🖨️  Bambu Lab {MODEL} Status")
    print("=" * 40)
    print(f"Status:    {state_text}")
    print(f"Datei:     {filename}")
    print(f"Fortschritt: {percent}%")
    print(f"Layer:     {layer} / {total_layer}")
    print(f"Restzeit:  {hours}h {mins}min")
    print("-" * 40)
    print("🌡️  Temperaturen:")
    print(f"   Nozzle: {nozzle}°C")
    print(f"   Bett:   {bed}°C")
    
    if error and error != 0:
        print("-" * 40)
        print(f"⚠️  Fehler-Code: {error}")
    print("=" * 40)


def main():
    print(f"Verbinde mit {MODEL} @ {HOST}...")
    status = get_printer_status()
    print_status(status)


if __name__ == "__main__":
    main()
