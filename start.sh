#!/bin/bash

# Network Scanner Launch Script

echo "🌐 Network Scanner Launcher"
echo "=========================="

# Preveri ali je Docker nameščen
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    echo "✅ Docker je nameščen"
    
    read -p "Želite zagnati z Docker-jem? (y/n) [PRIPOROČENO]: " docker_choice
    
    if [[ $docker_choice == "y" || $docker_choice == "Y" || $docker_choice == "" ]]; then
        echo "🐳 Zaganjam z Docker-jem..."
        echo "📱 Odprite http://localhost:5000 v brskalniku"
        docker-compose up --build
        exit 0
    fi
fi

# Lokalna namestitev
echo "🔧 Zaganjam lokalno..."

# Preveri ali je Python nameščen
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 ni nameščen!"
    exit 1
fi

# Preveri ali je nmap nameščen
if ! command -v nmap &> /dev/null; then
    echo "❌ Nmap ni nameščen!"
    echo "Namestite ga z: sudo apt-get install nmap"
    exit 1
fi

# Preveri ali obstaja virtualno okolje
if [ ! -d "venv" ]; then
    echo "📦 Ustvarjam virtualno okolje..."
    python3 -m venv venv
fi

# Aktiviraj virtualno okolje
echo "🔄 Aktiviram virtualno okolje..."
source venv/bin/activate

# Namesti odvisnosti če še niso
if ! python -c "import flask" 2>/dev/null; then
    echo "📥 Nameščam odvisnosti..."
    pip install -r requirements.txt
fi

# Počisti stare cache datoteke če so direktoriji
if [ -d "devices.json" ]; then
    echo "🧹 Čistim stare cache datoteke..."
    rm -rf devices.json
fi
if [ -d "config.json" ]; then
    rm -rf config.json
fi

# Preveri ali uporabnik ima sudo pravice
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  OPOZORILO: Za najboljše rezultate (OS detekcija) zaženite kot root:"
    echo "   sudo $0"
    echo ""
    read -p "Želite nadaljevati brez sudo pravic? (y/n): " continue_choice
    if [[ $continue_choice != "y" && $continue_choice != "Y" ]]; then
        echo "Prekinjam..."
        exit 0
    fi
fi

# Zaženi aplikacijo
echo "🚀 Zaganjam Network Scanner..."
echo "📱 Odprite http://localhost:5000 v brskalniku"
echo "🔄 Za zaustavitev pritisnite CTRL+C"
echo ""
python app.py
