# Network Scanner

Preprosto Python orodje za skeniranje lokalnega omrežja, ki uporablja `nmap` za odkrivanje naprav in odprtih vrat.

## Namestitev

1.  **Predpogoj**: Prepričajte se, da imate na sistemu nameščen `nmap`.
    ```bash
    # Na Debian/Ubuntu
    sudo apt update && sudo apt install nmap
    ```

2.  Klonirajte repozitorij (ali preprosto ustvarite datoteke).

3.  Ustvarite in aktivirajte virtualno okolje:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

4.  Namestite potrebne Python pakete:
    ```bash
    pip install -r requirements.txt
    ```

## Uporaba

Skripto je potrebno zagnati z `sudo` pravicami za najboljše rezultate (npr. zaznavanje OS). Omrežni rang podajte kot argument.

```bash
sudo python3 scanner.py <omrezni_rang>