# DNS resolver - projekt z predmetu ISA na FIT VUT
### Autor: Patrik Gáfrik (xgafri00)
### Ak. rok: 2023/2024
### Popis: program, ktorý pošle paket na DNS server, spracuje paket s odpoveďou a vo vhodnej forme ju vypíše na štandardný výstup.

<br>

Preklad programu:
<br>
Program ide preložiť príkazom `make` v adresári so zdrojovým súborom.

Spustenie Programu (volitelné parametre sú v zátvorkách):
```shell
./dns [-r] [-x] [-6] -s server [-p port] adresa
```

- #### -r: Požadovaná rekurzia, inak bez rekurzie
- #### -x: Reverzný dotaz namiesto priameho
- #### -6: Dotaz typu AAAA namiesto A
- #### -s server: IP adresa alebo doménové meno serveru, kam sa má zaslať dotaz
- #### -p port: Číslo portu, na ktorý sa má poslať dotaz, default 53
- #### adresa: Dotazovaná adresa
---

Spustenie Testu:
```shell
make test
```
---
Obmedzenia implementácie:
<br>
Chýba implementácia dotazov pre reverzné záznamy (PTR). Prepínač `-x` nemá vplyv na chovanie programu.