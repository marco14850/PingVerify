from pythonping import ping
from colorama import Fore, init
import argparse
import ipaddress
import re
import multiprocessing


init(convert=None)
conf = {}
outPermit = {"JSON", "CSV", "TXT", "NA"}
ips_global = []


def parseo_argumentos():
    parser = argparse.ArgumentParser("BETA-1.0 verificación de vida de hosts por icmp")
    parser.add_argument('-v', '--verbose', help='Despliega mensajes de error e informativos',
                        action='store_true', default=False, required=False)
    parser.add_argument('-iH', '--inputHosts', help='Establece los host a escanear en una cadena de texto',
                        type=validar_hosts, default=False, required=False)
    gl_args = parser.parse_args()
    global conf
    conf = gl_args


def validar_hosts(ips):
    tempIp = ips.split(",")
    for ip in tempIp:
        validar_ip(ip)


def validar_ip(ips):
    # validamos ip
    global ips_global
    hostname_pattern = "^[a-zA-Z0-9\.-]{1,235}$"
    letter_pattern = ".*[a-zA-z].*"
    range_pattern = "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}-[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    try:
        # Se valida la Sub-Red
        if "/" in ips:
            subred = ipaddress.ip_network(ips, strict=False)
            for host in subred.hosts():
                ips_global.append(str(host))
        # Se valida rango de ip
        elif "-" in ips:
            if re.match(range_pattern, ips):
                temp_ip = ips.split("-")
                for subnets in ipaddress.summarize_address_range(ipaddress.IPv4Address(temp_ip[0]),
                                                                 ipaddress.IPv4Address(temp_ip[1])):
                    for host in subnets.hosts():
                        ips_global.append(str(host))
                ips_global.append(str(temp_ip[0]))
                ips_global.append(str(temp_ip[1]))
            # Se valida el Hostname
        elif re.match(letter_pattern, ips):
            if re.match(hostname_pattern, ips):
                ips_global.append(ips)
            else:
                print(Fore.RED + "Hostname invalido: " + ips)
        # Se valida un hostname en concreto
        else:
            ips_global.append(str(ipaddress.ip_address(ips)))
    # Errores y excepciones posibles
    except ValueError:
        print(Fore.RED + "IP o Sub-Red invalida verifica que el valor exista: " + ips)
    except:
        print(Fore.RED + "Ip, Sub-Red o Hostname no Valido : " + ips)


def imprimir_mensaje(msg, requerido=False):
    global conf
    if conf.verbose or requerido:
        print(msg)


def make_ping(ip):
    result = ping(str(ip), count=2, timeout=2)
    # Verificación en base a tiempo de respuesta promedio
    if result.rtt_avg < 2:
        print(Fore.WHITE + str(ip) + '\t' + Fore.GREEN + "[ACTIVE]")
    else:
        print(Fore.WHITE + str(ip) + '\t' + Fore.RED + "[TIMEOUT]")


if __name__ == "__main__":
    parseo_argumentos()
    process = []
    for ip in ips_global:
        process.append(multiprocessing.Process(target=make_ping, args=(ip, )))
    imprimir_mensaje("Procesos agregados a la cola")
    for p in process:
        p.start()
    for p in process:
        try:
            p.join()
        except Exception as ex:
            imprimir_mensaje("Fallo en la ejecucion \n" + str(type(ex)) + "\n" + str(ex.args))
