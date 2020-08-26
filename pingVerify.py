from pythonping import ping
from colorama import Fore, init
from datetime import datetime
import argparse
import netaddr
import re
import threading
import json
import csv as cs

init(convert=None, autoreset=True)
conf = {}
outPermit = {"json", "csv", "txt", "NA"}
ips_global = []
bitacora = {}


def parseo_argumentos():
    parser = argparse.ArgumentParser("ALFA-1.0 verificación de vida de hosts por icmp")
    parser.add_argument('-v', '--verbose', help='Despliega mensajes de error e informativos',
                        action='store_true', default=False, required=False)
    parser.add_argument('-iH', '--inputHosts', help='Establece los host a escanear en una cadena de texto',
                        type=validar_hosts, default=False, required=False)
    parser.add_argument('-oN', '--outputName', help='Establece el nombre del archivo',
                        type=str, default="Ping-" + datetime.now().strftime("%d-%b-%Y-%H.%M.%S"), required=False)
    parser.add_argument('-t', '--threats', help='Establece el numero de hilos utilizados al realizar ping',
                        type=int, default=10, required=False)
    parser.add_argument('-oF', '--outputFormat', help='Establece el formato de salida del archivo [NA, JSON, CSV, TXT]',
                        type=str, default="NA", required=False)
    gl_args = parser.parse_args()
    global conf
    conf = gl_args
    if gl_args.outputFormat not in outPermit:
        gl_args.outputFormat = "NA"
        imprimir_mensaje(Fore.LIGHTYELLOW_EX + "Formato de salida no reconocido")
    else:
        imprimir_mensaje(Fore.GREEN + "Datos obtenidos con Exito")


def validar_hosts(ips):
    tempIp = ips.split(",")
    for ip in tempIp:
        validar_ip(ip)


def validar_ip(ips):
    global ips_global
    hostname_pattern = "^[a-zA-Z0-9\.-]{1,235}$"
    letter_pattern = ".*[a-zA-z].*"
    range_pattern = "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}-[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    try:
        # Se valida la Sub-Red
        if "/" in ips:
            subret = netaddr.IPNetwork(ips)
            for host in subret:
                ips_global.append(str(host))
        # Se valida rango de ip
        elif "-" in ips:
            if re.match(range_pattern, ips):
                temp_ip = ips.split("-")
                ip_list = list(netaddr.IPRange(temp_ip[0], temp_ip[1]))
                for ip in ip_list:
                    ips_global.append(str(ip))
            # Se valida el Hostname
        elif re.match(letter_pattern, ips):
            if re.match(hostname_pattern, ips):
                ips_global.append(ips)
            else:
                print(Fore.RED + "Hostname invalido: " + ips)
        # Se valida un hostname en concreto
        else:
            ips_global.append(str(netaddr.IPAddress(ips)))
    # Errores y excepciones posibles
    except:
        print(Fore.RED + "Ip, Sub-Red o Hostname no Valido : " + ips)


def imprimir_mensaje(msg, requerido=False):
    global conf
    if conf.verbose or requerido:
        print(msg)


def make_ping(ip):
    global bitacora
    result = ping(str(ip), count=2, timeout=2)
    # Verificación en base a tiempo de respuesta promedio
    if result.rtt_avg < 2:
        bitacora[ip] = {'status': 'ACTIVE'}
        return ip, 'ACTIVE'
    else:
        bitacora[ip] = {'status': 'TIMEOUT'}
        return ip, 'TIMEOUT'


def guardar_datos():
    global bitacora
    for i in bitacora:
        if bitacora[i]['status'] == 'ACTIVE':
            print(Fore.WHITE + str(i) + '\t' + Fore.GREEN + "[ACTIVE]")
        else:
            print(Fore.WHITE + str(i) + '\t' + Fore.RED + "[TIMEOUT]")
    if conf.outputFormat.lower != "NA":
        if conf.outputFormat == "json":
            with open(conf.outputName + '.' + conf.outputFormat, 'w') as file:
                json.dump(bitacora, file, indent=4)
        elif conf.outputFormat == "csv":
            csvFile = open(conf.outputName + '.' + conf.outputFormat, 'w', newline='')
            writer = cs.writer(csvFile, delimiter=',', quoting=cs.QUOTE_ALL)
            w = {'IP', 'Status'}
            writer.writerow((w))
            for ip in bitacora:
                writer.writerow((ip, bitacora[i]['status']))
            csvFile.close()
        elif conf.outputFormat == "txt":
            txtFile = open(str(conf.outputName) + '.' + str(conf.outputFormat), 'w', newline='')
            for i in bitacora:
                txtFile.writelines(str(i) + '\t' + bitacora[i]['status']+'\n')
            txtFile.close()


if __name__ == "__main__":
    parseo_argumentos()
    threads = []
    for ip in ips_global:
        threads.append(threading.Thread(target=make_ping, args=(ip,)))
    imprimir_mensaje("Hilos de ejecución creados")
    for t in threads:
        t.start()
    for t in threads:
        try:
            t.join()
        except Exception as ex:
            imprimir_mensaje("Fallo en la ejecucion \n" + str(type(ex)) + "\n" + str(ex.args))
    guardar_datos()