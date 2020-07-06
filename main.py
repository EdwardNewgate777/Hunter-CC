import subprocess
import sys
from time import sleep

from handler_Sandbox import Handler_vm
from handler_Sniffer import Handler_Sniff
from scanner import Scanner


def check_exist(file):
    try:
        with open(file, "r"):
            return True
    except FileNotFoundError:
        return False


def check_exec(filename):
    win = 'Windows'

    result = subprocess.check_output("file {}".format(filename), shell=True).decode('utf-8')
    if result.find(win):
        return win


def main():
    scanner = Scanner()
    try:
        file = sys.argv[1]
    except IndexError:
        file = input("Veuillez saisir le chemin du fichier a analyser : ")

    if check_exist(file):
        scanner.filename = file
    else:
        print("ERREUR : Le fichier n'existe pas !")
        exit()

    print("Chargement du malware...")
    if scanner.isMalware():
        print("Menace détectée")
        os = check_exec(scanner.get_filename())

        # Démarrage des VMs
        print("Démarrage de la VM {}...".format(os))
        handler_vm = Handler_vm(os, 'ghjghvgh', 'pentester01', file)
        handler_vm.start_vm()
        sleep(30)
        print("Envoie du virus vers {}".format(os))
        handler_vm.copyTo()

        print("Démarrage de la VM d'analyse...")
        handler_sniff = Handler_Sniff(handler_vm, 'ghjghvgh', 'root')
        handler_sniff.start_vm()
        print("Début d'analyse...".format(os))
        handler_sniff.copyTo()
        sleep(5)
        handler_sniff.start()

        handler_vm.run_malware()

    else:
        print("Aucune menace détectée")

main()
