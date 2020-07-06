# coding: utf-8

import subprocess


class Handler_vm():
    def __init__(self, vm='', pwd='', user='', malware='', snapshot='Ready', verbose=False):
        self.vm = vm
        self.user = user
        self.pwd = pwd
        self.malware = malware
        self.directory = 'c:/Users/{}/Documents'.format(user)
        self.name_snapshot = snapshot
        self.verbose = verbose

    def debug(self, str):
            print("------------------------------------------------------------------------------------------")
            print(str)
            print("------------------------------------------------------------------------------------------")

    def execute(self, cmd):
        response = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, err = response.communicate()
        result = (stdout + err).decode('utf-8', errors='ignore')
        if self.verbose:
            self.debug(result)
        return result

    def start_vm(self, headless=False):
        options = ''

        if headless:
            options = " --type headless"

        cmd = 'vboxmanage startvm {}'.format(self.vm + options)
        if self.verbose:
            self.debug(cmd)
        self.execute(cmd)

    def shutdown_vm(self):
        options = ' poweroff'
        cmd = 'vboxmanage controlvm {}'.format(self.vm + options)
        if self.verbose:
            self.debug(cmd)
        self.execute(cmd)

    def copyTo(self):
        cmd = 'VBoxManage guestcontrol {} copyto "{}" --target-directory "{}" --username {} --password {}'.format(self.vm, self.malware, self.directory, self.user, self.pwd)
        if self.verbose:
            self.debug(cmd)
        self.execute(cmd)

    def get_ip(self):
        cmd = 'VBoxManage guestcontrol {} run "ipconfig.exe" --dos2unix --username {} --password {}'.format(self.vm, self.user, self.pwd)
        if self.verbose:
            self.debug(cmd)
        raw = self.execute(cmd)

        # Parse la donnée brute pour recuperer l'ip
        index_beg = raw.find('IPv4')
        index_end = raw.find('\n', index_beg)
        ip = raw[index_beg:index_end].split(':')[-1].strip()

        return ip

    def get_vm(self):
        return self.vm

    def restore(self):
        cmd = 'VBoxManage snapshot {} restore {}'.format(self.vm, self.name_snapshot)
        self.debug(cmd)
        self.execute(cmd)

    def run_malware(self):
        filename = self.malware.split('/')[-1]
        cmd = 'VBoxManage guestcontrol {} start --exe {}/{} --username {} --password {}'.format(self.vm, self.directory, filename, self.user, self.pwd)
        if self.verbose:
            self.debug(cmd)
        self.execute(cmd)


