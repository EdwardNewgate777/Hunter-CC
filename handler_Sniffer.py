import subprocess
from threading import Thread


class Handler_Sniff(Thread):
    def __init__(self, sandbox, pwd='', user='', snapshot='Ready'):
        Thread.__init__(self)
        self.vm = "Ubuntu"
        self.user = user
        self.pwd = pwd
        self.name_sniff = 'sniff.py'
        self.target = sandbox.get_ip()
        self.sandbox = sandbox
        self.name_snapshot = snapshot
        self.directory ='/home/edward/'

    def debug(self, str):
        print("------------------------------------------------------------------------------------------")
        print(str)
        print("------------------------------------------------------------------------------------------")

    def execute(self, cmd):
        response = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, err = response.communicate()
        result = (stdout + err).decode('utf-8')
        #self.debug(result)
        return result

    def start_vm(self, headless=False):
        options = ''

        if headless:
            options = " --type headless"

        cmd = 'vboxmanage startvm {}'.format(self.vm + options)
        #self.debug(cmd)
        self.execute(cmd)

    def shutdown_vm(self):
        options = ' poweroff'
        cmd = 'vboxmanage controlvm {}'.format(self.vm + options)
        #self.debug(cmd)
        self.execute(cmd)

    def run(self):
        cmd = 'VBoxManage guestcontrol {} run --username "{}" --password "{}" --exe "/usr/bin/python3" -- - "{}{}" "{}"'.format(self.vm, self.user, self.pwd, self.directory, self.name_sniff, self.target)

        result = self.execute(cmd)
        print("TROUVER !!!!\n")
        print("L'adresse du C&C est : {}".format(result))
        print("FIN")
        self.shutdown_vm()
        self.vm_restore()
        self.sandbox.shutdown_vm()
        self.sandbox.restore()

        exit()

    # BUG
    def rmfile(self):
        cmd="VBoxManage guestcontrol {} --username {} --password {} rm {}{}".format(self.vm, self.user, self.pwd, self.directory, self.name_sniff)
        #self.debug(cmd)
        self.execute(cmd)

    def copyTo(self):
        cmd = 'VBoxManage guestcontrol {} copyto "{}" --target-directory "{}" --username "{}" --password "{}" '.format(self.vm, self.name_sniff, self.directory, self.user, self.pwd)
        #self.debug(cmd)
        self.execute(cmd)

    def vm_restore(self):
        cmd = 'VBoxManage snapshot {} restore {}'.format(self.vm, self.name_snapshot)
        self.execute(cmd)

