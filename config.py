import subprocess


class Configuration():
    def __init__(self, name_sandbox='Windows', name_sniffer='Ubuntu', ip_range='10.0.2.0', name_network='Zone' ):
        self.name_sandbox = name_sandbox
        self.name_sniffer = name_sniffer
        self.name_network = name_network
        self.ip_range = ip_range

    def execute(self, cmd):
        response = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, err = response.communicate()
        result = (stdout + err).decode('utf-8', errors='ignore')

        return result

    def create_network(self):
        cmd = 'VBoxManage natnetwork add --netname {} --network {}/24'.format(self.name_network, self.ip_range)
        self.execute(cmd)

    def add_vms_in_net(self):
        VMs = [self.name_sniffer, self.name_sandbox]

        for vm in VMs:
            cmd = 'vboxmanage modifyvm "{}" --nic1 natnetwork --nicpromisc1 allow-vms'.format(vm)
            self.execute(cmd)
            cmd = 'vboxmanage modifyvm "{}" --nat-network1 {}'.format(vm, self.name_network)
            self.execute(cmd)
