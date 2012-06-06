# -*- coding: utf-8 -*-

import os
import sys
import time
import shutil
import atexit
import subprocess
import charon.util


class MachineDefinition:
    """Base class for Charon backend machine definitions."""
    
    @classmethod
    def get_type(cls):
        assert False

    def __init__(self, xml):
        self.name = xml.get("name")
        assert self.name
        self.encrypted_links_to = set([e.get("value") for e in xml.findall("attrs/attr[@name='encryptedLinksTo']/list/string")])


class MachineState:
    """Base class for Charon backends machine states."""

    @classmethod
    def get_type(cls):
        assert False

    def __init__(self, depl, name):
        self.name = name
        self.depl = depl
        self.created = False
        self._ssh_pinged = False
        self._ssh_pinged_this_time = False
        self._ssh_master_started = False
        self._ssh_master_opts = []
        self._public_vpn_key = None
        self.index = None

        # Nix store path of the last global configuration deployed to
        # this machine.  Used to check whether this machine is up to
        # date with respect to the global configuration.
        self.cur_configs_path = None

        # Nix store path of the last machine configuration deployed to
        # this machine.
        self.cur_toplevel = None

    def log(self, msg):
        self.depl.log("[" + self.name + "] " + msg)

    def warn(self, msg):
        self.log("warning: " + msg)

    def write(self):
        self.depl.update_machine_state(self)
        
    def create(self, defn, check):
        """Create or update the machine instance defined by ‘defn’, if appropriate."""
        assert False

    def serialise(self):
        """Return a dictionary suitable for representing the on-disk state of this machine."""
        x = {'targetEnv': self.get_type()}
        if self.cur_configs_path: x['vmsPath'] = self.cur_configs_path
        if self.cur_toplevel: x['toplevel'] = self.cur_toplevel
        if self._ssh_pinged: x['sshPinged'] = self._ssh_pinged
        if self._public_vpn_key: x['publicVpnKey'] = self._public_vpn_key
        if self.index != None: x['index'] = self.index
        return x

    def deserialise(self, x):
        """Deserialise the state from the given dictionary."""
        self.cur_configs_path = x.get('vmsPath', None)
        self.cur_toplevel = x.get('toplevel', None)
        self._ssh_pinged = x.get('sshPinged', False)
        self._public_vpn_key = x.get('publicVpnKey', None)
        self.index = x.get('index', None)

    def destroy(self):
        """Destroy this machine, if possible."""
        self.warn("don't know how to destroy machine ‘{0}’".format(self.name))

    def stop(self):
        """Stop this machine, if possible."""
        self.warn("don't know how to stop machine ‘{0}’".format(self.name))
        
    def start(self):
        """Start this machine, if possible."""
        pass
        
    def get_ssh_name(self):
        assert False

    def get_ssh_flags(self):
        return []

    def get_physical_spec(self, machines):
        return []

    def show_type(self):
        return self.get_type()

    @property
    def vm_id(self):
        return None

    @property
    def public_ipv4(self):
        return None
    
    @property
    def private_ipv4(self):
        return None

    def address_to(self, m):
        """Return the IP address to be used to access machone "m" from this machine."""
        ip = m.public_ipv4
        if ip: return ip
        return None

    def wait_for_ssh(self, check=False):
        """Wait until the SSH port is open on this machine."""
        if self._ssh_pinged and (not check or self._ssh_pinged_this_time): return
        sys.stderr.write("waiting for SSH on ‘{0}’...".format(self.name))
        while True:
            res = subprocess.call(["nc", "-z", self.get_ssh_name(), "22", "-w", "1"])
            if res == 0: break
            time.sleep(1)
            sys.stderr.write(".")
        sys.stderr.write("\n")
        self._ssh_pinged = True
        self._ssh_pinged_this_time = True
        self.write()

    def _open_ssh_master(self):
        """Start an SSH master connection to speed up subsequent SSH sessions."""
        if self._ssh_master_started: return

        # Start the master.
        control_socket = self.depl.tempdir + "/ssh-master-" + self.name
        res = subprocess.call(
            ["ssh", "-x", "root@" + self.get_ssh_name(), "-S", control_socket,
             "-M", "-N", "-f"]
            + self.get_ssh_flags())
        if res != 0: 
            raise Exception("unable to start SSH master connection to ‘{0}’".format(self.name))

        # Kill the master on exit.
        atexit.register(
            lambda: 
            subprocess.call(
                ["ssh", "root@" + self.get_ssh_name(),
                 "-S", control_socket, "-O", "exit"], stderr=charon.util.devnull)
            )
        
        self._ssh_master_opts = ["-S", control_socket]
        self._ssh_master_started = True

    def run_command(self, command, check=True, capture_stdout=False, stdin_string=None):
        """Execute a command on the machine via SSH."""
        self._open_ssh_master()
        cmdline = ["ssh", "-x", "root@" + self.get_ssh_name()] + self._ssh_master_opts + self.get_ssh_flags() + [command];
        if capture_stdout:
            return subprocess.check_output(cmdline)
        else:
            stdin = None
            if stdin_string != None:
                # Ugly, should pipe it in.
                tempfile = self.depl.tempdir + "/ssh-stdin-" + self.name
                # !!! set permission
                with open(tempfile, "w+") as f:
                    f.write(stdin_string)
                stdin = open(tempfile)
            res = subprocess.call(cmdline, stdin=stdin)
            if stdin != None: stdin.close()
            if check and res != 0:
                raise Exception("command ‘{0}’ failed on machine ‘{1}’".format(command, self.name))
            return res

    def _create_key_pair(self, key_name="Charon auto-generated key"):
        key_dir = self.depl.tempdir + "/ssh-key-" + self.name
        os.mkdir(key_dir, 0700)
        res = subprocess.call(["ssh-keygen", "-t", "dsa", "-f", key_dir + "/key", "-N", '', "-C", key_name],
                              stdout=charon.util.devnull)
        if res != 0: raise Exception("unable to generate an SSH key")
        f = open(key_dir + "/key"); private = f.read(); f.close()
        f = open(key_dir + "/key.pub"); public = f.read().rstrip(); f.close()
        shutil.rmtree(key_dir)
        return (private, public)

    def copy_closure_to(self, path):
        """Copy a closure to this machine."""
        
        # !!! Implement copying between cloud machines, as in the Perl
        # version.

        env = dict(os.environ)
        env['NIX_SSHOPTS'] = ' '.join(self.get_ssh_flags());
        res = subprocess.Popen(
            ["nix-copy-closure", "--gzip", "--to", "root@" + self.get_ssh_name(), path],
            env=env).wait()
        if res != 0:
            raise Exception("unable to copy closure to machine ‘{0}’".format(self.name))

    def generate_vpn_key(self):
        if self._public_vpn_key: return
        (private, public) = self._create_key_pair(key_name="Charon VPN key of {0}".format(self.name))
        f = open(self.depl.tempdir + "/id_vpn-" + self.name, "w+")
        f.write(private)
        f.seek(0)
        # FIXME: use run_command
        res = subprocess.call(
            ["ssh", "-x", "root@" + self.get_ssh_name()]
            + self.get_ssh_flags() +
            ["umask 077 && mkdir -p /root/.ssh && cat > /root/.ssh/id_charon_vpn"],
            stdin=f)
        f.close()
        if res != 0: raise Exception("unable to upload VPN key to ‘{0}’".format(self.name))
        self._public_vpn_key = public
        self.write()


import charon.backends.none
import charon.backends.virtualbox
import charon.backends.ec2

def create_definition(xml):
    """Create a machine definition object from the given XML representation of the machine's attributes."""
    target_env = xml.find("attrs/attr[@name='targetEnv']/string").get("value")
    for i in [charon.backends.none.NoneDefinition,
              charon.backends.virtualbox.VirtualBoxDefinition,
              charon.backends.ec2.EC2Definition]:
        if target_env == i.get_type():
            return i(xml)
    raise Exception("unknown backend type ‘{0}’".format(target_env))

def create_state(depl, type, name):
    """Create a machine state object of the desired backend type."""
    for i in [charon.backends.none.NoneState,
              charon.backends.virtualbox.VirtualBoxState,
              charon.backends.ec2.EC2State]:
        if type == i.get_type():
            return i(depl, name)
    raise Exception("unknown backend type ‘{0}’".format(type))
