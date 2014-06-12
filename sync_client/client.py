#
# Copyright (c) 2013 Citrix Systems, Inc.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

"""HTTP client using python-requests"""
from sys import path
path.append('/usr/lib/python2.6/site-packages/requests-0.11.1-py2.6.egg')
from json import loads, dumps
from sys import argv
from dbus import SystemBus, Interface, DBusException, String, Boolean, Int32
from subprocess import call, check_call, Popen, PIPE, check_output
from subprocess import CalledProcessError
from os.path import basename, dirname, join, split
from argparse import ArgumentParser
from logging import DEBUG, Formatter, getLogger, INFO, StreamHandler
from logging.handlers import SysLogHandler
from traceback import format_exc
from time import sleep, time
from uuid import uuid4
from tempfile import NamedTemporaryFile
from os import unlink, O_CREAT, O_RDONLY, O_WRONLY, environ
from pyicbinn import icbinn_clnt_create_v4v, icbinn_close, icbinn_lock
from pyicbinn import icbinn_mkdir, icbinn_open, icbinn_pwrite, icbinn_rand
from pyicbinn import icbinn_readent, icbinn_rename, icbinn_stat, icbinn_pread
from pyicbinn import icbinn_unlink
from re import match
from itertools import izip_longest

# TODO: revisit info messages, convert most to debug messages or remove?
# TODO: ICBINN_MAXDATA, O_WRONLY etc. should come from pyicbinn

ICBINN_SERVER_PORT = 4878
ICBINN_SERVER_DOMAIN_ID = 0
ICBINN_MAXDATA = 65536
ICBINN_FILE = 0
ICBINN_DIRECTORY = 1
ICBINN_UNKNOWN = 2
ICBINN_LTYPE_RDLCK = 0
ICBINN_LTYPE_WRLCK = 1
ICBINN_LTYPE_UNLCK = 2
ICBINN_RANDOM = 0
ICBINN_URANDOM = 1
DISK_DIR = 'disks'
REPO_DOWNLOAD_DIR = 'repo-download'
REPO_HANDOVER_DIR = 'repo'
ENCRYPT_SNAPSHOTS = 'encrypt_snapshots'
STATUS_OKAY = 0
STATUS_INTERNAL_EXCEPTION = 1
STATUS_FAILED = 2
DOWNLOAD_BLOCK_SIZE = 512 * 1024
ENCRYPTION_KEY_BYTES = 64
PROGRESS_INTERVAL = 1
DISK_TYPE_ISO = 'iso'
DISK_TYPE_VHD = 'vhd'
DISK_TYPES = [DISK_TYPE_ISO, DISK_TYPE_VHD]
SYNC_ROLE_PLATFORM = 'platform'
SYNC_ROLE_REALM = 'realm'
SYNC_ROLES = [SYNC_ROLE_PLATFORM, SYNC_ROLE_REALM]
RPC_PREFIX = 'rpc:'

ICBINN_STORAGE = None # set to the icbinn object for storage by setup_icbinn
ICBINN_CONFIG = None # set to the icbinn object for config by setup_icbinn

# VM properties set at template top level rather than config
VM_TOP_PROPERTIES = [
    'amt-pt', 'auto-s3-wake', 'control-platform-power-state', 'cpuid',
    'crypto-key-dirs', 'description', 'domstore-read-access',
    'domstore-write-access', 'download-progress', 'gpu', 'greedy-pciback-bind',
    'hidden', 'hidden-in-ui', 'icbinn-path', 'image-path', 'keep-alive',
    'measured', 'name', 'native-experience', 'oem-acpi-features', 'os',
    'ovf-transport-iso', 'provides-default-network-backend',
    'provides-graphics-fallback', 'provides-network-backend', 'ready', 'realm',
    'restrict-display-depth', 'run-insteadof-start',
    'run-on-acpi-state-change', 'run-on-state-change', 'run-post-create',
    'run-pre-boot', 'run-pre-delete', 's3-mode',
    's4-mode', 'seamless-id', 'seamless-traffic', 'show-switcher',
    'shutdown-priority', 'slot', 'start-from-suspend-image', 'start-on-boot',
    'stubdom', 'sync-uuid', 'time-offset', 'track-dependencies', 'type',
    'ui-selectable', 'usb-control', 'usb-enabled', 'usb-grab-devices',
    'wireless-control', 'xci-cpuid-signature']

VM_UNDERSCORE_PROPERTIES = [
    'start-on-boot', 'start-on-boot-priority', 'image-path']

VM_NO_HYPHEN_PROPERTIES = [
    'cmd-line']

VM_CENSORED_PROPERTIES = [
    'realm', 'sync-uuid', 'crypto-key-dirs', 'ready', 'download-progress']

log = getLogger(basename(argv[0]))

class Error(Exception):
    """Base class for other exceptions"""

class ConfigError(Error):
    """sync-client configuration is not valid"""
    exit_code = 4

class HTTPError(Error):
    """An error occurred while contacting the server"""
    exit_code = 5

class ServerVersionError(Error):
    """The server version is not supported"""
    exit_code = 6

class TargetStateError(Error):
    """The target state is not valid"""
    exit_code = 7

class PlatformError(Error):
    """An error occurred while updating the platform to the target state"""
    exit_code = 8

class IcbinnConnectError(Error):
    """Unable to connect to icbinn server"""
    exit_code = 9

class IcbinnError(Error):
    """Other icbinn error"""
    exit_code = 10

class MissingDownload(Error):
    """stat failed on a file after download"""
    exit_code = 11

class InsufficientIcbinnPaths(Error):
    """We did not get the two icbinn paths we needed"""
    exit_code = 12

class DiskMissing(Error):
    """The file for a disk we are responsible for is missing"""
    exit_code = 13

class KeyMismatch(Error):
    """We downloaded a VHD with a key that did not match the key that came with it"""
    exit_code = 14

class EncryptionKeyLengthWrong(Error):
    """We got a key length that we did not expect"""
    exit_code = 15

class VhdUtilSnapshotFailed(Error):
    """Running vhd-util snapshot did not create a file"""
    exit_code = 16

def setup_icbinn():
    """Setup icbinn paths and objects module level variables"""
    global ICBINN_CONFIG, ICBINN_STORAGE
    xenstore = Popen(['xenstore-read', 'vm'], stdout=PIPE, close_fds=True)
    output, _ = xenstore.communicate()
    if xenstore.returncode != 0:
        raise PlatformError('unable to read syncvm object path: '
                            'xenstore-read failed')
    syncvm_object_path = output.replace('-', '_').rstrip()
    paths = get_vm_property(syncvm_object_path, 
                                  'icbinn-path').split(',')
    if len(paths) < 2:
        raise InsufficientIcbinnPaths(2, paths)
    instances= [Icbinn(path, server_port=ICBINN_SERVER_PORT + x) for 
                x, path in enumerate(paths)]
    ICBINN_STORAGE, ICBINN_CONFIG = instances[:2]


# TODO: consider moving Icbinn and IcbinnFile into pyicbinn

class Icbinn(object):
    def __init__(self, mount_point, 
                 server_domain_id=ICBINN_SERVER_DOMAIN_ID,
                 server_port=ICBINN_SERVER_PORT):
        self.mount_point = mount_point
        log.info("calling icbinn at (%d, %d)", server_domain_id, server_port)
        try:
            self.icbinn = icbinn_clnt_create_v4v(server_domain_id,
                                                 server_port)
        except Exception as exc:
            raise IcbinnConnectError("failed to connect to icbinn server at "
                                     "(%d, %d): icbinn_clnt_create_v4v "
                                     "failed: %r" % (server_domain_id,
                                                     server_port, exc))
        if self.icbinn is None:
            raise IcbinnConnectError("failed to connect to icbinn server at "
                                     "(%d, %d): icbinn_clnt_create_v4v "
                                     "failed" % (server_domain_id,
                                                 server_port))
        log.info("successfully contacted icbinn server for %s" % (mount_point))

    def exists(self, path):
        log.info("statting %s on icbinn %s" % (path, self.mount_point))
        try:
            res = self.stat(path)
        except IcbinnError:
            log.info("stat %s failed" % (path))
            return False
        log.info("stat %s returned %r" % (path, res))
        return res[1] in [ICBINN_FILE, ICBINN_DIRECTORY]

    def listdir(self, path):
        files = []
        while True:
            entry = icbinn_readent(self.icbinn, str(path), len(files))
            if entry is None:
                break
            files.append(entry[0])
        return files

    def mkdir(self, path):
        if icbinn_mkdir(self.icbinn, str(path)) < 0:
            raise PlatformError("error creating icbinn directory '%s': "
                                "icbinn_mkdir failed" % path)

    def makedirs(self, path, timeout=10):
        # avoid leading and trailing slash confusion
        segs = [x for x in path.split() if x] 
        for here in [join(*segs[0:y]) for y in range(1, len(segs) + 1)]:
            try:
                self.mkdir(here)
            except PlatformError:
                pass
        if not self.stat(path)[1] == ICBINN_DIRECTORY:
            raise PlatformError("unable to create %s over icbinn" 
                                % (here))

    def open(self, path, mode):
        return IcbinnFile(self.icbinn, path, mode)

    def rename(self, src, dst):
        if icbinn_rename(self.icbinn, str(src), str(dst)) < 0:
            raise IcbinnError("error renaming icbinn file '%s' to '%s': "
                              "icbinn_rename failed" % (src, dst))

    def stat(self, path):
        try:
            return icbinn_stat(self.icbinn, str(path))
        except OSError as exc:
            raise IcbinnError("error statting icbinn file '%s': icbinn_stat "
                              "failed: %s" % (path, exc))

    def unlink(self, path):
        if icbinn_unlink(self.icbinn, str(path)) < 0:
            raise IcbinnError("error unlinking icbinn file '%s': "
                              "icbinn_unlink failed" % path)
    
    def rand(self, src, size):
        data = ""
        while True:
            log.info("read %d of %d bytes of random data from icbinn",
                     len(data), size)
            if len(data) == size:
                break
            try:
                data += icbinn_rand(self.icbinn, src, size - len(data))
            except IOError as exc:
                raise IcbinnError("error reading random data from icbinn: "
                                  "icbinn_rand failed: %s" % exc)
        return data

    def write_file(self, name, content):
        file_obj = self.open(name, O_WRONLY | O_CREAT)
        file_obj.pwrite(content, 0)
        file_obj.close()

    def mounted_path(self, path):
        components = path.split('/')
        if '.' in components or '..' in components:
            raise TargetStateError('invalid components in %s' % (path))
        return join(self.mount_point, path)

class IcbinnFile(object):
    def __init__(self, icbinn, path, mode):
        self.icbinn = icbinn
        self.path = path

        self.fd = icbinn_open(self.icbinn, str(self.path), mode)
        if self.fd < 0:
            raise IcbinnError("error opening icbinn file '%s': icbinn_open "
                              "failed" % self.path)

    def close(self):
        if icbinn_close(self.icbinn, self.fd) < 0:
            raise IcbinnError("error closing icbinn file '%s': icbinn_close "
                              "failed" % self.path)

    def get_read_lock(self):
        if icbinn_lock(self.icbinn, self.fd, ICBINN_LTYPE_RDLCK) < 0:
            raise IcbinnError("error getting read lock on icbinn file '%s': "
                              "icbinn_lock failed" % self.path)

    def get_write_lock(self):
        if icbinn_lock(self.icbinn, self.fd, ICBINN_LTYPE_WRLCK) < 0:
            raise IcbinnError("error getting write lock on icbinn file '%s': "
                              "icbinn_lock failed" % self.path)

    def pwrite(self, data, offset):
        data_len = len(data)
        written = 0
        while written < data_len:
            n = icbinn_pwrite(self.icbinn, self.fd,
                              data[written:written + ICBINN_MAXDATA],
                              offset + written)
            if n < 0:
                raise IcbinnError("error writing to icbinn file '%s': "
                                  "icbinn_pwrite failed" % self.path)
            written += n

    def pread(self, size, offset):
        try:
            return icbinn_pread(self.icbinn, self.fd, size, offset)
        except IOError as exc:
            raise IcbinnError("error reading icbinn file '%s': icbinn_pwrite "
                              "failed: %s" % (self.path, exc))

    def unlock(self):
        if icbinn_lock(self.icbinn, self.fd, ICBINN_LTYPE_UNLCK) < 0:
            raise IcbinnError("error unlocking icbinn file '%s': icbinn_lock "
                              "failed" % self.path)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

class HTTPServer(object):
    """Encapsulate downloads from an HTTP server, using curl"""
    def __init__(self, base_url, user=None, password=None, cacert=None):
        if not base_url.endswith('/'):
            base_url += '/'
        self.base_url = base_url
        self.user = user
        self.password = password
        self.cacert = cacert

    def write_auth_file(self, stream):
        """Write curl auth config to stream"""
        stream.write('--digest\n')
        stream.write('--cacert %s\n' % self.cacert)
        stream.write('--user %s:%s\n' % (self.user, self.password))
        stream.flush()

    def operation(self, method, document, timeout=5, **kex):
        """Access document using curl"""
        url = self.base_url + document
        log.info('%s %s' % (method.upper(), url))
        with NamedTemporaryFile(suffix='.cred') as cf:
            self.write_auth_file(cf)
            with NamedTemporaryFile(suffix='.'+method+'.out') as tf:
                args = ['curl', '--silent', '--max-time', str(timeout), 
                        '-K', cf.name, url]
                if method.upper() == 'PUT':
                    tf2 = file(tf.name, 'w')
                    tf2.write(kex.get('data', ''))
                    tf2.close()
                    args += ['--upload-file', tf.name]
                elif method.upper() == 'GET':
                    args += ['--out', tf.name]
                    args += ['--write-out', '%{http_code}']
                curl = Popen(args, stdout=PIPE, stderr=PIPE, close_fds=True)
                out, err = curl.communicate()
                for line in out.split('\n'):
                    if line != '{}':
                        log.info('curl stdout %s' % line)
                for line in err.split('\n'):
                    if line:
                        log.info('curl stderr %s' % line)

                if method.upper() == 'GET':
                    # parse HTTP response code and raise an error if in 400s
                    if out.startswith('4'):
                        raise HTTPError('%s request for %s: HTTP response code %s' % (method.upper(), url, out))

                if curl.returncode != 0:
                    raise HTTPError('%s request for %s failed: curl exit code '
                                    '%d\n%s' % (method.upper(), url,
                                                curl.returncode, err))
                if method.upper() == 'GET':
                    ofile = file(tf.name, 'rb')
                    outb = ofile.read()
                    ofile.close()
                else:
                    # TODO: do we want to record output for PUT operations?
                    # is that even meaningful?
                    outb = None
        return outb

    def download(self, document, destination, size, desc, icbinn, timeout=3600,
                 progress_callback=None):
        """Download document to destination using curl.

        Destination is an icbinn path"""

        url = self.base_url + document
        log.info('downloading URL %s timeout %d', url, timeout)
        partial_destination = destination + '.partial'
        icbinn.makedirs(dirname(destination))
        try:
            partial_size = icbinn.stat(partial_destination)[0]
        except IcbinnError:
            partial_size = 0
        if progress_callback:
            progress_callback(partial_size)
        if partial_size < size:
            with NamedTemporaryFile(suffix='.cred') as cf:
                self.write_auth_file(cf)
                curl = Popen(['curl', '--silent', '--fail',
                              '--max-time', str(timeout), 
                              '-K', cf.name,
                              '--range', str(partial_size) + '-', url],
                             stdout=PIPE, close_fds=True)
                with icbinn.open(partial_destination,
                                 O_WRONLY | O_CREAT) as icbinn_file:
                    while True:
                        data = curl.stdout.read(DOWNLOAD_BLOCK_SIZE)
                        if data == '':
                            break
                        icbinn_file.pwrite(data, partial_size)
                        partial_size += len(data)
                        if progress_callback: 
                            progress_callback(partial_size)
                if curl.wait() != 0:
                    raise HTTPError('failed to download %s to %s: curl exit '
                                    'code %d' % (url, partial_size,
                                                 curl.returncode))
        if progress_callback:
            progress_callback(size)
        icbinn.rename(partial_destination, destination)
        log.info('downloaded %s', destination)

def get_property(path, key, interface, 
                 service='com.citrix.xenclient.xenmgr'):
    """Lookup key on interface at path"""
    obj = SystemBus().get_object(service, path)
    propi = Interface(obj, dbus_interface='org.freedesktop.DBus.Properties')
    return propi.Get(interface, key)


def set_property(path, key, value, interface, 
                 service='com.citrix.xenclient.xenmgr'):
    """Set key to value on interface at path"""
    obj = SystemBus().get_object(service, path)
    propi = Interface(obj, dbus_interface='org.freedesktop.DBus.Properties')
    return str(propi.Set(interface, key, value))    

def open_xenmgr():
    """Return a dbus proxy for the main xenmgr interface"""
    bus = SystemBus()
    xenmgr_obj = bus.get_object('com.citrix.xenclient.xenmgr', '/')  
    return Interface(xenmgr_obj, dbus_interface='com.citrix.xenclient.xenmgr')

def open_xenmgr_unrestricted():
    """Return a dbus proxy for the main xenmgr interface"""
    bus = SystemBus()
    xenmgr_obj = bus.get_object('com.citrix.xenclient.xenmgr', '/')  
    return Interface(xenmgr_obj, 
                     dbus_interface='com.citrix.xenclient.xenmgr.unrestricted')

def open_vm(vm_path):
    """Return a dbus proxy for the VM object"""
    bus = SystemBus()
    vm_obj = bus.get_object('com.citrix.xenclient.xenmgr', vm_path)  
    return Interface(vm_obj, 
                     dbus_interface='com.citrix.xenclient.xenmgr.vm')
    
def open_input_daemon():
    """Return a dbus proxy for the input daemon interface"""
    bus = SystemBus()
    input_obj = bus.get_object('com.citrix.xenclient.input', '/')  
    return Interface(input_obj, dbus_interface='com.citrix.xenclient.input')

def open_db():
    """Return a dbus proxy for the database (i.e. domstore) interface"""
    bus = SystemBus()
    db_obj = bus.get_object('com.citrix.xenclient.db', '/')  
    return Interface(db_obj, dbus_interface='com.citrix.xenclient.db')

def get_vm_property(vm_path, key, uuidmap=None):
    """Return the name of the VM with vm_path"""
    value = get_property(vm_path, key, 'com.citrix.xenclient.xenmgr.vm')
    if uuidmap is not None and key.startswith('run-'):
        value = map_vm_run_property(value, uuidmap, True)
    return value

def set_vm_property(vm_path, key, value, uuidmap=None):
    """Set the name of the VM with vm_path to name. You guessed?"""
    current = get_vm_property(vm_path, key, uuidmap)
    if uuidmap is not None and key.startswith('run-'):
        value = map_vm_run_property(value, uuidmap, False)
    log.info('vm %r current %r desired %r', key, current, value)
    if str(current) != str(value):
        return set_property(vm_path, key, value, 
                            'com.citrix.xenclient.xenmgr.vm.unrestricted')

def map_vm_run_property(value, uuidmap, reverse):
    """Map any server VM uuids to a client VM uuids (or the reverse operation)
    in a run-* VM property"""
    if value.startswith(RPC_PREFIX):
        new_items = []
        for item in value[len(RPC_PREFIX):].split(","):
            item_key, item_sep, item_value = item.partition("=")
            if item_key == "vm" and item_sep == "=":
                item_value = map_vm_uuid(item_value, uuidmap, reverse)
            new_items.append(item_key + item_sep + item_value)
        new_value = RPC_PREFIX + ",".join(new_items)
        log.info('vm rpc value %r->%r', value, new_value)
        value = new_value
    return value

def get_nic_property(vm_path, nic_index, key, uuidmap):
    """Get the nic property key for vm_path, 
    mapping server to client uuids using uuidmap"""
    path = vm_path+'/nic/'+str(nic_index)
    log.info('looking up nic/%d property %s at %s', nic_index, key, path)
    try:
        value = get_property(path, key, 'com.citrix.xenclient.vmnic')
    except DBusException:
        value = None
    log.info('nic/%d property value %r', nic_index, value)
    if key == 'backend-uuid':
        value = map_vm_uuid(value, uuidmap, True)
    log.info('nic/%d done value %r', nic_index, value)
    return value

def set_nic_property(vm_path, nic_index, key, value, uuidmap):
    """Set the nic property key for vm_path, mapping server to client 
    uuids using uuidmap"""
    path = vm_path+'/nic/'+str(nic_index)
    if key == 'backend-uuid':
        value = map_vm_uuid(value, uuidmap, False)
    log.info('nic/%d property %r value %r', nic_index, key, value)
    return set_property(vm_path+'/nic/'+str(nic_index), key, value, 
                        'com.citrix.xenclient.vmnic')

def map_vm_uuid(value, uuidmap, reverse):
    """Map a server VM uuid to a client VM uuid (or the reverse operation)"""
    if reverse:
        for srv, cli in uuidmap.items():
            if cli == value:
                return srv
    else:
        try:
            return uuidmap[value]
        except KeyError:
            raise TargetStateError('vm uuid %r not in uuid map %r' %
                                   (value, uuidmap))

def get_domstore_key(vm, key):
    v = vm_control(vm)
    return v.get_domstore_key(key)

def set_domstore_key(vm, key, value):
    v = vm_control(vm)
    return v.set_domstore_key(key, value)

def get_disk_property(disk_path, key):
    """Get property key of disk at disk_path"""
    return get_property(disk_path, key, 'com.citrix.xenclient.vmdisk')

def set_disk_property(disk_path, key, value):
    """Set property key to value of disk at disk_path"""
    return set_property(disk_path, key, value, 'com.citrix.xenclient.vmdisk')

def get_ui_config(key):
    """Set a xenmgr configuration property key to value"""
    return get_property('/', key, 'com.citrix.xenclient.xenmgr.config.ui')

def set_ui_config(key, value):
    """Set a xenmgr configuration property key to value"""
    return set_property('/', key, value, 
                        'com.citrix.xenclient.xenmgr.config.ui')

def get_xenmgr_config(key):
    """Set a xenmgr configuration property key to value"""
    return get_property('/', key, 'com.citrix.xenclient.xenmgr.config')

def set_xenmgr_config(key, value):
    """Set a xenmgr configuration property key to value"""
    return set_property('/', key, value, 'com.citrix.xenclient.xenmgr.config')

def get_host_property(key):
    """Get a host configuration property"""
    return get_property('/host', key, 'com.citrix.xenclient.xenmgr.host')

def host_control():
    """Return a proxy with the host control interface"""
    host_obj = SystemBus().get_object('com.citrix.xenclient.xenmgr', '/host')
    return Interface(host_obj, dbus_interface='com.citrix.xenclient.xenmgr.host')

def vm_control(vm_path):
    """Return a proxy with the VM control interface for vm_path"""
    vm_obj = SystemBus().get_object('com.citrix.xenclient.xenmgr', vm_path)
    return Interface(vm_obj, dbus_interface='com.citrix.xenclient.xenmgr.vm')

def disk_control(disk_path):
    """Return a proxy with the disk path interface for disk_path"""
    disk_obj = SystemBus().get_object('com.citrix.xenclient.xenmgr', 
                                      disk_path)    
    return Interface(disk_obj, dbus_interface='com.citrix.xenclient.vmdisk')

def arrange_license(license, device_uuid):
    """Update license information"""
    if license['expiry_time'] is not None:
        host_control().set_license(license['expiry_time'], device_uuid,
                                   license['hash'])
    else:
        host_control().set_license('1970-01-01 00:00:00 +0000', device_uuid,
                                   'unlicensed')

def arrange_device(myconfig, device_config):
    """Arrange device configuration to match device_config"""
    set_config(device_config, 
               {'xenmgr': (get_xenmgr_config, set_xenmgr_config),
                'sync-client' : (myconfig.get, myconfig.set),
                'ui': (get_ui_config, set_ui_config)})
    log.info('my config %r', myconfig.config)

def get_current_release_and_build():
    """Get current XC release and build number from xenmgr"""
    build_info = get_host_property('build-info')
    return build_info['release'], build_info['build']

def arrange_xc_version(repo, download):
    """Arrange for the version of XC installed on the device to match the
       target state described in repo.
       
       If the current release and build don't match the target state, download
       the repository and hand it over to updatemgr to perform an over-the-air
       upgrade."""
    repo_name = generate_repo_file_name(repo['repo_uuid'])
    target = repo['release'], repo['build']
    current = get_current_release_and_build()
    upgrade_in_progress = False
    log.info('current release %s; current build %s', *current)

    for name in ICBINN_STORAGE.listdir(REPO_DOWNLOAD_DIR):
        # TODO: downloading with .partial suffix isn't useful for repos
        if (repo_name is None or current == target or
            name not in [repo_name, repo_name + '.partial']):
            file_path = join(REPO_DOWNLOAD_DIR, name)
            log.info('deleting obsolete downloaded repo %s', file_path)
            ICBINN_STORAGE.unlink(file_path)

    # TODO: or just leave files for updatemgr to consume? (only works if
    # updatemgr polls the directory)
    for name in ICBINN_STORAGE.listdir(REPO_HANDOVER_DIR):
        if repo_name is None or current == target or name != repo_name:
            file_path = join(REPO_HANDOVER_DIR, name)

            try:
                icbinn_file = ICBINN_STORAGE.open(file_path, O_WRONLY | O_CREAT)
            except IcbinnError:
                log.info('obsolete handed-over repo %s has been removed by '
                         'updatemgr', file_path)
                continue

            try:
                try:
                    icbinn_file.get_write_lock()
                except IcbinnError:
                    log.info('obsolete handed-over repo %s is locked by '
                             'updatemgr; upgrade in progress', file_path)
                    upgrade_in_progress = True
                    continue

                log.info('deleting obsolete handed-over repo %s', file_path)
                ICBINN_STORAGE.unlink(file_path)
            finally:
                icbinn_file.close()

    # TODO: consider not downloading at all if upgrade_in_progress
    if repo_name is None:
        log.info('target state does not specify release/build')
    elif current != target:
        log.info('current release/build does not match target state')
        download_file = join(REPO_DOWNLOAD_DIR, repo_name)
        handover_file = join(REPO_HANDOVER_DIR, repo_name)
        if not ICBINN_STORAGE.exists(handover_file):
            # TODO: checks on file size?
            if not ICBINN_STORAGE.exists(download_file):
                log.info('downloading repo %s', repo_name)
                download('repo/' + repo_name, download_file, repo['file_size'],
                         'update', ICBINN_STORAGE)

            if upgrade_in_progress:
                log.info('upgrade in progress; not handing repo %s over to '
                         'updatemgr', repo_name)
            else:
                log.info('handing repo %s over to updatemgr', repo_name)
                ICBINN_STORAGE.makedirs(split(handover_file)[0])
                ICBINN_STORAGE.rename(download_file, handover_file)
        # TODO: prod updatemgr (if not upgrade_in_progress)?

    return current

def ensure_disk_downloaded(disk, download, icbinn,
                           disk_progress_callback=None):
    """Download a disk if necessary.

    Download is a callback that takes a server path name
    and a local destination filename and makes the download happen.

    Return the disk size, the disk location relative to ICBINN_STORAGE,
    and whether we just downloaded it
    """
    destination_rel = generate_disk_path(disk['diskuuid'],
                                     disk.get('type', DISK_TYPE_VHD))
    log.info('%s original disk %s expected at %s',
             'HAVE' if icbinn.exists(destination_rel) else 'MISSING',
             redact_disk(disk), destination_rel)

    if not icbinn.exists(destination_rel):
        def progress_callback(partial):
            """Update progress"""
            if disk_progress_callback:
                disk_progress_callback(disk, partial)
        if download is None:
            return 0, destination_rel, False
        document = ('disk/' + disk['diskuuid'] + '.' +
                    disk.get('type', DISK_TYPE_VHD))
        download(document, destination_rel, disk['size'], 'VM disk', icbinn,
                 progress_callback=progress_callback)
    else:
        document = None
    try:
        return (icbinn.stat(destination_rel)[0], destination_rel, 
                (True if document else False))
    except IcbinnError:
        raise MissingDownload(destination_rel, document)

def check_uuid(uuid):
    """Return uuid if it is in the correct format for a uuid, and therefore
       safe to use when constructing a file name"""
    if match(r"[0-9a-f-]{36}$", uuid) is None:
        raise TargetStateError("uuid '%s' length %d is not valid" % (
                uuid, len(uuid)))
    return uuid

def check_disk_type(disk_type):
    """Return disk_type if it is a valid disk type, and therefore safe to use
       when constructing a file name"""
    if disk_type not in DISK_TYPES:
        raise TargetStateError("disk type '%s' is not valid" % disk_type)
    return disk_type

def generate_disk_path(diskuuid, disk_type):
    """Work out storage path for diskuuid of type disk_type"""
    return join(DISK_DIR,
                check_uuid(diskuuid) + '.' + check_disk_type(disk_type))

def generate_snapshot_vhd_path(diskuuid, shared, vm_instance_uuid):
    """Work out icbinn storage path for this VM's snapshot of diskuuid"""
    tag = 'shared' if shared else check_uuid(vm_instance_uuid)
    return join(DISK_DIR,
                check_uuid(diskuuid) + '_' + tag + '.' + DISK_TYPE_VHD)

def generate_repo_file_name(repo_uuid):
    """Work out file name for repo_uuid (or None if repo_uuid is None)"""
    if repo_uuid is not None:
        return check_uuid(repo_uuid) + '.tar'

def get_platform_crypto_dir():
    return get_property('/', 'platform-crypto-key-dirs',
        'com.citrix.xenclient.xenmgr.config')

def decode_encryption_key(encryption_key):
    """Return raw key for hexadecimal string encryption_key"""
    try:
        raw_key = encryption_key.decode('hex')
    except TypeError:
        raise TargetStateError('hexadecimal disk encryption key is not valid')
    if len(raw_key) != ENCRYPTION_KEY_BYTES:
        raise TargetStateError('disk encryption key is %d bytes; expected '
                               '%d' % (len(raw_key), ENCRYPTION_KEY_BYTES))
    return raw_key


def vhd_util(*args):
    """Run vhd-util via ICBINN"""
    environ['LIBVHD_ICBINN_VHD_SERVER'] = 'v4v:0:4878'
    environ['LIBVHD_ICBINN_KEY_SERVER'] = 'v4v:0:4879'
    cmd = ['vhd-util'] + list(args)
    log.info("running [ %s ]", ' '.join(cmd))
    return check_output(cmd, close_fds=True)

def make_key(myconfig, nbytes):
    """Make a key given myconfig of length nbytes"""
    src = (ICBINN_URANDOM if myconfig.get('use-pseudorandomness') else
           ICBINN_RANDOM)
    out = ''
    for _ in range(nbytes):
        out += ICBINN_STORAGE.rand(src, 1)
    return out

def calculate_key_path(vhd_rel, length):
    """Work out path for key for vhd_rel, with given length"""
    uuid = basename(vhd_rel)[:-4]
    return '%s,aes-xts-plain,%d.key' % (uuid, length)

def verify_vhd_key(vhd_rel, length=ENCRYPTION_KEY_BYTES*8):
    """Check that the key on disk matches the key fingerprint in the VHD
    Length is the key length in bits"""
    key_rel = calculate_key_path(vhd_rel, length)
    key_hash = vhd_util('key', '-C', '-k', key_rel)
    file_hash = vhd_util('key', '-p', '-n', vhd_rel)
    if key_hash.split()[-1:] != file_hash.split()[-1:]:
        raise KeyMismatch('file=', vhd_rel, 'file_hash=', file_hash, 
                          'key=', key_rel, 'key_hash=', key_hash)
    log.info('file %s has matching key fingerprint %s to file at %s', 
             ICBINN_STORAGE.mounted_path(vhd_rel), key_hash.split()[-1], 
             ICBINN_CONFIG.mounted_path(key_rel))

def place_vhd_key(vhd_rel, content, mark_vhd=False, 
                  length=ENCRYPTION_KEY_BYTES*8):
    """Associate key content with filesystem

    If mark_vhd is set, update the VHD with the fingerprint of the key

    If content is set, write the key to dom0 key storage (/config partition)"""
    key_rel = calculate_key_path(vhd_rel, length)
    if len(content)*8 != length:
        raise EncryptionKeyLengthWrong(len(content)*8, length)
    ICBINN_CONFIG.write_file(key_rel, content)
    if mark_vhd:
        vhd_util('key', '-s', '-n', vhd_rel, '-k', key_rel)
    verify_vhd_key(vhd_rel, length)

def configure_disk_path_and_type(phys_path, disk_path, disk_type, read_only):
    """Configure phys_path to dbus object at disk_path"""
    if disk_type == DISK_TYPE_VHD:
        if get_disk_property(disk_path, 'phys-path') != phys_path:
            disk_control(disk_path).attach_vhd(phys_path)
        set_disk_property(disk_path, 'mode', 'r' if read_only else 'w')
        set_disk_property(disk_path, 'devtype', 'disk')
    else:
        set_disk_property(disk_path, 'devtype', 'cdrom')
        set_disk_property(disk_path, 'mode', 'r' if read_only else 'w')
        set_disk_property(disk_path, 'phys-type', 'file')
        set_disk_property(disk_path, 'phys-path', phys_path)

def ensure_vm_exists(uuid, have, sync_name, config, name):
    """Ensure VM desc exists; given what VMs we have"""
    vmpath = have.get(uuid)
    log.info('%s %s %r', 'HAVE' if vmpath else 'DESIRE', uuid, config)
    allconfig = list(config) + [
        {'daemon':'vm', 'key':'realm', 'value':sync_name},
        {'daemon':'vm', 'key':'name', 'value':name},
        {'daemon':'vm', 'key':'sync-uuid', 'value':uuid}]
    base_template = ''

    if vmpath is None:
        topdict = dict()
        topdict['v4v-firewall-rules'] = dict()
        topdict['rpc-firewall-rules'] = dict()
        topdict['config'] = dict()
        topdict['config']['pci'] = dict()
        topdict['policies'] = dict()
        nics = topdict['config']['nic'] = {}
        for rec in allconfig :
            log.info('processing %s', rec)
            key = rec.get('key')
            daemon = rec.get('daemon')
            value = rec.get('value')
            if daemon == 'vmparam' and key == 'template':
                base_template = value
            elif daemon == 'vm' or daemon == 'vmparam':
                if key in VM_UNDERSCORE_PROPERTIES:
                    akey = key.replace('-', '_')
                elif key in VM_NO_HYPHEN_PROPERTIES:
                    akey = key.replace('-', '_')
                else:
                    akey = key
                if key.startswith('policy-'):
                    akey = akey[7:]
                    if akey.endswith('-recording'):
                        akey = akey.replace('-recording', '-rec')
                    elif akey == 'print-screen':
                        if value == 'true':
                            continue
                        else:
                            akey = 'print-screen-disallowed'
                            value = 'true'
                    topdict['policies'][akey] = value
                elif key.startswith('run-'):
                    # The value may require a server VM uuid to be replaced
                    # with a client VM uuid. The client VM may not exist at
                    # this point, so set this value later in arrange_vm.
                    pass
                elif key in VM_TOP_PROPERTIES:
                    topdict[akey] = value
                else:
                    topdict['config'][akey] = value
            if daemon.startswith('nic/') and key != 'backend-uuid':
                nic_index = daemon[4:]
                if nic_index not in nics:
                    nics[nic_index] = dict({'id': nic_index})
                nics[nic_index][key]= value
            if daemon in ['v4v', 'rpc', 'pci'] and value == 'true':
                if daemon == 'pci':
                    destdict = topdict['config']['pci']
                else:
                    destdict = topdict[daemon+'-firewall-rules']
                highest = max( [-1]+[int(i) for i in destdict.keys()])
                if daemon == 'pci':
                    rkey = dict()
                    for akey in key.split(','):
                        spl = akey.split('=')
                        rkey[spl[0]] = '='.join(spl[1:])
                else:
                    if daemon != 'rpc':
                        rkey = key.replace(',', ':')
                    else:
                        rkey = key.replace(',', ' ')
                destdict[str(highest+1)] = rkey
                log.info('%s rule %d: %r', daemon, highest+1, rkey)
        template = dumps(topdict)
        log.info('VM base %s template %s', base_template, template)
        vmpath = open_xenmgr_unrestricted(
            ).unrestricted_create_vm_with_template_and_json(
            base_template, template)
        log.info('created VM path %s', vmpath)
        have[uuid] = vmpath
    set_vm_property(vmpath, 'realm', sync_name)
    set_vm_property(vmpath, 'sync-uuid', uuid)

def filter_configuration(config, keywords):
    """Filter config for keywords"""
    if config is None:
        config = []
    config2 = []
    results = {}
    for item in config:
        if item['daemon'] == 'synchronizer' and item['key'] in keywords:
            results[item['key']] = decode_boolean(item['value'])
        else:
            config2.append(item)
    return config2, results

def destroy_disk(toolstack_disk_object):
    """Destroy a toolstack disk object, umounting if we can"""
    diskcontrol = disk_control(toolstack_disk_object)
    try:
        diskcontrol.umount()
    except DBusException:
        pass
    try:
        diskcontrol.delete()
    except DBusException:
        log.warning('error deleting %r', toolstack_disk_object)


def are_snapshots_encrypted(diskoptions, vmoptions):
    """Given disk options and VM options should snapshots be encrypted?"""
    if ENCRYPT_SNAPSHOTS in diskoptions:
        return diskoptions[ENCRYPT_SNAPSHOTS]
    elif ENCRYPT_SNAPSHOTS in vmoptions:
        return vmoptions[ENCRYPT_SNAPSHOTS]
    else:
        return True

def arrange_snapshot(diskuuid, shared, vm_instance_uuid, base_rel,
                     generate_key, encrypt_snapshots=True):
    """Make or use snapshot for diskuuid on vm_instance_uuid
    for disk base_rel (relative to ICBINN)

    generate_key is a callback to make disk keys.

    If shared it will be a shared shapshot"""

    snapshot_rel = generate_snapshot_vhd_path(
        diskuuid, shared, vm_instance_uuid)
    snapshot_dom0 = ICBINN_STORAGE.mounted_path(snapshot_rel)
    if ICBINN_STORAGE.exists(snapshot_rel):
        log.info('already have snapshot '+snapshot_dom0)
        verify_vhd_key(snapshot_rel)
    else:
        log.info("creating %s snapshot at %s", 
                 'encrypted' if encrypt_snapshots else 'clear', 
                 snapshot_dom0)
        vhd_util('snapshot', '-p', base_rel, '-n', snapshot_rel)
        if not ICBINN_STORAGE.exists(snapshot_rel):
            raise VhdUtilSnapshotFailed(base_rel, snapshot_rel)
        log.info('created snapshot '+ snapshot_dom0)
        if encrypt_snapshots:
            place_vhd_key(snapshot_rel, generate_key(), mark_vhd=True)
        else:
            log.warning('unencrypted VHD delta snapshot created')
    return snapshot_dom0


def arrange_disk_in_toolstack(vmpath, vmoptions,
                              disk_index, toolstack_disk_object, 
                              vmdisk, target_state_disk, generate_key,
                              vm_instance_uuid):
    """Sort out disk_index for vmpath with toolstack DBUS path
    toolstack_disk_object, target state vmdisk (either of which may be
    None, but not both.  

    vmoptions are the VM options, used as an input to determine if we
    should encrypt snapshots.

    generate_key is function which returns a new disk encryption key
    when called
    
    vm_instace_uuid is the UUID of the VM instance, for snapshot naming"""

    log.info('arranging toolstack state for disk %d '
             'record %s toolstack object %s target state disk %r', 
             disk_index, redact_disk(vmdisk), toolstack_disk_object,
             redact_disk(target_state_disk))

    if vmdisk is None:
        assert toolstack_disk_object is not None
        log.info('destroying excess disk object %s', toolstack_disk_object)
        destroy_disk(toolstack_disk_object)
        return

    diskconfig, diskoptions = filter_configuration(vmdisk['config'], 
                                                   [ENCRYPT_SNAPSHOTS])
    encrypt_snapshots = are_snapshots_encrypted(diskoptions, vmoptions)

    disk_path_rel = generate_disk_path(
        vmdisk['diskuuid'], 
        target_state_disk.get('type', DISK_TYPE_VHD))
    disk_path_dom0 = ICBINN_STORAGE.mounted_path(disk_path_rel)
    if not ICBINN_STORAGE.exists(disk_path_rel):
        raise DiskMissing(disk_path_dom0)

    if target_state_disk.get('read_only', False):
        snapshot_dom0 = None
        target_path_dom0 = disk_path_dom0
    else:
        disk_type = target_state_disk.get('type', DISK_TYPE_VHD)
        if disk_type != DISK_TYPE_VHD:
            raise TargetStateError('disk %s has type %s but is not '
                                   'read-only' % (target_state_disk, disk_type))
        snapshot_dom0 = target_path_dom0 = arrange_snapshot(
            vmdisk['diskuuid'], target_state_disk.get('shared'),
            vm_instance_uuid, disk_path_rel,
            generate_key, encrypt_snapshots)

    log.info('%s target path %r', 
            'CONFIGURED' if toolstack_disk_object else 'UNCONFIGURED',
            target_path_dom0)

    if toolstack_disk_object is None:
        vmc = vm_control(vmpath)
        toolstack_disk_object = vmc.add_disk()
        just_attached = True
    else:
        just_attached = False

    configure_disk_path_and_type(target_path_dom0, toolstack_disk_object, 
                                 target_state_disk.get('type', DISK_TYPE_VHD),
                                 target_state_disk.get('read_only', False))
    log.info("%s disk %s at %s %s snapshot at %s", 
            'ATTACHED' if just_attached else 'INSPECTED',
            disk_path_dom0, toolstack_disk_object,                     
            'ENCRYPTED' if encrypt_snapshots else 'CLEAR',
            snapshot_dom0)

    set_config(diskconfig, 
               {'disk': (
                lambda k: get_disk_property(toolstack_disk_object, k),
                lambda k, v: set_disk_property(toolstack_disk_object, k, v))})


def arrange_vm(myconfig, vmpath, vminfo, diskmap, uuidmap, already_disks):
    """Arrange that VM at vmpath is in state vminfo, 
    given the disks available. """

    vmc = vm_control(vmpath)
    keydir = ICBINN_CONFIG.mount_point
    if get_vm_property(vmpath, 'crypto-key-dirs') != keydir:
        log.info('setting VM crypto key dirs to %s', keydir)
        set_vm_property(vmpath, 'crypto-key-dirs', keydir)
    config, vmoptions = filter_configuration(vminfo.get('config'), 
                                             [ENCRYPT_SNAPSHOTS])
    config.append({'daemon': 'vm', 'key': 'name', 'value': vminfo['name']})
    def configure(daemon):
        if daemon == 'vm':
            return ((lambda k: get_vm_property(vmpath, k, uuidmap)),
                    (lambda k, v: set_vm_property(vmpath, k, v, uuidmap)))
        if daemon == 'domstore':
            return ((lambda k: get_domstore_key(vmpath, k)),
                    (lambda k, v: set_domstore_key(vmpath, k, v)))
        if daemon in ['vmparam', 'v4v', 'rpc', 'pci']:
            return (None, None)
        if daemon.startswith('nic/'):
            try:
                nic_index = int(daemon[4:])
            except ValueError:
                raise TargetStateError('invalid daemon %r' % daemon)
            return ((lambda k: get_nic_property(vmpath, nic_index, 
                                                k, uuidmap),
                     lambda k,v: set_nic_property(vmpath, nic_index, 
                                                  k, v, uuidmap)))

    set_config(config, configure)

    for vmdisk in vminfo['disks']:
        bytes = already_disks.get(vmdisk['diskuuid'])
        if bytes in [None, 0]:
            log.info('do not have data for %r yet', redact_disk(vmdisk))
            set_vm_property(vmpath, 'ready', False)
            return

    vmstate = get_vm_property(vmpath, 'state')
    if vmstate != 'stopped':
        log.info("vm %s is %s so disk configuration disabled", vmpath, vmstate)
        return

    # walk over each disk on the VM and that we want
    for disk_index, (toolstack_disk_object, vmdisk) in enumerate(
        izip_longest(vmc.list_disks(), vminfo['disks'])):
        target_state_disk = diskmap.get(vmdisk['diskuuid']) if vmdisk else None
        arrange_disk_in_toolstack(
            vmpath, vmoptions, disk_index, toolstack_disk_object, vmdisk, 
            target_state_disk, lambda: make_key(myconfig, ENCRYPTION_KEY_BYTES),
            vminfo['vm_instance_uuid'])

    set_vm_property(vmpath, 'ready', True)

def arrange_vms(myconfig, vms, disks, sync_name, already_disks, delete=True):
    """Ensure we have a VM set corresponding to vms, a list
    of VM information dictionaries. disks is a list of disk 
    information dictionaries."""
    disk_map = dict([(disk['diskuuid'], disk) for disk in disks])

    xenmgr = open_xenmgr()
    xenmgr_unrestricted = open_xenmgr_unrestricted()
    have = dict( [(get_vm_property(vm_path, 'sync-uuid'), vm_path) for 
                  vm_path in xenmgr.list_vms() if 
                  get_vm_property(vm_path, 'realm') == sync_name])
    log.info('VMs in realm %s have sync UUID to local VM mapping %r', 
             sync_name, have)
    allvms = dict ( [(str(vminfo['vm_instance_uuid']),
                       vminfo) for vminfo in vms])
    desired = dict( [rec for rec in allvms.items() if not 
                     rec[1].get('removed', False)])
    
    uuid_map = {} # maps server VM uuids to local client VM UUIDs
    for server_uuid, vminfo in desired.items():
        ensure_vm_exists(server_uuid, have, sync_name, vminfo['config'],
                         vminfo['name'])
        client_uuid = get_vm_property(have[server_uuid], 'uuid')
        uuid_map[vminfo['vm_uuid']] = client_uuid
    log.info('uuid_map %r', uuid_map)

    for server_uuid, vminfo in desired.items():
        log.info('ensuring %s exists', server_uuid)
        arrange_vm(myconfig, have[server_uuid], vminfo, disk_map, 
                   uuid_map, already_disks)
        log.info('confirmed exists %s', server_uuid)

    if delete:
        for server_uuid, vminfo in allvms.items():
            vmpath = have.get(server_uuid)
            if vmpath and vminfo['removed']:
                set_vm_property(vmpath, 'download-progress', -1)
                set_vm_property(vmpath, 'ready', False)

        for server_uuid, vmpath in have.items():
            vminfo = allvms.get(server_uuid)
            graceful_delete = (vminfo and vminfo.get('removed', False) and 
                               get_vm_property(vmpath, 'state') == 'stopped')
            if vminfo is None or graceful_delete:
                vmc = vm_control(vmpath)
                log.info('destroying unwanted VM %s', server_uuid)
                vmc.destroy()
                client_uuid = get_vm_property(have[server_uuid], 'uuid')
                try:
                    xenmgr_unrestricted.unrestricted_delete_vm(client_uuid)
                except DBusException:
                    # The run-pre-delete property may have prevented us from
                    # deleting the VM. Try again with it unset.
                    set_vm_property(vmpath, 'run-pre-delete', '')
                    xenmgr_unrestricted.unrestricted_delete_vm(client_uuid)

    return have

def delete_unused_disks(disks):
    """Remove any disks and local deltas owned by this synchronizer but not
       listed in disks"""
    disk_set = set([disk['diskuuid'] for disk in disks])
    for name in ICBINN_STORAGE.listdir(DISK_DIR):
        log.info('considering disk file %s', name)
        split_name = name.split('.', 1)
        split_base = split_name[0].split('_')
        if (len(split_name) < 2 or
            split_name[1] not in (DISK_TYPES +
                                  [x + '.partial' for x in DISK_TYPES]) or
            split_base[0] not in disk_set):
            log.info('deleting old disk file %s', name)
            ICBINN_STORAGE.unlink(join(DISK_DIR, name))
        else:
            log.info('retaining disk %s', name)

def arrange_disk_backing_files(disks, download, disk_progress_callback=None):
    """Ensure that disks have been downloaded and key files created"""
    delete_unused_disks(disks)

    diskinfo = {}

    for disk in disks:
        log.info("synchronizing disk %r", redact_disk(disk))
        nbytes, destination_rel, just_created = \
            ensure_disk_downloaded(disk, download, 
                                   ICBINN_STORAGE, disk_progress_callback)
        if just_created:
            enckey = disk.get('encryption_key')
            if enckey:
                place_vhd_key(destination_rel, decode_encryption_key(
                        enckey), mark_vhd=False)

        diskinfo[disk['diskuuid']] = nbytes

    return diskinfo

class VmProgress:
    def __init__(self, vm_target, vm_now, disk_target, disk_now):
        self.vm_target = vm_target
        self.vm_now = vm_now
        self.disk_target = dict( [(x['diskuuid'], x) for x in disk_target])
        self.disk_now = disk_now
        self.prev_report_t = None

    def update(self, disk, partial):
        now_t = time()
        if (self.prev_report_t is not None and
            now_t <= self.prev_report_t + PROGRESS_INTERVAL):
            return

        self.prev_report_t = now_t
        for vm in self.vm_target:
            vmpath = self.vm_now.get(vm['vm_instance_uuid'])
            if vmpath:
                have = 0
                total = 0
                for adisk in vm['disks']:
                    adiskobj = self.disk_target[adisk['diskuuid']]
                    total += adiskobj['size']
                    if disk['diskuuid'] == adiskobj['diskuuid']:
                        here = partial
                    else:
                        if adisk['diskuuid'] in self.disk_now:
                            here = adiskobj['size']
                        else:
                            here = 0
                    have += here
                perc = int(have*100.0 / total) if total else 100
                log.info("VM %s(%s) %d%% %d/%d", 
                         vm['name'], vm['vm_instance_uuid'], 
                         perc, have, total)
                set_vm_property(vmpath, 'download-progress', 
                                -1 if vm.get('removed') else perc)
    def finish(self):
        for vm in self.vm_target:
            vmpath = self.vm_now.get(vm['vm_instance_uuid'])
            set_vm_property(vmpath, 'download-progress', 100)
                        
def work_toward_state(state, download, device_uuid, sync_role, sync_name):
    """Work toward getting this machine into state.

    download is a callback that transfers a file from
    the web server to a specified location."""
    censor_vm_config(state, sync_role)
    cstate = {}
    myconfig = MyConfig({'use-pseudorandomness':False})
    if sync_role == SYNC_ROLE_PLATFORM:
        arrange_license(state['license'], device_uuid)
        arrange_device(myconfig, state['config'])
        cstate['release'], cstate['build'] = arrange_xc_version(
            state['repo'], download)

    # find out what disks we have
    already_disks = arrange_disk_backing_files(state['disks'], None)

    # get VMs ready with no disks
    have = arrange_vms(myconfig, state['vms'], state['disks'], sync_name,
                       already_disks, delete=False)

    # download disks
    vmprog = VmProgress(state['vms'], have, state['disks'], 
                        already_disks)
    cstate['disks'] = arrange_disk_backing_files(
        state['disks'], download,
        disk_progress_callback=vmprog.update)
    vmprog.finish()
    # populate disks in VMs
    arrange_vms(myconfig, state['vms'], state['disks'], sync_name,
                cstate['disks'])

    log.info('reached target state')
    return cstate

def censor_vm_config(state, sync_role):
    """Remove any vm config items which could subvert our attempts to label
       the vm with the correct realm, synchronizer uuid and so on. If this
       isn't the platform synchronizer, also remove any vm config items that
       only the platform synchronizer is allowed to set."""

    for vm in state['vms']:
        new_config = []
        for item in vm['config']:
            if (item['daemon'] == 'vm' and
                item['key'] in VM_CENSORED_PROPERTIES):
                log.warning('skipping vm config item %r for vm instance %s',
                            item, vm['vm_instance_uuid'])
            elif (sync_role == SYNC_ROLE_REALM and
                  item['daemon'] == 'vm' and
                  item['key'].startswith('run-')):
                log.warning('skipping vm config item %r for vm instance %s '
                            'for realm synchronizer',
                            item, vm['vm_instance_uuid'])
            else:
                new_config.append(item)
        vm['config'] = new_config

def decode_boolean(text):
    """Decode a boolean from a string"""
    return text.lower() in ['t', 'true', '1', 'y', 'yes', 'enable']

def set_config(config, daemons):
    """Configure daemons.

    daemons is either a dictionary mapping daemon names to (get, set) callbacks
    or a function that takes a daemon name and returns (get,set) callbacks or None 
    if that daemon name is not supported."""
    if config is None:
        return
    for item in config:
        if type(daemons) == type({}):
            daemon_control = daemons.get(item.get('daemon'))
        else:
            daemon_control = daemons(item.get('daemon'))
        if not daemon_control:
            raise TargetStateError('no support for daemon in %s' % item)
        if 'key' not in item:
            raise TargetStateError('no key in %s' % item)
        if 'value' not in item:
            raise TargetStateError('value not in %s' % item)

        if not daemon_control[0]:
            # Daemon is known but can't be configured at this point.
            log.info('skipping %s', item)
            continue
        
        try:
            current = daemon_control[0](item['key'])
        except DBusException as exc:
            raise PlatformError('unable to get property %s: %s' % (item, exc))
        log.info('item %r current value %r (%r)' % 
                 (item, current, type(current)))

        if isinstance(current, String):
            value = item['value']
        elif isinstance(current, Boolean) or type(current) == type(True):
            value = decode_boolean(item['value'])
        elif isinstance(current, Int32):
            try:
                value = int(item['value'])
            except ValueError:
                raise TargetStateError('invalid integer value %r' % item)
        else: 
            value = item['value']
        log.info('item %r current value %r (%r) new value %r (%r) %s',
                 item, current, type(current), value, type(value), 
                 'MATCH' if current == value else 'DIFFERENT')
        if current != value:
            daemon_control[1](item['key'], value)
            log.info('set %s', item)
        else:
            log.info('already have %s', item)

def parse_args():
    """Parse command-line arguments"""
    parser = ArgumentParser()

    parser.add_argument("-d", "--debug",
                        action="store_true",
                        help="output debugging messages")

    parser.add_argument("sync_name",
                        metavar="SYNCHRONIZER_NAME")

    return parser.parse_args()

def init_logging(sync_name, debug):
    formatter = Formatter(basename(argv[0]) +
                          "[" + sync_name + "]: %(message)s")

    syslog = SysLogHandler("/dev/log", SysLogHandler.LOG_DAEMON)
    syslog.setFormatter(formatter)
    log.addHandler(syslog)

    stream = StreamHandler()
    stream.setFormatter(formatter)
    log.addHandler(stream)

    if debug:
        log.setLevel(DEBUG)
    else:
        log.setLevel(INFO)

class Domstore:
    """Context manager for DomstoreConfig"""
    def __enter__(self):
        self.domstore = DomstoreConfig()
        return self.domstore

    def __exit__(self, *_):
        self.domstore.clean_up()

class DomstoreConfig:
    """Persistent sync-client configuration"""
    def __init__(self):
        db = open_db()
        self.url = self.read_key(db, "url")
        self.device_uuid = self.read_key(db, "device-uuid")
        self.secret = self.read_key(db, "secret")

        self.role = self.read_key(db, "role", SYNC_ROLE_PLATFORM)
        if self.role not in SYNC_ROLES:
            raise ConfigError("domstore key '%s' value '%s' is invalid; valid "
                              "options: %s" % ("role", self.role,
                                               ", ".join(SYNC_ROLES)))

        with NamedTemporaryFile(delete=False) as f:
            f.write(self.read_key(db, "cacert"))
            self.cacert_file = f.name

    def read_key(self, db, key, default=None):
        value = db.read(key)
        if value != "":
            return value
        if default is not None:
            return default
        raise ConfigError("domstore key '%s' not set" % key)

    def clean_up(self):
        unlink(self.cacert_file)

class MyConfig:
    """Transient sync-configuration
    (for the duration of one instance of this program only) """
    def __init__(self, defaults):
        """Store default configuration"""
        self.config = dict(defaults)
    def get(self, key):
        """Read config"""
        return self.config[key]
    def set(self, key, value):
        """Write config"""
        self.config[key] = value

def redact_disk(d):
    """ takes a disk description d (dictionary), and returns
    a shallow copy with sensitive data removed."""
    if d is None:
        return None
    d = d.copy()
    if d.get('encryption_key'):
        d['encryption_key'] = '<redacted>'
    return d

def redact_target_state(ts):
    """ takes a target state ts (dictionary), and returns
    a shallow copy with sensitive data removed."""
    ts = ts.copy()

    ts['disks'] = [redact_disk(d) for d in ts['disks']]
    return ts

def main():
    """Entry point code"""
    
    args = parse_args()
    init_logging(args.sync_name, args.debug)
    log.info("client starting")
    try:
        setup_icbinn()
        log.info("contacted icbinn")
        with Domstore() as domstore:
            server = HTTPServer(domstore.url, domstore.device_uuid,
                                domstore.secret, domstore.cacert_file)
            hello = loads(server.operation('get', 'hello/1'))
            log.info('we said hello; server said %r' % hello)
            if hello.get('server_version') != 1:
                raise ServerVersionError('unsupported server version in %r' %
                                         hello)
            cstate = {}
            def report(status):
                cstate['status'] = status
                log.info('reporting current state with status '+ str(status))
                try:
                    server.operation('put', 'current_state', data=dumps(cstate))
                except HTTPError as exc:
                    log.warning('HTTP failure putting current_state on '
                                'server: %s', exc)
            try:
                state = loads(server.operation('get', 'target_state'))
                log.info('target state=%s', redact_target_state(state))
                cstate = work_toward_state(state, server.download,
                                           domstore.device_uuid, domstore.role,
                                           args.sync_name)
                log.info('making okay status report')
                report(STATUS_OKAY)
                log.info('done')
            except Error as exc:
                report(STATUS_FAILED)
                raise
            except Exception:
                report(STATUS_INTERNAL_EXCEPTION)
                raise
    except Error as exc:
        for line in format_exc().split('\n'):
            log.error("error: %s", line)
        log.error("error: %s", exc)
        exit(exc.exit_code)
    except Exception:
        for line in format_exc().split('\n'):
            log.error("crash: %s", line)
        exit(3)
