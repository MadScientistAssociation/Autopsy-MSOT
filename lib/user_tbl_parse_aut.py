import binascii
from misc_functions_aut import *

class userTable:

    def __init__(self, infile_content):

        self.infile_content = infile_content

        # self.entries format is
        # [last modified, username, domain NetBios (short) name,
        #         0          1                   2
        # machine name, domain/workgroup name, telemetry agent version,
        #       3                4                       5
        # network share upload path, machine hardware specs, # of processors,
        #         6                         7                    8
        # CPU architecture, RAM, screen resolution, OS version, OS language ID,
        #        9          10          11              12            13
        # IE version
        #    14
        self.entries = []

    def parse_entries(self):

        ''' Search the file for locations of table entries. '''
        doc_length = len(self.infile_content)

        # File last modified timestamp
        last_mod = self.infile_content[36:44]
        last_mod_timestamp = binascii.hexlify(last_mod)
        self.entries.append(convert_time(last_mod_timestamp))

        # User account name (user principal name prefix)
        user_name = self.infile_content[44:558]
        user_name = utf16decode(user_name)
        self.entries.append(user_name)

        # Legacy domain name
        short_domain = self.infile_content[558:1110]
        short_domain = utf16decode(short_domain)
        self.entries.append(short_domain)

        # NetBIOS hostname
        machine_name = self.infile_content[1124:1156]
        machine_name = utf16decode(machine_name)
        self.entries.append(machine_name)

        # DNS domain name without hostname
        full_domain = self.infile_content[1156:1670]
        full_domain = utf16decode(full_domain)
        self.entries.append(full_domain)

        # Telemetry agent version, stored in tuple (major.minor, revision, build)
        # Minor
        min_version = self.infile_content[1668:1670]
        min_version = int(binascii.hexlify(min_version), 16)
        # Major
        max_version = self.infile_content[1670:1672]
        max_version = int(binascii.hexlify(max_version), 16)
        full_version = "%s.%s" % (max_version, min_version)
        # Revision
        revision = self.infile_content[1672:1674]
        revision = int(binascii.hexlify(revision), 16)
        # Build
        build = self.infile_content[1674:1676]
        build = int(binascii.hexlify(build), 16)
        self.entries.append((full_version, revision, build))

        # Network share where telemetry data is uploaded
        netshare = self.infile_content[1676:2196]
        netshare = utf16decode(netshare)
        self.entries.append(netshare)

        # Hardware specs
        specs = self.infile_content[2196:2356]
        specs = utf16decode(specs)
        self.entries.append(specs)

        # Number of processors in machine running telemetry agent,
        # Stored as a typle (logical, physical)
        # Number of logical processors
        log_proc = self.infile_content[2356:2360]
        log_proc = int(binascii.hexlify(log_proc), 16)
        # Number of physical processors
        phys_proc = self.infile_content[2360:2364]
        phys_proc = int(binascii.hexlify(phys_proc), 16)
        self.entries.append((log_proc, phys_proc))

        # CPU architecture
        cpu = self.infile_content[2364:2368]
        cpu = int(binascii.hexlify(cpu), 16)
        self.entries.append(cpu)

        # RAM of machine running telemetry agent
        ram = self.infile_content[2368:2372]
        ram = int(binascii.hexlify(ram), 16)
        self.entries.append(ram)

        # Screen resolution of machine running telemetry agent, stored as (width, height)
        # Height
        scr_height = self.infile_content[2372:2376]
        scr_height = int(binascii.hexlify(scr_height), 16)
        # Width
        scr_width = self.infile_content[2376:2380]
        scr_width = int(binascii.hexlify(scr_width), 16)
        self.entries.append((scr_width, scr_height))

        # Operating system version, stored in tuple (major.minor, product type, build)
        # Minor
        minor = self.infile_content[2380:2382]
        minor = int(binascii.hexlify(minor), 16)
        # Major
        major = self.infile_content[2382:2384]
        major = int(binascii.hexlify(major), 16)
        osversion = "%s.%s" % (major, minor)
        # Product Type
        prodtype = self.infile_content[2384:2386]
        prodtype = int(binascii.hexlify(prodtype), 16)
        # Build
        osbuild = self.infile_content[2386:2388]
        osbuild = int(binascii.hexlify(osbuild), 16)
        self.entries.append((osversion, prodtype, osbuild))

        # OS default language ID (default ID, default UI ID)
        # Default UI language ID
        defuilang = self.infile_content[2388:2390]
        defuilang = int(binascii.hexlify(defuilang), 16)
        # Default language ID
        deflang = self.infile_content[2392:2394]
        deflang = int(binascii.hexlify(deflang), 16)
        self.entries.append((deflang, defuilang))

        # Internet Explorer version on machine running telemetry agent
        # Stored (major.minor, revision, build)
        # Minor
        ieminor = self.infile_content[2396:2398]
        ieminor = int(binascii.hexlify(ieminor), 16)
        # Major
        iemajor = self.infile_content[2398:2400]
        iemajor = int(binascii.hexlify(iemajor), 16)
        ieversion = "%s.%s" % (iemajor, ieminor)
        # Revision
        ierev = self.infile_content[2400:2402]
        ierev = int(binascii.hexlify(ierev), 16)
        # Build
        #iebuild = self.infile_content[2404:2404]
        #iebuild = int(iebuild.encode('hex'), 16)
        self.entries.append((ieversion, ierev))#, iebuild))
