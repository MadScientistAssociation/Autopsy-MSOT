import binascii
from misc_functions_aut import *

class evtTable:

    def __init__(self, infile_content, objId):
        self.infile_content = infile_content
        self.objId = objId

        # dict containing information about each table entry
        self.entries = {}
        # entries structure is:
            # key: offset
            # value: list [entry_num,  timestamp 1, event_id, event_desc, GUID, timestamp 2, Autopsy object ID]
            #                 0            1          2         3          4         5              6

        # dict containing definitions for the event_id codes. These are listed in full at:
        # https://msdn.microsoft.com/en-us/library/office/jj230106.aspx
        self.event_codes = {
            1: "Document loaded successfully",
            2: "Document failed to load",
            3: "Template loaded successfully",
            4: "Template failed to load",
            5: "Add-in loaded successfully",
            6: "Add-in failed to load",
            7: "Add-in manifest downloaded successfully",
            8: "Add-in manifest did not download",
            9: "Add-in manifest could not be parsed",
            10:"Add-in used too much CPU",
            11:"Application crashed on load",
            12:"Application closed due to a problem",
            13:"Document closed successfully",
            14:"Application session extended",
            15:"Add-in disabled due to string search time-out",
            16:"Document open when applcation crashed",
            17:"Add-in closed successfully",
            18:"App closed successfully",
            19:"Add-in encountered runtime error",
            20:"Add-in failed to verify licensing"
        }

    def parse_entries(self):

        doc_length = len(self.infile_content)
        byte = 40 # Start reading the evt file at the first entry

        # Search through the file content in memory, looking for the table entries.
        while(byte < doc_length):

            # The first field is block length, which is always 156
            # No need to store this field
            offset = byte + 4
            self.entries[offset] = []

            # The entry number is the second byte
            entry_num = self.infile_content[byte+4:byte+5]
            self.entries[offset].append(int(binascii.hexlify(entry_num), 16))

            # Timestamp at offsets 24 - 31
            timestamp1 = self.infile_content[byte+24:byte+32]
            timestamp1_hex = binascii.hexlify(timestamp1)
            self.entries[offset].append(convert_time(timestamp1_hex))

            # The event ID is at offset 36 (one byte)
            event_id = (int(binascii.hexlify(self.infile_content[byte+36:byte+37]), 16))
            self.entries[offset].append(event_id)
            # Event ID can be mapped to a text description in self.event_codes
            if event_id in self.event_codes:
                event_desc = self.event_codes[event_id]
            else:
                event_desc = 'Unknown'
            self.entries[offset].append(event_desc)

            # The GUID is offsets 40-55
            self.entries[offset].append(binascii.hexlify(self.infile_content[byte+40:byte+56]))

            # Timestamp at offsets 136 - 143
            timestamp2 = self.infile_content[byte+136:byte+144]
            timestamp2_hex = binascii.hexlify(timestamp2)
            self.entries[offset].append(convert_time(timestamp2_hex))
            self.entries[offset].append(self.objId)

            byte += 156 # Jump to next entry
