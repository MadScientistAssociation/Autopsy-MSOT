
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Simple file-level ingest module for Autopsy.
# Search for TODO for the things that you need to change
# See http://sleuthkit.org/autopsy/docs/api-docs/3.1/index.html for documentation

import jarray
import inspect
import StringIO
import binascii
from datetime import datetime
from java.lang import System
from java.util.logging import Level
from jarray import zeros
from java.text import SimpleDateFormat
from java.util import Date
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from lib.sln_tbl_parse27 import *
from lib.evt_tbl_parse27 import *
from lib.user_tbl_parse27 import *
from lib.misc_functions27 import *

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
class MSOfficeTelemProcessFactory(IngestModuleFactoryAdapter):

    moduleName = "MS Office Telemetry Parser"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Parses file activity entries from Microsoft Office telemetry log files."

    def getModuleVersionNumber(self):
        return "1.0"

    # TODO:  Check This
    # Return true if module wants to get called for each file
    def isDataSourceIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createDataSourceIngestModule(self, ingestOptions):
        return MSOfficeTelemProcesser()


# Data source ingest module.  One gets created per data source.
class MSOfficeTelemProcesser(DataSourceIngestModule):

    _logger = Logger.getLogger(MSOfficeTelemProcessFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # TODO: Add any setup code that you need hereselfselfself.
    def startUp(self, context):
        self.context = context

        # TODO: Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # TODO: Add your analysis code in here.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Use FileManager to get .tbl files
        # Currently only checking for files in a parent folder whose namee contains "Telemetry"
        # to get the standard %USERPROFILE%/AppData/Locaaal/Microsoft/Ofice/16.0/Telemetry
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        sln_tbl_files = fileManager.findFiles(dataSource, "sln.tbl")
        evt_tbl_files = fileManager.findFiles(dataSource, "evt.tbl")
        usr_tbl_files = fileManager.findFiles(dataSource, "user.tbl")

        # Build a dict correlating each AbstractFile object and its Autopsy object ID
        tbl_file_dict = {}
        if (len(sln_tbl_files) > 0 and len(evt_tbl_files) > 0 and len(usr_tbl_files) > 0):
            for file in sln_tbl_files:
                tbl_file_dict[file.getId()] = file
            for file in evt_tbl_files:
                tbl_file_dict[file.getId()] = file
            for file in usr_tbl_files:
                tbl_file_dict[file.getId()] = file

        # Get total # of files for the progress bar
        numFiles = (len(sln_tbl_files) + len(evt_tbl_files) + len(usr_tbl_files))
        self.log(Level.INFO, "Found " + str(numFiles) + " Office telemetry files")
        progressBar.switchToDeterminate(numFiles)
        artifactCount = 0

        files_to_analyze = correlate_tbl_files(sln_tbl_files, evt_tbl_files, usr_tbl_files)

        for tbl_set in files_to_analyze:

            sln_object = tbl_file_dict[tbl_set[0]]
            evt_object = tbl_file_dict[tbl_set[1]]
            usr_object = tbl_file_dict[tbl_set[2]]

            # Read the contents of each file into Java zeros object
            sln_size = int(sln_object.getSize())
            sln_buffer = zeros(sln_size, 'b')
            sln_object.read(sln_buffer, 0, sln_size)

            evt_size = int(evt_object.getSize())
            evt_buffer = zeros(evt_size, 'b')
            evt_object.read(evt_buffer, 0, evt_size)

            usr_size = int(sln_object.getSize())
            usr_buffer = zeros(usr_size, 'b')
            usr_object.read(usr_buffer, 0, usr_size)

            # Ensure the .tbl files are valid Office telemetry files
            if validate_tbl_format(sln_buffer) != 'sln':
                continue
            if validate_tbl_format(evt_buffer) != 'evt':
                continue
            if validate_tbl_format(usr_buffer) != 'user':
                continue

            # If the tables have validated, parse them
            sln_table = slnTable(sln_buffer)
            sln_table.parse_entries()
            evt_table = evtTable(evt_buffer, evt_object.getId())
            evt_table.parse_entries()
            user_table = userTable(usr_buffer)
            user_table.parse_entries()

            # Set some local references for the user data that will be added to the output file
            user = user_table.entries[1]
            host = user_table.entries[3] + "." + user_table.entries[4]

            # docid offsets will be a dict formatted as:
            # docid : [[sln_table_offsets], [evt_table_offsets]]
            docid_offsets = build_entry_dict(sln_table, evt_table)

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            # Create a 2 dimensional list to hold the final entries before writing to file.
            # Each entry will be appended to this list as a sub-list.
            results = []

            for docid in docid_offsets:

                # Get all the sln table values for this document
                # Assume the SLN table does not contain duplicate entries for this.
                doc_path   = (sln_table.entries[docid_offsets[docid][0][0]][3]) + "\\" + (sln_table.entries[docid_offsets[docid][0][0]][2])
                doc_id     = sln_table.entries[docid_offsets[docid][0][0]][1]
                doc_type   = sln_table.entries[docid_offsets[docid][0][0]][0]
                doc_title  = sln_table.entries[docid_offsets[docid][0][0]][4]
                doc_author = sln_table.entries[docid_offsets[docid][0][0]][5]
                addin_name = sln_table.entries[docid_offsets[docid][0][0]][6]
                desc       = sln_table.entries[docid_offsets[docid][0][0]][7]

                # Get the evt table values for this document. There can be multiple entries per docid.
                for entry in range(len(docid_offsets[docid][1])):
                    if entry:
                        timestamp  = evt_table.entries[docid_offsets[docid][1][entry]][5].strftime('%Y-%m-%d %H:%M:%S.%f')
                        entry_num  = evt_table.entries[docid_offsets[docid][1][entry]][0]
                        event_id   = evt_table.entries[docid_offsets[docid][1][entry]][2]
                        event_desc = evt_table.entries[docid_offsets[docid][1][entry]][3]
                        objId      = evt_table.entries[docid_offsets[docid][1][entry]][6]

                        results.append([timestamp, entry_num, event_id, event_desc, doc_id, doc_title, doc_path, doc_type, doc_author, addin_name, desc, user, host, objId])
                        artifactCount += 1

            for result in results:

                # Get the Autopsy object for the evt.tbl that create the artifact
                sourcefile = tbl_file_dict[result[13]]

                # Make an artifact on the blackboard.
                artifact = sourcefile.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_RECENT_OBJECT)
                # Add Path attribute: MS Office document reported by telemetry
                artifact.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID(), MSOfficeTelemProcessFactory.moduleName, result[6]))
                # Add Datetime attribute: time of document open/closed reported by telemetry
                event_datetime = int((datetime.strptime(result[0], "%Y-%m-%d %H:%M:%S.%f") - datetime(1970, 1, 1)).total_seconds())
                artifact.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), MSOfficeTelemProcessFactory.moduleName, event_datetime))
                # Add Description attribute based on event ID
                artifact.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT.getTypeID(), MSOfficeTelemProcessFactory.moduleName, result[3]))


def correlate_tbl_files(sln_tbl_files, evt_tbl_files, usr_tbl_files):

    """ Iterate through lists of .tbl files found on the data source, and group them by
        file path. Returns list of tuples, each tuple is a group of correlated
        .tbl files.

        TODO: Multiple groups of .tbl files in a single directory are going to
        break the parser. """

    # Create dicts with key: path and value: object ID
    sln_dict = {}
    evt_dict = {}
    usr_dict = {}
    for sln_file in sln_tbl_files:
        folderpath = sln_file.getUniquePath()[:-7]
        sln_dict[folderpath] = sln_file.getId()
    for evt_file in evt_tbl_files:
        folderpath = evt_file.getUniquePath()[:-7]
        evt_dict[folderpath] = evt_file.getId()
    for usr_file in usr_tbl_files:
        folderpath = usr_file.getUniquePath()[:-8]
        usr_dict[folderpath] = usr_file.getId()

    # Find common path values across dicts. If path exists in all 3 dicts,
    # add to the common_paths list.
    common_paths = []
    for path in sln_dict:
        if ((path in evt_dict) and (path in usr_dict)):
            common_paths.append(path)

    # Create a list of tuples of correlated .tbl files
    files_to_analyze = []
    for path in common_paths:
        files_to_analyze.append((sln_dict[path], evt_dict[path], usr_dict[path]))

    # Return compiled list
    return(files_to_analyze)


def validate_tbl_format(infile_content):

    ''' Validate file header of .tbl file. First 8 bytes must be 20 00 00 00 53 44 44 54.
        Second 8 bytes determine which file (sln, etv, user). '''

    tbl_type = '' # Will hold type of tbl file

    # Grab the first 8 bytes of the file
    test_block_1 = infile_content[0:8]

    # Header should be 2000000053444454
    if binascii.hexlify(test_block_1) == '2000000053444454':
        print('Valid .tbl file found. Checking tbl type...')
    else:
        sys.exit('Invalid .tbl file!')

    # Test the next 8 bytes to determine the type of .tbl file.
    test_block_2 = infile_content[8:16]
    if binascii.hexlify(test_block_2) == '01000000564e4953':
        tbl_type = 'sln'
    elif binascii.hexlify(test_block_2) == '01000000544e5645':
        tbl_type = 'evt'
    elif binascii.hexlify(test_block_2) == '0100000052455355':
        tbl_type = 'user'

    return(tbl_type)


def build_entry_dict(sln_table, evt_table):

    ''' Build a dict from the entries parsed from sln_table and evt_table, to associate
        each docid with the offsets of entries in both tables. '''

    # docid_offsets is a dict with the format:
    # docid : [[sln_table_offsets], [evt_table_offsets]]
    docid_offsets = {}

    # Build a list of unique docids from the sln table.
    table_entries = set()
    for entry in sln_table.entries:
        table_entries.add(sln_table.entries[entry][1])

    # Add the offsets from the sln table into docid_offsets
    for entry in sln_table.entries:
        if sln_table.entries[entry][1] not in docid_offsets:
            # Add a new entry to docid_offsets. Add the value for this sln entry.
            docid_offsets[sln_table.entries[entry][1]] = [[entry,],[]]
        else:
            # Append the value for this sln entry
            # TODO: It doesn't appear the SLN table will contain duplicate DOCID entries.
            docid_offsets[sln_table.entries[entry][1]][0].append(entry)

    for entry in evt_table.entries:
        if evt_table.entries[entry][4] not in docid_offsets:
            pass
        else:
            docid_offsets[evt_table.entries[entry][4]][1].append(entry)

    return(docid_offsets)
