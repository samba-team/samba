import re, os.path, hashlib

class gp_file_append:
    def __init__(self, filename, comment='#'):
        self.filename = filename
        self.section = \
          '%s\n%s Samba GPO Section\n%s These settings are applied via GPO\n' \
            % (comment, comment, comment)
        self.section_end = '%s\n%s End Samba GPO Section\n%s\n' \
            % (comment, comment, comment)
        self.checksum = None

    def __get_file_data(self):
        if not os.path.exists(os.path.dirname(self.filename)):
            raise Exception('path %s not found' % \
                os.path.dirname(self.filename))
        if os.path.exists(self.filename):
            data = open(self.filename, 'r').read()
        else:
            data = ''
        checksum = hashlib.sha256(data).digest()
        return (data, checksum)

    def __set_data_pointers(self):
        try:
            self.start = re.finditer(self.section, self.data).next()
            self.end = re.finditer(self.section_end, self.data).next()
        except:
            self.start = None
            self.end = None

    def get_section(self):
        self.data, self.checksum = self.__get_file_data()

        # Get the current applied contents (if any)
        current = ''
        self.__set_data_pointers()
        if self.start and self.end:
            current = self.data[self.start.end():self.end.start()]
        return current

    def set_section(self, results):
        _, checksum = self.__get_file_data()
        if checksum != self.checksum:
            raise Exception('%s was modified elsewhere, checksum failed' % \
                self.filename)
        if results.strip():
            results = self.section + '\n' + results + '\n' + self.section_end
            if self.start and self.end:
                ndata = self.data[:self.start.start()] + results + \
                    self.data[self.end.end():]
            else:
                ndata = self.data + results
        else: # Remove the GPO section if all settings are removed
            if self.start and self.end:
                ndata = self.data[:self.start.start()] + \
                    self.data[self.end.end():]
            else:
                ndata = self.data
        open(self.filename, 'w').write(ndata)
        self.data, self.checksum = self.__get_file_data()
        self.__set_data_pointers()

class ini_file_append:
    def __init__(self, filename):
        self.modified = False
        self.append = gp_file_append(filename)
        self.vals = self.__get_section()

    def keys(self):
        return self.vals.keys()

    def __get_section(self):
        return {
            l.split('=')[0]: l.split('=')[-1] \
                for l in self.append.get_section().strip().split('\n')
        }

    def __set_section(self):
        results = '\n'.join([
            '%s=%s' % (key, val) \
                for key, val in self.vals.items() if key
        ])
        self.append.set_section(results)

    def __getitem__(self, key):
        if key in self.vals.keys():
            return self.vals[key]
        else:
            return None

    def __setitem__(self, key, val):
        self.modified = True
        self.vals[key] = val

    def __delitem__(self, key):
        self.modified = True
        if key in self.vals.keys():
            del self.vals[key]

    def __del__(self):
        if self.modified:
            self.__set_section()
