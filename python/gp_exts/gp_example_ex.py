from samba.gpclass import gp_ext, file_to

# When placed in one of the respective machine or user sub-directoriers,
# a python file defining a class inheriting from gp_ext() will be automatically
# imported and loaded by the samba_gpoupdate script and applied on the gpupdate
# interval.

class example_setter(file_to):
    '''An example setter class, which must inherit from file_to
    The mapper() and __str__() functions are mandatory, the rest of the
    implementation is arbitrary.
    '''

    def set_int(self, val):
        example = open('/etc/example.conf', 'w')
        example.write('%s = %d\n' % (self.attr, val))
        example.close()

    def set_str(self, val):
        example = open('/etc/example.conf', 'w')
        example.write('%s = %s\n' % (self.attr, val))
        example.close()

    def to_int(self):
        return int(self.val)

    def mapper(self):
        '''
        Maps local setting names to an apply function, and a value converter.
        The self.explicit converter causes the original value to be used,
        without conversion.
        '''
        return { "LinuxSettingInt" : (self.set_int, self.to_int),
                 "LinuxSettingStr" : (self.set_str, self.explicit),
               }

    def __str__(self):
        '''
        The name of the setter, as seen in the apply_map() keys.
        '''
        return "Example"

class gp_example_ex(gp_ext):
    '''An example group policy extension, which must inhert from gp_ext
    A group policy extension reads policies from the sysvol, and applies them
    as settings to the local machine.
    '''

    def __str__(self):
        '''
        Must return a unique extension name for identifying the extension
        '''
        return "Example extension"

    def read(self, policy):
        '''
        Receives the policy file as a string, and must parse and apply the
        policy using the setters returned by the apply_map() function.
        Alteratively, your class could inherit from gp_inf_ext() if reading a
        ini/inf file (common for gpos) and this function is implemented for
        you.
        '''
        mappings = self.apply_map()

        # Policies are all on seperate lines, space delimited
        for line in policy.split('\n'):
            (key, value) = line.split()
            (att, setter) = mappings['Example'].get(key)
            setter(self.logger,
                   self.ldb,
                   self.gp_db,
                   self.lp,
                   self.creds,
                   att,
                   value).update_samba()
            # gp_db.commit() saves the unapply log, this is mandatory
            self.gp_db.commit()

    def list(self, rootpath):
        '''
        This function must return the sysvol path to a policy file to be read
        '''
        return os.path.join(rootpath, "MACHINE/SomeGPfile.txt")

    def apply_map(self):
        '''
        The apply_map must return a dictionary of dictionaries. The first key
        "Example" is the name of the setter class. The inner keys
        "MSSettingName1", etc are the gpo value of the setting being applied.
        The value tuple contains the name of the local setting, and the
        setter class. The setter class is used within the read() function to
        convert and apply settings.
        '''
        return { "Example" : { "MSSettingName1":
                                    ("LinuxSettingInt", example_setter),
                               "MSSettingName2":
                                    ("LinuxSettingStr", example_setter),
                             }
               }

    @classmethod
    def enabled(cls):
        '''
        This function must be included in every extension.
        It returns a boolean that determines whether this policy extension
        is enabled. Here you should check for the existence of a .disabled
        file, and possibly perform other checks (such as whether this is a
        kdc, or a client machine, etc).
        '''
        disabled_file = \
            os.path.splitext(os.path.abspath(__file__))[0] + '.py.disabled'
        return not os.path.exists(disabled_file)

