#!/usr/bin/python

# meta-test-case / example for comfychair.  Should demonstrate
# different kinds of failure.

import comfychair, stf

class NormalTest(comfychair.TestCase):
    def runTest(self):
        pass

class RootTest(comfychair.TestCase):
    def setUp(self):
        self.require_root()
            
    def runTest(self):
        pass

class GoodExecTest(comfychair.TestCase):
    def runTest(self):
        exit, stdout = self.runCmdUnchecked("ls -l")

class BadExecTest(comfychair.TestCase):
    def setUp(self):
        exit, stdout = self.runCmdUnchecked("spottyfoot --slobber",
                                            skip_on_noexec = 1)

comfychair.runtests([NormalTest, RootTest, GoodExecTest, BadExecTest])
