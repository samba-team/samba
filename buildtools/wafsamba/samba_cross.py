# functions for handling cross-compilation

import os, sys, re, shlex
from waflib import Utils, Logs, Options, Errors, Context
from waflib.Configure import conf
from wafsamba import samba_utils

real_Popen = None

ANSWER_UNKNOWN = (254, "")
ANSWER_NO      = (1, "")
ANSWER_OK      = (0, "")

cross_answers_incomplete = False


def add_answer(ca_file, msg, answer):
    '''add an answer to a set of cross answers'''
    try:
        f = open(ca_file, 'a')
    except:
        Logs.error("Unable to open cross-answers file %s" % ca_file)
        sys.exit(1)
    (retcode, retstring) = answer
    # if retstring is more than one line then we probably
    # don't care about its actual content (the tests should
    # yield one-line output in order to comply with the cross-answer
    # format)
    retstring = retstring.strip()
    if len(retstring.split('\n')) > 1:
        retstring = ''
    answer = (retcode, retstring)

    if answer == ANSWER_OK:
        f.write('%s: OK\n' % msg)
    elif answer == ANSWER_UNKNOWN:
        f.write('%s: UNKNOWN\n' % msg)
    elif answer == ANSWER_NO:
        f.write('%s: NO\n' % msg)
    else:
        if retcode == 0:
            f.write('%s: "%s"\n' % (msg, retstring))
        else:
            f.write('%s: (%d, "%s")\n' % (msg, retcode, retstring))
    f.close()


def cross_answer(ca_file, msg):
    '''return a (retcode,retstring) tuple from a answers file'''
    try:
        f = open(ca_file, 'r')
    except:
        return ANSWER_UNKNOWN
    for line in f:
        line = line.strip()
        if line == '' or line[0] == '#':
            continue
        if line.find(':') != -1:
            a = line.split(':', 1)
            thismsg = a[0].strip()
            if thismsg != msg:
                continue
            ans = a[1].strip()
            if ans == "OK" or ans == "YES":
                f.close()
                return ANSWER_OK
            elif ans == "UNKNOWN":
                f.close()
                return ANSWER_UNKNOWN
            elif ans == "FAIL" or ans == "NO":
                f.close()
                return ANSWER_NO
            elif ans[0] == '"':
                f.close()
                return (0, ans.strip('"'))
            elif ans[0] == "'":
                f.close()
                return (0, ans.strip("'"))
            else:
                m = re.match('\(\s*(-?\d+)\s*,\s*\"(.*)\"\s*\)', ans)
                if m:
                    f.close()
                    return (int(m.group(1)), m.group(2))
                else:
                    raise Errors.WafError("Bad answer format '%s' in %s" % (line, ca_file))
    f.close()
    return ANSWER_UNKNOWN


class cross_Popen(Utils.subprocess.Popen):
    '''cross-compilation wrapper for Popen'''
    def __init__(*k, **kw):
        (obj, args) = k
        use_answers = False
        ans = ANSWER_UNKNOWN

        # Three possibilities:
        #   1. Only cross-answers - try the cross-answers file, and if
        #      there's no corresponding answer, add to the file and mark
        #      the configure process as unfinished.
        #   2. Only cross-execute - get the answer from cross-execute
        #   3. Both - try the cross-answers file, and if there is no
        #      corresponding answer - use cross-execute to get an answer,
        #       and add that answer to the file.
        if '--cross-answers' in args:
            # when --cross-answers is set, then change the arguments
            # to use the cross answers if available
            use_answers = True
            i = args.index('--cross-answers')
            ca_file = args[i+1]
            msg     = args[i+2]
            ans = cross_answer(ca_file, msg)

        if '--cross-execute' in args and ans == ANSWER_UNKNOWN:
            # when --cross-execute is set, then change the arguments
            # to use the cross emulator
            i = args.index('--cross-execute')
            newargs = shlex.split(args[i+1])
            newargs.extend(args[0:i])
            if use_answers:
                p = real_Popen(newargs,
                               stdout=Utils.subprocess.PIPE,
                               stderr=Utils.subprocess.PIPE,
                               env=kw.get('env', {}))
                ce_out, ce_err = p.communicate()
                ans = (p.returncode, samba_utils.get_string(ce_out))
                add_answer(ca_file, msg, ans)
            else:
                args = newargs

        if use_answers:
            if ans == ANSWER_UNKNOWN:
                global cross_answers_incomplete
                cross_answers_incomplete = True
                add_answer(ca_file, msg, ans)
            (retcode, retstring) = ans
            args = ['/bin/sh', '-c', "echo -n '%s'; exit %d" % (retstring, retcode)]
        real_Popen.__init__(*(obj, args), **kw)


@conf
def SAMBA_CROSS_ARGS(conf, msg=None):
    '''get test_args to pass when running cross compiled binaries'''
    if not conf.env.CROSS_COMPILE:
        return []

    global real_Popen
    if real_Popen is None:
        real_Popen  = Utils.subprocess.Popen
        Utils.subprocess.Popen = cross_Popen
        Utils.run_process = Utils.run_regular_process
        Utils.get_process = Utils.alloc_process_pool = Utils.nada

    ret = []

    if conf.env.CROSS_EXECUTE:
        ret.extend(['--cross-execute', conf.env.CROSS_EXECUTE])

    if conf.env.CROSS_ANSWERS:
        if msg is None:
            raise Errors.WafError("Cannot have NULL msg in cross-answers")
        ret.extend(['--cross-answers', os.path.join(Context.launch_dir, conf.env.CROSS_ANSWERS), msg])

    if ret == []:
        raise Errors.WafError("Cannot cross-compile without either --cross-execute or --cross-answers")

    return ret

@conf
def SAMBA_CROSS_CHECK_COMPLETE(conf):
    '''check if we have some unanswered questions'''
    global cross_answers_incomplete
    if conf.env.CROSS_COMPILE and cross_answers_incomplete:
        raise Errors.WafError("Cross answers file %s is incomplete" % conf.env.CROSS_ANSWERS)
    return True
