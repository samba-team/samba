/*
   Unix SMB/CIFS implementation.
   SMB test generator - load and parse test config
   Copyright (C) James Myers 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "gentest.h"

static struct gentest_context_t *contextP;

#define NUMPARAMETERS (sizeof(parm_table) / sizeof(struct parm_struct))

static BOOL do_parameter(const char *pszParmName, const char *pszParmValue);
static BOOL do_section(const char *pszSectionName);

/* prototypes for the special type handlers */
static BOOL handle_tests(const char *pszParmValue, char **ptr);

static BOOL handle_options(const char *pszParmValue, char **ptr);
static BOOL handle_fields(const char *pszParmValue, char **ptr);

static struct enum_list enum_command[] = {
            {
                SMBunlink, "SMBunlink"
            },
            {SMBclose, "SMBclosex"},
            {-1, NULL}
        };
static struct enum_list enum_condition[] = {
            {
                TEST_COND_NEGPROT, "TEST_COND_NEGPROT"
            },
            {TEST_COND_SESSION, "TEST_COND_SESSION"},
            {TEST_COND_TCON, "TEST_COND_TCON"},
            {TEST_COND_FID, "TEST_COND_FID"},
            {-1, NULL}
        };
static struct enum_list enum_test_type[] = {
            {
                testTypeConnected, "Connected"
            },
            {testTypeFilename, "Filename"},
            {testTypeFid, "FID"},
            {-1, NULL}
        };
static struct enum_list enum_options[] = {
            {TEST_OPTION_FILE_EXISTS, "FILE_EXISTS"},
            {TEST_OPTION_FILE_NOT_EXIST, "FILE_NOT_EXIST"},
            {TEST_OPTION_FILE_HIDDEN, "FILE_HIDDEN"},
            {TEST_OPTION_FILE_SYSTEM, "FILE_SYSTEM"},
            {TEST_OPTION_FILE_INVISIBLE, "FILE_INVISIBLE"},
            {TEST_OPTION_FILE_WILDCARD, "FILE_WILDCARD"},
            {TEST_OPTION_FID_INVALID, "FID_INVALID"},
            {TEST_OPTION_FID_VALID, "FID_VALID"},
            {-1, NULL}
        };
static struct enum_list enum_execute[] = {
            {(int)gen_execute_unlink, "gen_execute_unlink"},
            {(int)gen_execute_close, "gen_execute_close"},
            {-1, NULL}
        };
static struct enum_list enum_verify[] = {
                                            {
                                                (int)gen_verify_unlink, "gen_verify_unlink"
                                            },
                                            {(int)gen_verify_close, "gen_verify_close"},
                                            {-1, NULL}
                                        };
static struct enum_list enum_field_type[] = {
            {
                testFieldTypeFilename, "Filename"
            },
            {testFieldTypeFileAttr, "FileAttr"},
            {testFieldTypeFid, "FID"},
            {testFieldTypeMtime, "Mtime"},
            {testFieldTypeTrans2, "Trans2"},
            {-1, NULL}
        };
static struct enum_list enum_function[] = {
            {
                (int)test_field_get_filename, "test_field_get_filename"
            },
            {(int)test_field_get_file_attr, "test_field_get_file_attr"},
            {-1, NULL}
        };

/* Note: We do not initialise the defaults union - it is not allowed in ANSI C
 */
#define GEN_FLAG_GLOBAL 0x0001 /* fundamental options */
#define GEN_FLAG_TEST 	0x0002 /* test options */
#define GEN_FLAG_FIELD 	0x0004 /* field options */

static struct {
    int command;
    char *name;
    int debug;
    int condition;
    int type;
    int options;
    int words;
    struct field_test_spec* fields;
    int field_count;
    void* execute;
    void* verify;
}
test_section;

static struct {
    char *name;
    int type;
    BOOL random;
    int words;
    void * function;
}
field_section;

static struct parm_struct parm_table[] = {
            {"Base Options", P_SEP, P_SEPARATOR
            },
            /* global section parameters */
            {"tests", P_LIST, P_GLOBAL, NULL, handle_tests, NULL, GEN_FLAG_GLOBAL},

            /* test section parameters */
            {"Test section", P_SEP, P_SEPARATOR},
            {"command", P_ENUM, P_LOCAL, &test_section.command, NULL, enum_command, GEN_FLAG_TEST},
            {"name", P_STRING, P_LOCAL, &test_section.name, NULL, NULL, GEN_FLAG_TEST},
            {"debug", P_INTEGER, P_LOCAL, &test_section.debug, NULL, NULL, GEN_FLAG_TEST},
            {"condition", P_ENUM, P_LOCAL, &test_section.condition, NULL, enum_condition, GEN_FLAG_TEST},
            {"type", P_ENUM, P_LOCAL, &test_section.type, NULL, enum_test_type, GEN_FLAG_TEST},
            {"options", P_LIST, P_LOCAL, &test_section.options, handle_options, NULL, GEN_FLAG_TEST},
            {"word count", P_INTEGER, P_LOCAL, &test_section.words, NULL, NULL, GEN_FLAG_TEST},
            {"fields", P_LIST, P_LOCAL, NULL, handle_fields, NULL, GEN_FLAG_TEST},
            {"execute", P_ENUM, P_LOCAL, &test_section.execute, NULL, enum_execute, GEN_FLAG_TEST},
            {"verify", P_ENUM, P_LOCAL, &test_section.verify, NULL, enum_verify, GEN_FLAG_TEST},

            /* field section parameters */
            {"Field section", P_SEP, P_SEPARATOR},
            {"type", P_ENUM, P_LOCAL, &field_section.type, NULL, enum_field_type, GEN_FLAG_FIELD},
            {"random", P_BOOL, P_LOCAL, &field_section.random, NULL, NULL, GEN_FLAG_FIELD},
            {"word count", P_INTEGER, P_LOCAL, &field_section.words, NULL, NULL, GEN_FLAG_FIELD},
            {"function", P_ENUM, P_LOCAL, &field_section.function, NULL, enum_function, GEN_FLAG_FIELD},

            {NULL, P_BOOL, P_NONE, NULL, NULL, NULL, 0}
        };

static BOOL handle_tests(const char *pszParmValue, char **ptr) {
    contextP->testNames = str_list_make(pszParmValue, NULL);
    return True;
}
static BOOL handle_options(const char *pszParmValue, char **ptr) {
    /* convert option names (in enum_options) to flags */
    char **str_array;

    str_array = str_list_make(pszParmValue, NULL);

    if (str_array) {
        size_t i, j;
        for ( j = 0; str_array[j] != NULL; j++) {
            BOOL optionValid = False;
            for (i = 0; enum_options[i].name; i++) {
                if (strequal(str_array[j],
                             enum_options[i].name)) {
                    *(int *)ptr |= enum_options[i].value;
                    optionValid = True;
                    break;
                }
            }
            if (!optionValid)
                DEBUG(0,("handle_options: '%s' invalid option\n",
                         str_array[j]));
        }
    }
    DEBUG(9,("handle_options: %s -> %p\n", pszParmValue, *ptr));

    return True;
}

static BOOL handle_fields(const char *pszParmValue, char **ptr) {
    /* create initialized field structures for each name */
    char **str_array;

    str_array = str_list_make(pszParmValue, NULL);

    if (str_array) {
        size_t i;
        for ( i = 0; str_array[i] != NULL; i++)
            test_section.field_count++;
        /* allocate new field array */
        test_section.fields = talloc(contextP->mem_ctx,
                                     test_section.field_count * sizeof(struct field_test_spec));
        for ( i = 0; str_array[i] != NULL; i++)
            test_section.fields[i].name = str_array[i];
    }
    return True;
}

/***************************************************************************
 Map a parameter's string representation to something we can use. 
 Returns False if the parameter string is not recognised, else TRUE.
***************************************************************************/

static int map_parameter(const char *pszParmName, int section) {
    int iIndex;
    unsigned validFlags = 0;

    if (*pszParmName == '-')
        return (-1);

    /* Check for section-specific parameters.
     * This allows the same parameter name to be used in 
     * different sections with different meanings.
     */
    if (section == GEN_SECTION_GLOBAL)
        validFlags |= GEN_FLAG_GLOBAL;
    if (section == GEN_SECTION_TEST)
        validFlags |= GEN_FLAG_TEST;
    if (section == GEN_SECTION_FIELD)
        validFlags |= GEN_FLAG_FIELD;
    for (iIndex = 0; parm_table[iIndex].label; iIndex++)
        if ((parm_table[iIndex].flags & validFlags) &&
                strwicmp(parm_table[iIndex].label, pszParmName) == 0)
            return (iIndex);

    /* Warn only if it isn't parametric option */
    if (strchr(pszParmName, ':') == NULL)
        DEBUG(0, ("Unknown parameter encountered: \"%s\"\n", pszParmName));
    /* We do return 'fail' for parametric options as well because they are
       stored in different storage
     */
    return (-1);
}

/***************************************************************************
 Set a boolean variable from the text value stored in the passed string.
 Returns True in success, False if the passed string does not correctly 
 represent a boolean.
***************************************************************************/

static BOOL set_boolean(BOOL *pb, const char *pszParmValue) {
    BOOL bRetval;

    bRetval = True;
    if (strwicmp(pszParmValue, "yes") == 0 ||
            strwicmp(pszParmValue, "true") == 0 ||
            strwicmp(pszParmValue, "1") == 0) {
        *pb = True;
    } else if (strwicmp(pszParmValue, "no") == 0 ||
               strwicmp(pszParmValue, "False") == 0 ||
               strwicmp(pszParmValue, "0") == 0) {
        *pb = False;
    } else {
        DEBUG(0,
              ("ERROR: Badly formed boolean in configuration file: \"%s\".\n",
               pszParmValue));
        bRetval = False;
    }
    return (bRetval);
}

/***************************************************************************
 Process a parameter
***************************************************************************/

static BOOL gen_do_parm(struct gentest_context_t *context,
                 const char *pszParmName, const char *pszParmValue) {
    int parmnum, i;
    void *parm_ptr = NULL;	/* where we are going to store the result */
    void *def_ptr = NULL;

    parmnum = map_parameter(pszParmName, context->iCurrentSectionType);

    if (parmnum < 0) {
        DEBUG(0, ("Ignoring unknown parameter \"%s\"\n", pszParmName));
        return (True);
    }
    DEBUG(19,("gen_do_parm: parm %s is valid\n", pszParmName));
    def_ptr = parm_table[parmnum].ptr;

    /* we might point at a test, a field or a global */
    if (context->iCurrentSectionType == GEN_SECTION_GLOBAL) {
        parm_ptr = def_ptr;
    } else {
        if (parm_table[parmnum].class == P_GLOBAL) {
            DEBUG(0,
                  ("Global parameter %s found in service section!\n",
                   pszParmName));
            return (True);
        }
        parm_ptr = def_ptr;
    }

    /* if it is a special case then go ahead */
    if (parm_table[parmnum].special) {
        parm_table[parmnum].special(pszParmValue, (char **)parm_ptr);
        return (True);
    }
    DEBUG(19,("gen_do_parm: parm %s type=%d\n", pszParmName,
              parm_table[parmnum].type));

    /* now switch on the type of variable it is */
    switch (parm_table[parmnum].type) {
    case P_BOOL:
        set_boolean(parm_ptr, pszParmValue);
        break;

    case P_INTEGER:
        *(int *)parm_ptr = atoi(pszParmValue);
        break;

    case P_LIST:
        *(char ***)parm_ptr = str_list_make(pszParmValue, NULL);
        break;

    case P_STRING:
        parm_ptr = talloc_strdup(context->mem_ctx, pszParmValue);
        break;

    case P_ENUM:
        for (i = 0; parm_table[parmnum].enum_list[i].name; i++) {
            if (strequal
                    (pszParmValue,
                     parm_table[parmnum].enum_list[i].name)) {
                *(int *)parm_ptr =
                    parm_table[parmnum].
                    enum_list[i].value;
                break;
            }
        }
        break;
    case P_SEP:
        break;
    default:
        break;
    }

    return (True);
}
/***************************************************************************
 Process a parameter.
***************************************************************************/

static BOOL do_parameter(const char *pszParmName, const char *pszParmValue) {
    BOOL bRetval;

    DEBUG(4, ("doing parameter %s = %s\n", pszParmName, pszParmValue));
    bRetval = gen_do_parm(contextP, pszParmName, pszParmValue);

    return bRetval;
}

/***************************************************************************
Check a test for consistency. Return False if the test is in any way
incomplete or faulty, else True.
***************************************************************************/

static BOOL test_ok(struct gentest_context_t *context,int iTest) {
    BOOL bRetval = True;

    DEBUG(9,("test_ok: index=%d, tests@%p\n", iTest,
             context->tests));
    /* initialize new test section */
    DEBUG(9,("test_ok: name=%s\n", test_section.name));
    context->tests[iTest].name = test_section.name;
    context->tests[iTest].debug = test_section.debug;
    context->tests[iTest].type = test_section.type;
    context->tests[iTest].command = test_section.command;
    context->tests[iTest].initial_conditions = test_section.condition;
    context->tests[iTest].options = test_section.options;
    context->tests[iTest].word_count = test_section.words;
    context->tests[iTest].fields = test_section.fields;
    context->tests[iTest].field_count = test_section.field_count;
    context->tests[iTest].execute = test_section.execute;
    context->tests[iTest].verify = test_section.verify;

    /* validate test entry */
    DEBUG(9,("test_ok: validate name=%s\n", test_section.name));
    if (context->tests[iTest].name[0] == '\0') {
        DEBUG(0, ("The following message indicates an internal error:\n"));
        DEBUG(0, ("No test name in test entry.\n"));
        bRetval = False;
    }
    if (bRetval) {
        context->tests[iTest].valid = True;
        DEBUG(9,("added valid test %s\n",test_section.name));
    }

    return (bRetval);
}
/***************************************************************************
Check a field for consistency. Return False if the field is in any way
incomplete or faulty, else True.
***************************************************************************/

static BOOL field_ok(struct gentest_context_t *context,int iField) {
    BOOL bRetval = True;

    /* setup new field entry */
    DEBUG(9,("field_ok: index=%d, fields@%p\n", iField,
             context->fields));
    context->fields[iField].name = field_section.name;
    context->fields[iField].type = field_section.type;
    context->fields[iField].random = field_section.random;
    context->fields[iField].word_count = field_section.words;
    context->fields[iField].function = field_section.function;

    /* validate field */
    if (context->fields[iField].name[0] == '\0') {
        DEBUG(0, ("The following message indicates an internal error:\n"));
        DEBUG(0, ("No field name in field entry.\n"));
        bRetval = False;
    }
    if (bRetval) {
        context->fields[iField].valid = True;
        DEBUG(9,("added valid field %s\n",field_section.name));
    }
    
    return (bRetval);
}
/***************************************************************************
Find a test by name. Otherwise works like get_test.
***************************************************************************/

static int gettestbyname(struct gentest_context_t *context,
                         const char *pszTestName) {
    int iTest;

    for (iTest = context->iNumTests - 1; iTest >= 0; iTest--)
        if (context->tests[iTest].valid &&
                strwicmp(context->tests[iTest].name, pszTestName) == 0) {
            break;
        }

    return (iTest);
}
/***************************************************************************
Find a field by name. Otherwise works like get_field.
***************************************************************************/

static int getfieldbyname(struct gentest_context_t *context,
                          const char *pszFieldName) {
    int iField;

    for (iField = context->iNumFields - 1; iField >= 0; iField--)
        if (context->fields[iField].valid &&
                strwicmp(context->fields[iField].name, pszFieldName) == 0) {
            break;
        }

    return (iField);
}
/***************************************************************************
 Add a new test to the tests array initialising it with the given 
 test. 
***************************************************************************/

static int add_a_test(struct gentest_context_t *context,
                      const char *name) {
    int i;
    int num_to_alloc = context->iNumTests + 1;

    DEBUG(3, ("add_a_test: %s at index %d\n", name, num_to_alloc-1));
    /* it might already exist */
    if (name) {
        i = gettestbyname(context, name);
        if (i >= 0)
            return (i);
    }

    /* find an invalid one */
    for (i = 0; i < context->iNumTests; i++)
        if (!context->tests[i].valid)
            break;

    /* if not, then create one */
    DEBUG(3, ("add_a_test: add %s at index %d\n", name, i));
    if (i == context->iNumTests) {
        struct enum_test *tsp;

        tsp = talloc_realloc(context->mem_ctx, context->tests,
                             sizeof(struct enum_test) *
                             num_to_alloc);

        if (!tsp) {
            DEBUG(0,("add_a_test: failed to enlarge TestPtrs!\n"));
            return (-1);
        } else {
            context->tests = tsp;
        }

        context->iNumTests++;
        DEBUG(3, ("add_a_test: tests@%p\n", tsp));
    } //else
    //free_test(context->tests[i]);
    /* reinitialize test section fields */
    test_section.command = 0;
    test_section.name = talloc_strdup(context->mem_ctx, name);
    test_section.debug = 0;
    test_section.condition = 0;
    test_section.type = 0;
    test_section.options = 0;
    test_section.words = 0;
    test_section.fields = NULL;
    test_section.field_count = 0;
    test_section.execute = NULL;
    test_section.verify = NULL;
    context->tests[i].valid = False;

    if (name)
        context->tests[i].name = test_section.name;
    DEBUG(3, ("add_a_test: added %s at index %d\n", name, i));
    return (i);
}
/***************************************************************************
 Add a new field to the fields array initialising it with the given 
 field. 
***************************************************************************/

static int add_a_field(struct gentest_context_t *context,
                       const char *name) {
    int i;
    int num_to_alloc = context->iNumFields + 1;

    DEBUG(3, ("add_a_field: %s at index %d\n", name, num_to_alloc-1));
    /* it might already exist */
    if (name) {
        i = getfieldbyname(context, name);
        if (i >= 0)
            return (i);
    }

    /* find an invalid one */
    for (i = 0; i < context->iNumFields; i++)
        if (!context->fields[i].valid)
            break;

    /* if not, then create one */
    DEBUG(3, ("add_a_field: add %s at index %d\n", name, i));
    if (i == context->iNumFields) {
        field_test_spec *tsp;

        tsp = talloc_realloc(context->mem_ctx, context->fields,
                             sizeof(field_test_spec) *
                             num_to_alloc);

        if (!tsp) {
            DEBUG(0,("add_a_field: failed to enlarge FieldPtrs!\n"));
            return (-1);
        } else {
            context->fields = tsp;
        }

        context->iNumFields++;
        DEBUG(3, ("add_a_field: fields@%p\n", tsp));
    }

    /* reinitialize field section fields */
    field_section.name = NULL;
    field_section.type = 0;
    field_section.random = False;
    field_section.words = 0;
    field_section.function = NULL;
    context->fields[i].valid = False;

    if (name)
        field_section.name = talloc_strdup(context->mem_ctx, name);
    DEBUG(3, ("add_a_field: added %s at index %d\n", name, i));
    return (i);
}
/***************************************************************************
 Process a new section (test or field).
 Returns True on success, False on failure. 
***************************************************************************/

static BOOL do_section(const char *pszSectionName) {
    BOOL bRetval;
    BOOL isglobal = (strwicmp(pszSectionName, GLOBAL_NAME) == 0);
    char *sectionType, *sectionName, *p;

    bRetval = False;
    DEBUG(4, ("doing section %s\n", pszSectionName));
    /* if we've just struck a global section, note the fact. */
    contextP->bInGlobalSection = isglobal;

    /* check for multiple global sections */
    if (contextP->bInGlobalSection) {
        DEBUG(3, ("Processing section \"[%s]\"\n", pszSectionName));
        contextP->iCurrentSectionType = GEN_SECTION_GLOBAL;
        return (True);
    } else if (contextP->iCurrentSectionType == GEN_SECTION_GLOBAL) {
        /* just finished global section */
        ;
    }

    /* parse section name (form <type:name> */
    sectionType = talloc_strdup(contextP->mem_ctx, pszSectionName);
    p = strchr_m(sectionType,':');
    if (p) {
        *p = 0;
        sectionName = talloc_strdup(contextP->mem_ctx, p+1);
    } else {
        DEBUG(0, ("Invalid section name %s\n", pszSectionName));
        return False;
    }

    /* if we have a current test or field, tidy it up before moving on */
    bRetval = True;

    if (contextP->iTestIndex >= 0 && contextP->iCurrentSectionType == GEN_SECTION_TEST)
        bRetval = test_ok(contextP, contextP->iTestIndex);
    if (contextP->iFieldIndex >= 0 && contextP->iCurrentSectionType == GEN_SECTION_FIELD)
        bRetval = field_ok(contextP, contextP->iFieldIndex);

    /* determine type of this section */
    contextP->iCurrentSectionType = GEN_SECTION_INVALID;
    if (strequal(sectionType, "test"))
        contextP->iCurrentSectionType = GEN_SECTION_TEST;
    if (strequal(sectionType, "field"))
        contextP->iCurrentSectionType = GEN_SECTION_FIELD;
    if (contextP->iCurrentSectionType == GEN_SECTION_INVALID) {
        DEBUG(0, ("Invalid section type %s\n", sectionType));
        return False;
    }

    /* if all is still well, move to the next record in the tests array */
    if (bRetval) {
        /* We put this here to avoid an odd message order if messages are */
        /* issued by the post-processing of a previous section. */
        DEBUG(2, ("Processing section \"[%s]\"\n", pszSectionName));

        if (contextP->iCurrentSectionType == GEN_SECTION_TEST) {
            if ((contextP->iTestIndex = add_a_test(contextP, sectionName))
                    < 0) {
                DEBUG(0, ("Failed to add a new test\n"));
                return (False);
            }
        }
        if (contextP->iCurrentSectionType == GEN_SECTION_FIELD) {
            if ((contextP->iFieldIndex = add_a_field(contextP, sectionName))
                    < 0) {
                DEBUG(0, ("Failed to add a new field\n"));
                return (False);
            }
        }
    }

    return (bRetval);
}

/***************************************************************************
 Load the test configuration from the test config file. Return True on success, 
 False on failure.
***************************************************************************/

BOOL gen_load_config(struct gentest_context_t *contextPTR) {
    char *n2;
    BOOL bRetval;

    contextP = contextPTR;
    contextP->param_opt = NULL;

    n2 = talloc_strdup(contextP->mem_ctx, contextP->config_filename);

    /* We get sections first, so have to start 'behind' to make up */
    contextP->iTestIndex = -1;
    bRetval = pm_process(n2, do_section, do_parameter);

    /* finish up the last section */
    DEBUG(4, ("pm_process() returned %s\n", BOOLSTR(bRetval)));

    /* if we have a current test or field, tidy it up before moving on */
    if (contextP->iTestIndex >= 0 && contextP->iCurrentSectionType == GEN_SECTION_TEST)
        bRetval = test_ok(contextP, contextP->iTestIndex);
    if (contextP->iFieldIndex >= 0 && contextP->iCurrentSectionType == GEN_SECTION_FIELD)
        bRetval = field_ok(contextP, contextP->iFieldIndex);

    /* OK, we've parsed the configuration, now we need to match
     * the field sections to fields required by tests */
    if (bRetval) {
        int i,j,k;
        BOOL fieldValid;
        for (i=0; i<contextP->iNumTests; i++) {
            DEBUG(19,("gen_load_config: process test %d %s\n",
                      i, contextP->tests[i].name));
            for (j=0; j<contextP->tests[i].field_count; j++) {
                fieldValid = False;
                DEBUG(19,("gen_load_config: look for field %s\n",
                          contextP->tests[i].fields[j].name));
                for (k=0; k<contextP->iNumFields; k++) {
                    DEBUG(19,("gen_load_config: compare field %s\n",
                              contextP->fields[k].name));
                    if (strequal(contextP->tests[i].fields[j].name,
                                 contextP->fields[k].name)) {
                        /* matching field found */
                        fieldValid = True;
                        contextP->tests[i].fields[j].type = contextP->fields[k].type;
                        contextP->tests[i].fields[j].word_count = contextP->fields[k].word_count;
                        contextP->tests[i].fields[j].function = contextP->fields[k].function;
                        contextP->tests[i].fields[j].valid = contextP->fields[k].valid;
                        contextP->tests[i].fields[j].random = contextP->fields[k].random;
                        contextP->tests[i].fields[j].parms = contextP->fields[k].parms;
                        break;
                    }
                    if (fieldValid)
                        break;
                }
                if (!fieldValid) {
                	contextP->tests[i].fields[j].valid = False;
                	contextP->tests[i].fields[j].function = test_field_get_null;
                    DEBUG(0,("missing field section: %s\n",
                             contextP->tests[i].fields[j].name));
                }
            }
        }
    }

    return (bRetval);
}
