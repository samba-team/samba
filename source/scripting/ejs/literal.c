/*
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 * Copyright (c) 2006 Derrell Lipman
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 * Derrell Lipman:
 * This version is modified from the original.  It has been modified to
 * natively use EJS variables rather than the original C object interface, and
 * to use the talloc() family of functions for memory allocation.
 */

#include "includes.h"
#include "scripting/ejs/smbcalls.h"

enum json_tokener_error {
        json_tokener_success,
        json_tokener_error_oom, /* out of memory */
        json_tokener_error_parse_unexpected,
        json_tokener_error_parse_null,
        json_tokener_error_parse_date,
        json_tokener_error_parse_boolean,
        json_tokener_error_parse_number,
        json_tokener_error_parse_array,
        json_tokener_error_parse_object,
        json_tokener_error_parse_string,
        json_tokener_error_parse_comment,
        json_tokener_error_parse_eof
};

enum json_tokener_state {
        json_tokener_state_eatws,
        json_tokener_state_start,
        json_tokener_state_finish,
        json_tokener_state_null,
        json_tokener_state_date,
        json_tokener_state_comment_start,
        json_tokener_state_comment,
        json_tokener_state_comment_eol,
        json_tokener_state_comment_end,
        json_tokener_state_string,
        json_tokener_state_string_escape,
        json_tokener_state_escape_unicode,
        json_tokener_state_boolean,
        json_tokener_state_number,
        json_tokener_state_array,
        json_tokener_state_datelist,
        json_tokener_state_array_sep,
        json_tokener_state_datelist_sep,
        json_tokener_state_object,
        json_tokener_state_object_field_start,
        json_tokener_state_object_field,
        json_tokener_state_object_field_end,
        json_tokener_state_object_value,
        json_tokener_state_object_sep
};

enum date_field {
        date_field_year,
        date_field_month,
        date_field_day,
        date_field_hour,
        date_field_minute,
        date_field_second,
        date_field_millisecond
};

struct json_tokener
{
        char *source;
        int pos;
        void *ctx;
        void *pb;
};

static const char *json_number_chars = "0123456789.+-e";
static const char *json_hex_chars = "0123456789abcdef";

#define hexdigit(x) (((x) <= '9') ? (x) - '0' : ((x) & 7) + 9)

extern struct MprVar json_tokener_parse(char *s);
static struct MprVar json_tokener_do_parse(struct json_tokener *this,
                                           enum json_tokener_error *err_p);

/*
 * literal_to_var() parses a string into an ejs variable.  The ejs
 * variable is returned.  Upon error, the javascript variable will be
 * `undefined`.  This was created for parsing JSON, but is generally useful
 * for parsing the literal forms of objects and arrays, since ejs doesn't
 * procide that functionality.
 */
int literal_to_var(int eid, int argc, char **argv)
{
        struct json_tokener tok;
        struct MprVar obj;
        enum json_tokener_error err = json_tokener_success;
        
        if (argc != 1) {
		ejsSetErrorMsg(eid,
                               "literal_to_var() requires one parameter: "
                               "the string to be parsed.");
		return -1;
        }

        tok.source = argv[0];
        tok.pos = 0;
        tok.ctx = talloc_new(mprMemCtx());
        if (tok.ctx == NULL) {
                mpr_Return(eid, mprCreateUndefinedVar());
                return 0;
        }
        tok.pb = talloc_zero_size(tok.ctx, 1);
        if (tok.pb == NULL) {
                mpr_Return(eid, mprCreateUndefinedVar());
                return 0;
        }
        obj = json_tokener_do_parse(&tok, &err);
        talloc_free(tok.pb);
        if (err != json_tokener_success) {
                mprDestroyVar(&obj);
                mpr_Return(eid, mprCreateUndefinedVar());
                return 0;
        }
        mpr_Return(eid, obj);
        return 0;
}

static void *append_string(void *ctx,
                           char *orig,
                           char *append,
                           int size)
{
    char c;
    char *end_p = append + size;
    void *ret;

    /*
     * We need to null terminate the string to be copied.  Save character at
     * the size limit of the source string.
     */
    c = *end_p;

    /* Temporarily null-terminate it */
    *end_p = '\0';

    /* Append the requested data */
    ret = talloc_append_string(ctx, orig, append);
    
    /* Restore the original character in place of our temporary null byte */
    *end_p = c;

    /* Give 'em what they came for */
    return ret;
}


static struct MprVar json_tokener_do_parse(struct json_tokener *this,
                                           enum json_tokener_error *err_p)
{
        enum json_tokener_state state;
        enum json_tokener_state saved_state;
        enum date_field date_field;
        struct MprVar current = mprCreateUndefinedVar();
        struct MprVar tempObj;
        struct MprVar obj;
        enum json_tokener_error err = json_tokener_success;
        char date_script[] = "JSON_Date.create(0);";
        char *obj_field_name = NULL;
        char *emsg = NULL;
        char quote_char;
        int deemed_double;
        int start_offset;
        char c;
        
        state = json_tokener_state_eatws;
        saved_state = json_tokener_state_start;

        
        do {
                c = this->source[this->pos];
                switch(state) {
                        
                case json_tokener_state_eatws:
                        if(isspace(c)) {
                                this->pos++;
                        } else if(c == '/') {
                                state = json_tokener_state_comment_start;
                                start_offset = this->pos++;
                        } else {
                                state = saved_state;
                        }
                        break;
                        
                case json_tokener_state_start:
                        switch(c) {
                        case '{':
                                state = json_tokener_state_eatws;
                                saved_state = json_tokener_state_object;
                                current = mprObject(NULL);
                                this->pos++;
                                break;
                        case '[':
                                state = json_tokener_state_eatws;
                                saved_state = json_tokener_state_array;
                                current = mprArray(NULL);
                                this->pos++;
                                break;
                        case 'N':
                        case 'n':
                                start_offset = this->pos++;
                                if (this->source[this->pos] == 'e') {
                                    state = json_tokener_state_date;
                                } else {
                                    state = json_tokener_state_null;
                                }
                                break;
                        case '"':
                        case '\'':
                                quote_char = c;
                                talloc_free(this->pb);
                                this->pb = talloc_zero_size(this->ctx, 1);
                                if (this->pb == NULL) {
                                        *err_p = json_tokener_error_oom;
                                        goto out;
                                }
                                state = json_tokener_state_string;
                                start_offset = ++this->pos;
                                break;
                        case 'T':
                        case 't':
                        case 'F':
                        case 'f':
                                state = json_tokener_state_boolean;
                                start_offset = this->pos++;
                                break;
#if defined(__GNUC__)
                        case '0' ... '9':
#else
                        case '0':
                        case '1':
                        case '2':
                        case '3':
                        case '4':
                        case '5':
                        case '6':
                        case '7':
                        case '8':
                        case '9':
#endif
                        case '-':
                                deemed_double = 0;
                                state = json_tokener_state_number;
                                start_offset = this->pos++;
                                break;
                        default:
                                err = json_tokener_error_parse_unexpected;
                                goto out;
                        }
                        break;
                        
                case json_tokener_state_finish:
                        goto out;
                        
                case json_tokener_state_null:
                        if(strncasecmp("null",
                                       this->source + start_offset,
                                       this->pos - start_offset)) {
                                *err_p = json_tokener_error_parse_null;
                                mprDestroyVar(&current);
                                return mprCreateUndefinedVar();
                        }
                        
                        if(this->pos - start_offset == 4) {
                                mprDestroyVar(&current);
                                current = mprCreateNullVar();
                                saved_state = json_tokener_state_finish;
                                state = json_tokener_state_eatws;
                        } else {
                                this->pos++;
                        }
                        break;
                        
                case json_tokener_state_date:
                        if (this->pos - start_offset <= 18) {
                                if (strncasecmp("new Date(Date.UTC(",
                                                this->source + start_offset,
                                                this->pos - start_offset)) {
                                        *err_p = json_tokener_error_parse_date;
                                        mprDestroyVar(&current);
                                        return mprCreateUndefinedVar();
                                } else {
                                        this->pos++;
                                        break;
                                }
                        }
                        
                        this->pos--;            /* we went one too far */
                        state = json_tokener_state_eatws;
                        saved_state = json_tokener_state_datelist;

                        /* Create a JsonDate object */
                        if (ejsEvalScript(0,
                                          date_script,
                                          &tempObj,
                                          &emsg) != 0) {
                                *err_p = json_tokener_error_parse_date;
                                mprDestroyVar(&current);
                                return mprCreateUndefinedVar();
                        }
                        mprDestroyVar(&current);
                        mprCopyVar(&current, &tempObj, MPR_DEEP_COPY);
                        date_field = date_field_year;
                        break;
                        
                case json_tokener_state_comment_start:
                        if(c == '*') {
                                state = json_tokener_state_comment;
                        } else if(c == '/') {
                                state = json_tokener_state_comment_eol;
                        } else {
                                err = json_tokener_error_parse_comment;
                                goto out;
                        }
                        this->pos++;
                        break;
                        
                case json_tokener_state_comment:
                        if(c == '*') state = json_tokener_state_comment_end;
                        this->pos++;
                        break;
                        
                case json_tokener_state_comment_eol:
                        if(c == '\n') {
                                state = json_tokener_state_eatws;
                        }
                        this->pos++;
                        break;
                        
                case json_tokener_state_comment_end:
                        if(c == '/') {
                                state = json_tokener_state_eatws;
                        } else {
                                state = json_tokener_state_comment;
                        }
                        this->pos++;
                        break;
                        
                case json_tokener_state_string:
                        if(c == quote_char) {
                                this->pb = append_string(
                                        this->ctx,
                                        this->pb,
                                        this->source + start_offset,
                                        this->pos - start_offset);
                                if (this->pb == NULL) {
                                        err = json_tokener_error_oom;
                                        goto out;
                                }
                                current = mprString(this->pb);
                                saved_state = json_tokener_state_finish;
                                state = json_tokener_state_eatws;
                        } else if(c == '\\') {
                                saved_state = json_tokener_state_string;
                                state = json_tokener_state_string_escape;
                        }
                        this->pos++;
                        break;
                        
                case json_tokener_state_string_escape:
                        switch(c) {
                        case '"':
                        case '\\':
                                this->pb = append_string(
                                        this->ctx,
                                        this->pb,
                                        this->source + start_offset,
                                        this->pos - start_offset - 1);
                                if (this->pb == NULL) {
                                        err = json_tokener_error_oom;
                                        goto out;
                                }
                                start_offset = this->pos++;
                                state = saved_state;
                                break;
                        case 'b':
                        case 'n':
                        case 'r':
                        case 't':
                                this->pb = append_string(
                                        this->ctx,
                                        this->pb,
                                        this->source + start_offset,
                                        this->pos - start_offset - 1);
                                if (this->pb == NULL) {
                                        err = json_tokener_error_oom;
                                        goto out;
                                }
                                if (c == 'b') {
                                        /*
                                         * second param to append_string()
                                         * gets temporarily modified; can't
                                         * pass string constant.
                                         */
                                        char buf[] = "\b";
                                        this->pb = append_string(this->ctx,
                                                                 this->pb,
                                                                 buf,
                                                                 1);
                                        if (this->pb == NULL) {
                                                err = json_tokener_error_oom;
                                                goto out;
                                        }
                                } else if (c == 'n') {
                                        char buf[] = "\n";
                                        this->pb = append_string(this->ctx,
                                                                 this->pb,
                                                                 buf,
                                                                 1);
                                        if (this->pb == NULL) {
                                                err = json_tokener_error_oom;
                                                goto out;
                                        }
                                } else if (c == 'r') {
                                        char buf[] = "\r";
                                        this->pb = append_string(this->ctx,
                                                                 this->pb,
                                                                 buf,
                                                                 1);
                                        if (this->pb == NULL) {
                                                err = json_tokener_error_oom;
                                                goto out;
                                        }
                                } else if (c == 't') {
                                        char buf[] = "\t";
                                        this->pb = append_string(this->ctx,
                                                                 this->pb,
                                                                 buf,
                                                                 1);
                                        if (this->pb == NULL) {
                                                err = json_tokener_error_oom;
                                                goto out;
                                        }
                                }
                                start_offset = ++this->pos;
                                state = saved_state;
                                break;
                        case 'u':
                                this->pb = append_string(
                                        this->ctx,
                                        this->pb,
                                        this->source + start_offset,
                                        this->pos - start_offset - 1);
                                if (this->pb == NULL) {
                                        err = json_tokener_error_oom;
                                        goto out;
                                }
                                start_offset = ++this->pos;
                                state = json_tokener_state_escape_unicode;
                                break;
                        default:
                                err = json_tokener_error_parse_string;
                                goto out;
                        }
                        break;
                        
                case json_tokener_state_escape_unicode:
                        if(strchr(json_hex_chars, c)) {
                                this->pos++;
                                if(this->pos - start_offset == 4) {
                                        unsigned char utf_out[3];
                                        unsigned int ucs_char =
                                                (hexdigit(*(this->source + start_offset)) << 12) +
                                                (hexdigit(*(this->source + start_offset + 1)) << 8) +
                                                (hexdigit(*(this->source + start_offset + 2)) << 4) +
                                                hexdigit(*(this->source + start_offset + 3));
                                        if (ucs_char < 0x80) {
                                                utf_out[0] = ucs_char;
                                                this->pb = append_string(
                                                        this->ctx,
                                                        this->pb,
                                                        (char *) utf_out,
                                                        1);
                                                if (this->pb == NULL) {
                                                        err = json_tokener_error_oom;
                                                        goto out;
                                                }
                                        } else if (ucs_char < 0x800) {
                                                utf_out[0] = 0xc0 | (ucs_char >> 6);
                                                utf_out[1] = 0x80 | (ucs_char & 0x3f);
                                                this->pb = append_string(
                                                        this->ctx,
                                                        this->pb,
                                                        (char *) utf_out,
                                                        2);
                                                if (this->pb == NULL) {
                                                        err = json_tokener_error_oom;
                                                        goto out;
                                                }
                                        } else {
                                                utf_out[0] = 0xe0 | (ucs_char >> 12);
                                                utf_out[1] = 0x80 | ((ucs_char >> 6) & 0x3f);
                                                utf_out[2] = 0x80 | (ucs_char & 0x3f);
                                                this->pb = append_string(
                                                        this->ctx,
                                                        this->pb,
                                                        (char *) utf_out,
                                                        3);
                                                if (this->pb == NULL) {
                                                        err = json_tokener_error_oom;
                                                        goto out;
                                                }
                                        }
                                        start_offset = this->pos;
                                        state = saved_state;
                                }
                        } else {
                                err = json_tokener_error_parse_string;
                                goto out;
                        }
                        break;
                        
                case json_tokener_state_boolean:
                        if(strncasecmp("true", this->source + start_offset,
                                       this->pos - start_offset) == 0) {
                                if(this->pos - start_offset == 4) {
                                        current = mprCreateBoolVar(1);
                                        saved_state = json_tokener_state_finish;
                                        state = json_tokener_state_eatws;
                                } else {
                                        this->pos++;
                                }
                        } else if(strncasecmp("false", this->source + start_offset,
                                              this->pos - start_offset) == 0) {
                                if(this->pos - start_offset == 5) {
                                        current = mprCreateBoolVar(0);
                                        saved_state = json_tokener_state_finish;
                                        state = json_tokener_state_eatws;
                                } else {
                                        this->pos++;
                                }
                        } else {
                                err = json_tokener_error_parse_boolean;
                                goto out;
                        }
                        break;
                        
                case json_tokener_state_number:
                        if(!c || !strchr(json_number_chars, c)) {
                                int numi;
                                double numd;
                                char *tmp = talloc_strndup(
                                        this->ctx,
                                        this->source + start_offset,
                                        this->pos - start_offset);
                                if (tmp == NULL) {
                                        err = json_tokener_error_oom;
                                        goto out;
                                }
                                if(!deemed_double && sscanf(tmp, "%d", &numi) == 1) {
                                        current = mprCreateIntegerVar(numi);
                                } else if(deemed_double && sscanf(tmp, "%lf", &numd) == 1) {
                                        current = mprCreateFloatVar(numd);
                                } else {
                                        talloc_free(tmp);
                                        err = json_tokener_error_parse_number;
                                        goto out;
                                }
                                talloc_free(tmp);
                                saved_state = json_tokener_state_finish;
                                state = json_tokener_state_eatws;
                        } else {
                                if(c == '.' || c == 'e') deemed_double = 1;
                                this->pos++;
                        }
                        break;
                        
                case json_tokener_state_array:
                        if(c == ']') {
                                this->pos++;
                                saved_state = json_tokener_state_finish;
                                state = json_tokener_state_eatws;
                        } else {
                                int oldlen;
                                char idx[16];
                                
                                obj = json_tokener_do_parse(this, &err);
                                if (err != json_tokener_success) {
                                        goto out;
                                }
                                oldlen = mprToInt(mprGetProperty(&current,
                                                                 "length",
                                                                 NULL));
                                mprItoa(oldlen, idx, sizeof(idx));
                                mprSetVar(&current, idx, obj);
                                saved_state = json_tokener_state_array_sep;
                                state = json_tokener_state_eatws;
                        }
                        break;
                        
                case json_tokener_state_datelist:
                        if(c == ')') {
                                if (this->source[this->pos+1] == ')') {
                                        this->pos += 2;
                                        saved_state = json_tokener_state_finish;
                                        state = json_tokener_state_eatws;
                                } else {
                                        err = json_tokener_error_parse_date;
                                        goto out;
                                }
                        } else {
                                obj = json_tokener_do_parse(this, &err);
                                if (err != json_tokener_success) {
                                        goto out;
                                }

                                /* date list items must be integers */
                                if (obj.type != MPR_TYPE_INT) {
                                        err = json_tokener_error_parse_date;
                                        goto out;
                                }
                                
                                switch(date_field) {
                                case date_field_year:
                                        mprSetVar(&current, "year", obj);
                                        break;
                                case date_field_month:
                                        mprSetVar(&current, "month", obj);
                                        break;
                                case date_field_day:
                                        mprSetVar(&current, "day", obj);
                                        break;
                                case date_field_hour:
                                        mprSetVar(&current, "hour", obj);
                                        break;
                                case date_field_minute:
                                        mprSetVar(&current, "minute", obj);
                                        break;
                                case date_field_second:
                                        mprSetVar(&current, "second", obj);
                                        break;
                                case date_field_millisecond:
                                        mprSetVar(&current, "millisecond", obj);
                                        break;
                                default:
                                        err = json_tokener_error_parse_date;
                                        goto out;
                                }

                                /* advance to the next date field */
                                date_field++;

                                saved_state = json_tokener_state_datelist_sep;
                                state = json_tokener_state_eatws;
                        }
                        break;
                        
                case json_tokener_state_array_sep:
                        if(c == ']') {
                                this->pos++;
                                saved_state = json_tokener_state_finish;
                                state = json_tokener_state_eatws;
                        } else if(c == ',') {
                                this->pos++;
                                saved_state = json_tokener_state_array;
                                state = json_tokener_state_eatws;
                        } else {
                                *err_p = json_tokener_error_parse_array;
                                mprDestroyVar(&current);
                                return mprCreateUndefinedVar();
                        }
                        break;
                        
                case json_tokener_state_datelist_sep:
                        if(c == ')') {
                                if (this->source[this->pos+1] == ')') {
                                        this->pos += 2;
                                        saved_state = json_tokener_state_finish;
                                        state = json_tokener_state_eatws;
                                } else {
                                        err = json_tokener_error_parse_date;
                                        goto out;
                                }
                        } else if(c == ',') {
                                this->pos++;
                                saved_state = json_tokener_state_datelist;
                                state = json_tokener_state_eatws;
                        } else {
                                *err_p = json_tokener_error_parse_date;
                                mprDestroyVar(&current);
                                return mprCreateUndefinedVar();
                        }
                        break;
                        
                case json_tokener_state_object:
                        state = json_tokener_state_object_field_start;
                        start_offset = this->pos;
                        break;
                        
                case json_tokener_state_object_field_start:
                        if(c == '}') {
                                this->pos++;
                                saved_state = json_tokener_state_finish;
                                state = json_tokener_state_eatws;
                        } else if (c == '"' || c == '\'') {
                                quote_char = c;
                                talloc_free(this->pb);
                                this->pb = talloc_zero_size(this->ctx, 1);
                                if (this->pb == NULL) {
                                        *err_p = json_tokener_error_oom;
                                        goto out;
                                }
                                state = json_tokener_state_object_field;
                                start_offset = ++this->pos;
                        } else {
                                err = json_tokener_error_parse_object;
                                goto out;
                        }
                        break;
                        
                case json_tokener_state_object_field:
                        if(c == quote_char) {
                                this->pb = append_string(
                                        this->ctx,
                                        this->pb,
                                        this->source + start_offset,
                                        this->pos - start_offset);
                                if (this->pb == NULL) {
                                        err = json_tokener_error_oom;
                                        goto out;
                                }
                                obj_field_name = talloc_strdup(this->ctx,
                                                               this->pb);
                                if (obj_field_name == NULL) {
                                        err = json_tokener_error_oom;
                                        goto out;
                                }
                                saved_state = json_tokener_state_object_field_end;
                                state = json_tokener_state_eatws;
                        } else if(c == '\\') {
                                saved_state = json_tokener_state_object_field;
                                state = json_tokener_state_string_escape;
                        }
                        this->pos++;
                        break;
                        
                case json_tokener_state_object_field_end:
                        if(c == ':') {
                                this->pos++;
                                saved_state = json_tokener_state_object_value;
                                state = json_tokener_state_eatws;
                        } else {
                                *err_p = json_tokener_error_parse_object;
                                mprDestroyVar(&current);
                                return mprCreateUndefinedVar();
                        }
                        break;
                        
                case json_tokener_state_object_value:
                        obj = json_tokener_do_parse(this, &err);
                        if (err != json_tokener_success) {
                                goto out;
                        }
                        mprSetVar(&current, obj_field_name, obj);
                        talloc_free(obj_field_name);
                        obj_field_name = NULL;
                        saved_state = json_tokener_state_object_sep;
                        state = json_tokener_state_eatws;
                        break;
                        
                case json_tokener_state_object_sep:
                        if(c == '}') {
                                this->pos++;
                                saved_state = json_tokener_state_finish;
                                state = json_tokener_state_eatws;
                        } else if(c == ',') {
                                this->pos++;
                                saved_state = json_tokener_state_object;
                                state = json_tokener_state_eatws;
                        } else {
                                err = json_tokener_error_parse_object;
                                goto out;
                        }
                        break;
                        
                }
        } while(c);
        
        if(state != json_tokener_state_finish &&
           saved_state != json_tokener_state_finish)
                err = json_tokener_error_parse_eof;
        
out:
        talloc_free(obj_field_name);
        if(err == json_tokener_success) {
                return current;
        } else {
                mprDestroyVar(&current);
                *err_p = err;
                return mprCreateUndefinedVar();
        }
}


void smb_setup_ejs_literal(void)
{
	ejsDefineStringCFunction(-1,
                                 "literal_to_var",
                                 literal_to_var,
                                 NULL,
                                 MPR_VAR_SCRIPT_HANDLE);
}
