%{

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "krb5_locl.h"
#include "config_file.h"

static char section[128];
static FILE *F;

static krb5_config_file *cf;

static krb5_config_section *csec;

static krb5_config_relation **crel;
static krb5_config_relation **rels[16];
static int relp;

%}

%union {
	int	i;
	char   *s;
}

%token <s> STRING

%%

file	:  section_list
	;

section_list : /* empty */
	| section rel_list section_list { 
					printf("section_list\n"); }
	;

section
	: '[' STRING ']' 
	{
		krb5_config_section *p;
		p = ALLOC(1, krb5_config_section);
		p->next = NULL;
		p->name = $2;
		p->relations = NULL;
		if(cf->sections)
			p->next = cf->sections;
		cf->sections = p;
		csec = p;
		crel = &p->relations;
		printf("section\n"); strcpy(section, $2); }
	;

rel_list 
	: relation rel_sub
	;

rel_sub	: /* empty */ 
	| relation rel_sub 
	;

relation
	: tag '=' value { printf("relation\n"); }
	;

tag	: STRING 
	{	
		krb5_config_relation *p;
		if(!crel){
			fprintf(stderr, "error\n");
			return -17;
		}
		p = ALLOC(1, krb5_config_relation);
		p->tag = $1;
		if(*crel){
			p->next = NULL;
			(*crel)->value.data.relations = p;
			rels[relp++] = crel;
			crel = &p;
		}else{
			p->next = *crel;
			*crel = p;
		}
		printf("tag\n"); 
	}
	;

value	: STRING
	{
		(*crel)->value.type = krb5_config_value_string;
		(*crel)->value.data.string = $1;
		crel = &(*crel)->next;
		printf("value/string\n"); 
	}
	| '{' rel_list '}'
	{
		crel = rels[--relp];
		(*crel)->value.type = krb5_config_value_list;
		crel = &(*crel)->next;
		printf("value/list\n");
	}
	;

%%

static int yylex(void)
{
  int c;
  static char save;
  static char yytext[1024];
  char *p = yytext;
  int type = 0;
  while(1){
    if(save){
      c = save;
      save = 0;
    }else
      c = getc(F);
    if(c == EOF)
      break;
    if(isspace(c))
      if(type)
	break; /* end of token */
      else 
	continue; /* eat ws */
    if(strchr("[]={}", c)){
      if(type)
	save = c;
      else{
	return c;
      }
      break;
    }
    *p++ = c;
    type = STRING;
    continue;
  }
  *p = 0;
  yylval.s = strdup(yytext);
  return type;
}

static void yyerror(char *s)
{
	printf("yyerror: %s\n", s);
}


/*----------------------------------------*/

static void
free_config_file(krb5_config_file *cf)
{
  if(!cf)
    return;
  FREE(cf->filename);
  free(cf);
}

static void free_config_relation(krb5_config_relation *rel);

static void
free_config_value(krb5_config_value val)
{
  if(val.type == krb5_config_value_string)
    FREE(val.data.string);
  else if(val.type == krb5_config_value_list)
    free_config_relation(val.data.relations);
  else
    fprintf(stderr, "free_config_value: krb5_config_value "
	    "with bad type passed (%d)\n", val.type);
}

static void
free_config_relation(krb5_config_relation *rel)
{
  if(!rel)
    return;
  free_config_value(rel->value);
  free_config_relation(rel->next);
  FREE(rel);
}

static void
free_config_section(krb5_config_section *sec)
{
  if(!sec)
    return;
  FREE(sec->name);
  free_config_relation(sec->relations);
  free_config_section(sec->next);
  FREE(sec);
}


void
krb5_free_config_file(krb5_config_file *cf)
{
  free_config_file(cf);
}

krb5_error_code
krb5_get_config_tag(krb5_config_file *cf, const char *tag, char **value)
{
  char *str;
  char *p;
  krb5_config_section *s;
  krb5_config_relation *r;
  
  str = strdup(tag);
  p = strtok(str, " \t");
  if(!p)
    return ENOENT;
  for(s = cf->sections; s; s = s->next){
    if(!strcmp(s->name, p)){
      p = strtok(NULL, " \t");
      for(r = s->relations; r;){
	if(!strcmp(r->tag, p)){
	  if(r->value.type == krb5_config_value_string){
	    *value = strdup(r->value.data.string);
	    free(str);
	    return 0;
	  }else{
	    p = strtok(NULL, " \t");
	    r = r->value.data.relations;
	    continue;
	  }
	}
	r = r->next;
      }
    }
  }
  return ENOENT;
}

krb5_error_code
krb5_parse_config_file(krb5_config_file **cfile, const char *filename)
{
  krb5_error_code ret;
  if(!filename)
    filename = krb5_config_file;
  F = fopen(filename, "r");
  if(F == NULL)
    return errno;
  cf = ALLOC(1, krb5_config_file);
  if(!cf)
	return ENOMEM;
  ret = yyparse();

  fclose(F);
  if(ret)
	krb5_free_config_file(cf);
  else
	*cfile = cf;
  return ret;
}
