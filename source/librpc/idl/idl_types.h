#define STR_ASCII    LIBNDR_FLAG_STR_ASCII
#define STR_LEN4     LIBNDR_FLAG_STR_LEN4
#define STR_SIZE4    LIBNDR_FLAG_STR_SIZE4
#define STR_NOTERM   LIBNDR_FLAG_STR_NOTERM
#define STR_NULLTERM LIBNDR_FLAG_STR_NULLTERM

/*
  a UCS2 string prefixed with [size] [offset] [length], all 32 bits
  not null terminated
*/
#define unistr_noterm [flag(STR_NOTERM|STR_SIZE4|STR_LEN4)] string

/*
  a UCS2 string prefixed with [size] [offset] [length], all 32 bits
*/
#define unistr        [flag(STR_SIZE4|STR_LEN4)]            string

/*
  a UCS2 string prefixed with [size], 32 bits
*/
#define lstring       [flag(STR_SIZE4)]                     string

/*
  a null terminated UCS2 string
*/
#define nstring       [flag(STR_NULLTERM)]                  string

/*
  an ascii string prefixed with [size] [offset] [length], all 32 bits
  null terminated
*/
#define ascstr        [flag(STR_ASCII|STR_SIZE4|STR_LEN4)]  string

/*
  an ascii string prefixed with [offset] [length], both 32 bits
  null terminated
*/
#define ascstr2       [flag(STR_ASCII|STR_LEN4)]            string


#define NDR_NOALIGN LIBNDR_FLAG_NOALIGN
